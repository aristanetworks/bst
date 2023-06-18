#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <dbus/dbus.h>

#include "capable.h"
#include "cgroup.h"
#include "path.h"

#define BUS_NAME  "org.freedesktop.systemd1"
#define PATH      "/org/freedesktop/systemd1"
#define INTERFACE "org.freedesktop.systemd1.Manager"

/* This cgroup driver implements the "Integration is good :)" path of the systemd
   cgroup delegation guide[1]. It is assumed that readers of this code will
   have read the guide beforehand.

   The driver talks to systemd via dbus to create a scope in which the bst
   process will be placed. bst will then move itself into a subcgroup to avoid
   the no-internal-process rule, and place the child process into a separate
   subcgroup in which limits will be applied.

   [1]: https://systemd.io/CGROUP_DELEGATION/
 */

static DBusError dberr;
static DBusConnection* bus;

static int cgroup_systemd_driver_init(bool fatal)
{
	dbus_error_init(&dberr);

	/* Open the system bus if we're root, and the session bus otherwise. This
	   matches the behaviour of other systemd clients. */
	if (getuid() == 0) {
		bus = dbus_bus_get(DBUS_BUS_SYSTEM, &dberr);
	} else {
		bus = dbus_bus_get(DBUS_BUS_SESSION, &dberr);
	}
	if (dbus_error_is_set(&dberr)) {
		if (fatal) {
			errx(1, "cgroup_systemd_driver_init: dbus_connection_open: %s", dberr.message);
		}
		return -1;
	}

	return 0;
}

static bool cgroup_systemd_current_path(char *path)
{
	/* We use machines-bst.slice as default; this corresponds to the
	   cgroup /machines.slice/machines-bst.slice when the bus is the
	   system bus, while this corresponds to the user session slice,
	   i.e. /user.slice/user-<UID>.slice/user-<UID>-machines.slice/user-
	   <UID>-machines-bst.slice, when the user bus is used. */
	strcpy(path, "machines-bst.slice");
	return true;
}

static size_t bus_copy_type(char *buf, size_t sz, char until, bool once, const char *type)
{
	size_t idx = 0;
	while (idx < sz - 1 && type[idx]) {
		char t = type[idx];
		buf[idx] = type[idx];
		idx++;

		if (t == until) {
			break;
		}
		switch (t) {
		case DBUS_STRUCT_BEGIN_CHAR:
			idx += bus_copy_type(buf + idx, sz - idx, DBUS_STRUCT_END_CHAR, false, type + idx);
			buf[idx] = type[idx];
			idx++;
		}
		if (once) {
			break;
		}
	}
	buf[idx] = 0;
	return idx;
}

static bool bus_message_append_aux(DBusMessageIter *iter, const char **fmt, char until, bool once, va_list vl)
{
	char typebuf[128];

	DBusMessageIter container;
	for (; **fmt != until; ++(*fmt)) {
		switch (**fmt) {
		case DBUS_TYPE_STRING:
			{
				char *s = va_arg(vl, char *);
				if (!dbus_message_iter_append_basic(iter, **fmt, &s)) {
					return false;
				}
			} break;
		case DBUS_TYPE_UINT32:
			{
				uint32_t u = va_arg(vl, uint32_t);
				if (!dbus_message_iter_append_basic(iter, **fmt, &u)) {
					return false;
				}
			} break;
		case DBUS_TYPE_BOOLEAN:
			{
				dbus_bool_t b = va_arg(vl, int);
				if (!dbus_message_iter_append_basic(iter, **fmt, &b)) {
					return false;
				}
			} break;
		case DBUS_TYPE_VARIANT:
			{
				const char *type = va_arg(vl, const char *);
				if (!dbus_message_iter_open_container(iter, **fmt, type, &container)) {
					return false;
				}
				if (!bus_message_append_aux(&container, &type, '\0', true, vl)) {
					return false;
				}
				if (!dbus_message_iter_close_container(iter, &container)) {
					return false;
				}
			} break;
		case DBUS_TYPE_ARRAY:
			{
				int len = va_arg(vl, int);
				size_t typesz = bus_copy_type(typebuf, sizeof (typebuf), '\0', true, *fmt+1);

				if (!dbus_message_iter_open_container(iter, **fmt, typebuf, &container)) {
					return false;
				}
				*fmt += typesz - 1;

				for (int i = 0; i < len; i++) {
					const char *type = typebuf;
					if (!bus_message_append_aux(&container, &type, '\0', true, vl)) {
						return false;
					}
				}
				if (!dbus_message_iter_close_container(iter, &container)) {
					return false;
				}

			} break;
		case DBUS_STRUCT_BEGIN_CHAR:
			{
				bus_copy_type(typebuf, sizeof (typebuf), DBUS_STRUCT_END_CHAR, false, *fmt+1);
				if (!dbus_message_iter_open_container(iter, DBUS_TYPE_STRUCT, NULL, &container)) {
					return false;
				}
				++(*fmt);
				if (!bus_message_append_aux(&container, fmt, DBUS_STRUCT_END_CHAR, false, vl)) {
					return false;
				}
				if (!dbus_message_iter_close_container(iter, &container)) {
					return false;
				}
			} break;
		default:
			errx(1, "programming error: unsupported D-Bus type '%c'", **fmt);
		}
		if (once) {
			break;
		}
	}
	return true;
}

static bool bus_message_append(DBusMessageIter *iter, const char *fmt, ...)
{
	va_list vl;
	va_start(vl, fmt);
	bool ok = bus_message_append_aux(iter, &fmt, '\0', false, vl);
	va_end(vl);
	return ok;
}

static int cgroup_systemd_join_cgroup(const char *parent, const char *name)
{
	/* Register a signal to wait for the scope creation to complete */

	DBusError error;
	dbus_error_init(&error);
	const char *expr = "type='signal',"
			"sender='"BUS_NAME"',"
			"path='"PATH"',"
			"interface='"INTERFACE"',"
			"member='JobRemoved'";
	dbus_bus_add_match(bus, expr, &error);
	dbus_connection_flush(bus);
	if (dbus_error_is_set(&error)) {
		errx(1, "cgroup_systemd_join_cgroup: dbus_bus_add_match: %s", error.message);
	}

	/* Create a transient scope unit in which the current process will be
	   placed. */
	DBusMessage *msg = dbus_message_new_method_call(BUS_NAME, PATH, INTERFACE, "StartTransientUnit");
	if (!msg) {
		errno = ENOMEM;
		err(1, "cgroup_systemd_join_cgroup: dbus_message_new_method_call");
	}

	char namebuf[PATH_MAX];
	makepath_r(namebuf, "%s.scope", name);

	DBusMessageIter iter, props;
	dbus_message_iter_init_append(msg, &iter);

	dbus_bool_t ok = true;

	/* Set name and mode */
	ok = ok && bus_message_append(&iter, "ss", namebuf, "fail");

	/* Set properties */
	ok = ok && dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(sv)", &props);

	ok = ok && bus_message_append(&props, "(sv)(sv)(sv)(sv)",
			"Description", "s", "/usr/bin/true",
			"Delegate", "b", 1, /* Delegate all cgroup controllers to us */
			"Slice", "s", parent,
			"PIDs", "au", 1, (uint32_t)getpid());

	ok = ok && dbus_message_iter_close_container(&iter, &props);

	/* Systemd expects auxiliary units in the message, and we have none */
	ok = ok && bus_message_append(&iter, "a(sa(sv))", 0);

	if (!ok) {
		errno = -ENOMEM;
		err(1, "cgroup_systemd_join_cgroup: preparing D-Bus message");
	}

	/* Perform the call. Systemd will place our process into the cgroup for us. */
	DBusMessage *reply = dbus_connection_send_with_reply_and_block(bus, msg, -1, &dberr);
	if (!reply) {
		errx(1, "cgroup_systemd_join_cgroup: failed to start transient scope unit: %s", dberr.message);
	}

	dbus_message_unref(msg);
	dbus_message_unref(reply);

	/* Wait for the scope creation job to complete */
	for (;;) {
		dbus_connection_read_write(bus, -1);
		msg = dbus_connection_pop_message(bus);

		if (msg == NULL) {
			continue;
		}

		if (!dbus_message_is_signal(msg, INTERFACE, "JobRemoved")) {
			goto next;
		}
		if (!dbus_message_iter_init(msg, &iter)) {
			errx(1, "cgroup_systemd_join_cgroup: JobRemoved signal message has no arguments");
		}

		// ID
		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32) {
			goto bad_sig;
		}
		if (!dbus_message_iter_next(&iter)) {
			goto bad_sig;
		}

		// Path
		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_OBJECT_PATH) {
			goto bad_sig;
		}
		if (!dbus_message_iter_next(&iter)) {
			goto bad_sig;
		}

		// Unit
		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING) {
			goto bad_sig;
		}
		if (!dbus_message_iter_next(&iter)) {
			goto bad_sig;
		}

		// Result
		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING) {
			goto bad_sig;
		}
		char *result;
		dbus_message_iter_get_basic(&iter, &result);
		if (strcmp(result, "done")) {
			errx(1, "cgroup_systemd_join_cgroup: failed to start transient scope unit: job finished with result '%s'", result);
		}

	next:
		dbus_message_unref(msg);
		break;

	bad_sig:
		errx(1, "cgroup_systemd_join_cgroup: JobRemoved signal message does not have signature 'uoss'");
	}

	char selfcgroup[PATH_MAX];
	if (!cgroup_read_current(selfcgroup)) {
		errx(1, "could not determine current cgroup; are you using cgroups v2?");
	}
	int cgroupfd = open(selfcgroup, O_RDONLY | O_DIRECTORY, 0);
	if (cgroupfd == -1) {
		err(1, "cgroup_systemd_join_cgroup: open %s", selfcgroup);
	}

	return cgroupfd;
}

const struct cgroup_driver_funcs cgroup_driver_systemd = {
	.init         = cgroup_systemd_driver_init,
	.join_cgroup  = cgroup_systemd_join_cgroup,
	.current_path = cgroup_systemd_current_path,
};

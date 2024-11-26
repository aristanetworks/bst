bst(1) "bst" "Bestie"

# NAME

bst - run executables in their own spacetime.

# SYNOPSIS

bst [options] [--] [<VAR=value...> [--]] [executable [args...]]

# DESCRIPTION

Runs _executable_ in its own isolated environment.  If _executable_ is not
specified, then _${SHELL:-/bin/sh}_ is run.
The meaning of isolated depends on the platform or the version of bst, but bst
generally tries to unshare every available namespace and arrange the inner
environment to be as deterministic as possible within these parameters.

Because of the relativistic nature of these isolated environments with
regard to the executable being run, we call these environments "spacetimes".
Spacetimes may define their own meaning about devices, randomness, locale,
time, namespaces, and filesystem structure.

Users of bst may choose to opt-out of some of the isolation.

Environment variables can be overriden for the spacetime process by specifying
_VAR=value_ before the executable to run. This can be useful in conjunction
with --no-env if environment variables used by bst (LC_\*, TERM, ...) and
the setup program should be different from the environment variables of the
spacetime process.

# OPTIONS

\--argv0 <string>
	Run _executable_ with the specified value for _argv[0]_.
	By default, _argv[0]_ is _executable_ itself.

\--share <ns>[=<file>]++
\--share <ns,ns...>[=<directory>]++
\--share <directory>
	Share the specified namespaces with the namespace anchored by
	*<file>*, which can be a file like /proc/[pid]/ns/mnt,
	or a bind-mount of that file, or a file created by
	_bst --persist=_*<dir>*.  If no *=<file>* is given, then share the
	given namespace with the process invoking bst.

	Multiple namespaces may be specified in a comma-separated list.  If more
	than one namespace is specified, and a target path is specified, it is
	interpreted as a directory name in which to find the eponymous nsfs files.

	_--share_ can also take a lone directory path, in which case all namespaces
	are presumed to be shared from their respective nsfs files under that path.

	Available namespaces are:
	- *cgroup* (since Linux 4.6)
	- *ipc* (since Linux 2.6.19)
	- *mnt*
	- *net* (since Linux 2.6.24)
	- *pid* (since Linux 3.8)
	- *time* (since Linux 5.6)
	- *uts* (since Linux 2.6.19)
	- *user* (since Linux 3.8)

	A special value of *all* can also be used to signify to share all
	namespaces.

	All namespaces are unshared by default; _e.g.,_ if _--share mnt_
	is not given, then the child process runs in a new (unshared)
	mount namespace initialized as a copy of bst's parent's mount
	namespace.

\--unshare <ns,ns...>
	Unshare the specified namespaces.  By default, *bst* unshares all
	namespaces, so this flag is not normally necessary.

	_--unshare_ is useful when used in conjunction with _--share all_ in
	order to share a select set of namespaces except for a few ones.

	Available namespaces are the same as for _--share_.

\--persist <ns,ns...>=<path>++
\--persist <directory>
	Persist specified namespaces of the new process into files in the
	given directory, allowing re-entry via _--share <dir>_ even after bst
	exits (but note that pid namespaces whose init died cannot be re-entered).

	If no namespaces are specified, all namespaces are persisted into
	*<directory>*.

	If one namespace is specified, *<path>* is used as the bind-mount target
	for the nsfs file representing this namespace.

	Multiple namespaces may be specified in a comma-separated list.  If more
	than one namespace is specified, *<path>* represents instead the directory
	into which nsfs files will be persisted.  In this case, the files are named
	the same as the namespace files in _/proc/[pid]/ns_.

	This option is equivalent to bind-mounting files under _/proc/[pid]/ns/_
	in (or on) the target path after invoking bst, except avoiding a race where
	the child exits before the bind-mounts complete.  Note that in order to
	persist the mount namespace, the persist directory must be on a private
	mount subtree (for more information, see *mount_namespaces*(7)).

	See *bst-unpersist*(1) for more details about how to release persisted
	namespace files.

\--workdir <dir>
	Change the current work directory for the inner process to *<dir>*.

	*<dir>* must be an absolute path relative to the current root, or, if
	a new root has been specified with _--root_, the new root.

\--root <dir>
	Change the root directory for the inner process to *<dir>*.

\--mount [source=]<source>,[target=]<target>,[type=]<type>,<options...>
	Perform a mount in the inner process' mount namespace.

	*<target>* must be an absolute path relative to the current root, or, if
	a new root has been specified with _--root_, the new root.

	*<source>* can be a path relative to the initial work directory, or an
	absolute path relative to the inner root directory.

	*<type>* is the filesystem type, or _none_ if ignored.
	Consult _/proc/filesystems_ for a list of supported filesystem types.

	Additionally, the following filesystem types are recognized by *bst*:
	- *bst_devtmpfs* (see _--no-fake-devtmpfs_)

	*<options>* are mount options. Recognized options are the same as with
	*mount*(1).

	You cannot use this option with _--share=mount_.

\--uid <uid>
	Set the user ID of the inner process to *<uid>*.

\--gid <gid>
	Set the group ID of the inner process to *<gid>*.

\--groups <gid>[,gid]...
	Set the additional group IDs of the inner process to the specified GIDs.

\--arch <name>
	Set the execution domain of the inner process to the specified architecture.
	This affects the output of _uname -m_, and takes the same architecture names
	as *setarch*(1).

\--hostname <hostname>
	Set the hostname for the inner process' UTS namespace.

	By default, if the UTS namespace is unshared, *bst* sets the hostname to
	_"localhost"_.

	You cannot use this option with _--share=uts_.

\--domainname <domainname>
	Set the domain name for the inner process' UTS namespace.

	By default, if the UTS namespace is unshared, *bst* sets the domain name to
	_"localdomain"_.

	You cannot use this option with _--share=uts_.

\--time <name-or-id>=<seconds>[.<nanoseconds>]
	Set the value of the specified clock for the inner process' time namespace.

	Valid clock names are the same as the ones described in *time_namespaces*(7).
	Alternatively, the numerical clock IDs can be supplied.

	You cannot use this option with _--share=time_.

\--init <argv>
	Set the init process to be used as parent of *<executable>*. *<argv>* is
	a space-delimited argv array, and _argv[0]_ must be an absolute path to a
	valid executable in the current filesystem root (in other words, the init
	executable does not need to exist in the root specified by _--root_).

	If an empty *<argv>* is passed to _--init_, no init process will be
	spawned by bst, and *<executable>* will be executed directly.

	If bst unshares the pid namespace and no _--init_ is specified, it uses
	by default *bst-init*(1).

\--setup <cmdline>++
\--setup-exe <executable>

	Run the specified executable during the setup, after all namespaces
	have been unshared and the new process has been forked, but before
	changing anything else.

	If _--setup-exe_, *<executable>* is a filesystem path or an executable
	name resolvable in _$PATH_, and is executed without any arguments.

	If _--setup_, *<cmdline>* is used as if the setup process was
	_/bin/sh -euc "<cmdline>"_.

	See the *SETUP PROGRAMS* section for more information about how the program
	is called and what environment it runs in.

\--uid-map <inner:outer:length>[,<inner:outer:length>...]++
\--gid-map <inner:outer:length>[,<inner:outer:length>...]
	Override the default generated [ug]id map. The map must be fully-specified.

	By default, *bst* maps your current [UG]ID to 0, then maps continuously
	all allotted sub[ug]ids for the current [UG]ID as written in
	_/etc/sub[ug]id_ (see *subuid*(5), *subgid*(5)).

	You cannot use this option with _--share=user_.

\--nic [name=]<name>,[type=]<type>[,[options]]
	Create a network interface in the inner process' network namespace.

	You cannot use this option with _--share=net_.

	Supported interface types and valid options are described in more detail
	in the *NETWORKING* section.

\--ip [ip=]<ip-address>[/<subnet>],[dev=]<device-name>
	Add the specified IPv4 or IPv6 address to the specified device in the inner
	process' network namespace.

	Specifying a subnet to an IPv4 address sets the corresponding broadcast address.

	You cannot use this option with _--share=net_.

\--route [dst=(<ip>/<subnet>|default)][,src=<ip>][gateway=<ip>][,[options]]
	Add a route in the inner process' network namespace.

	You cannot use this option with _--share=net_.

	Supported options are described in more detail in the *NETWORKING* section.

\--cgroup-driver <driver>
	Specify the cgroup driver to use.

	Valid values are _native_, _systemd_, or _none_.

	The _native_ driver manages and cleans up cgroups directly, with no
	intermediary. It is appropriate to use in situations where nothing is
	owning the cgroups tree, like in most containers.

	The _systemd_ driver defers the management of the cgroup to systemd. It
	does so by creating a systemd scope unit via the D-Bus API. This driver
	is appropriate for systemd-managed systems, as directly creating cgroups
	without informing systemd on these systems causes bst to step on systemd's
	toes, and vice-versa.

	The _none_ driver disables cgroup support -- *bst* will leave the child
	process in the parent control group. Using this driver is not recommended
	for typical use, but has worth in testing or maintaining compatibility.

	By default, *bst* will attempt to use the _systemd_ driver before falling
	back to the _native_ driver.

\--cgroup <name>
	Specify the cgroup that *bst* will operate within. The interpretation of the
	value depends on the driver in use:

	If the driver is _native_, then this is a path to the cgroup directory that
	will be used to create the *bst* cgroup.

	If the driver is _systemd_, then this is the name of a systemd slice unit
	under which the *bst* cgroup will be placed.

\--limit <resource>=<value>
	Apply a cgroup quota <value> to the provided <resource>. Multiple limits can
	be specified in conjunction.

	<resource>=<value> follow the interface of the underlying cgroup.

	Common <resource>=<value> pairs include, for instance:
	- *cpu.max*=$MAX
	- *cpu.weight*=$WEIGHT
	- *memory.min*=$MIN
	- *memory.max*=$MAX

	Consult the CGroupsV2 documentation of your kernel for a full list of
	possible resources.

	To use a <resource> ensure that the proper controller (io, cpu, memory) has
	been enabled in the parent cgroup.

\--try-limit <resource>=<value>
	Identical to _--limit_, but ignored if the resouce is unsupported by the
	kernel, or hasn't been enabled in the cgroup.subtree_control file.

\--rlimit <resource>=<value>++
\--rlimit <resource>=[hard]:[soft]
	Set the specified hard and soft resource limits of the specified resource
	based on *<value>*.

	Accepted values for *<resource>* are:
	- *as*:         size of virtual memory
	- *core*:       maximum size of core files created
	- *cpu*:        maximum amount of CPU time in seconds
	- *data*:       maximum size of a process's data segment
	- *fsize*:      maximum size of files written by the shell and its children
	- *locks*:      maximum number of file locks
	- *memlock*:    maximum size a process may lock into memory
	- *msgqueue*:   maximum number of bytes in POSIX message queues
	- *nice*:       maximum scheduling priority (`nice')
	- *nofile*:     maximum number of open file descriptors
	- *nproc*:      maximum number of user processes
	- *rss*:        maximum resident set size
	- *rtprio*:     maximum real-time scheduling priority
	- *rttime*:     limit (in microseconds) of real-time-scheduled CPU time before making a blocking system call
	- *sigpending*: maximum number of pending signals
	- *stack*:      maximum stack size

	Format of *<value>*:
	- Single numerical value: set both hard and soft limits to <value>.
	- Colon-separated hard:soft values.

	When either limit is not provided (empty string), use the
	current value without trying to make any changes.  When
	neither limit is provided, this is a special case to set the
	soft resource limit to the current hard limit value.

	Examples:++
	\--rlimit nproc=100       hard=100, soft=100++
	\--rlimit nproc=200:100   hard=200, soft=100++
	\--rlimit nproc=:100      hard=(unchanged), soft=100++
	\--rlimit nproc=100:      hard=100, soft=(unchanged)++
	\--rlimit nproc=:         hard=(unchanged), soft=(hard limit)

	If a value is not provided using a --rlimit option for a given resource,
	the hard limit will be used as the soft limit, unless *--no-copy-hard-rlimits* has
	been provided.

	Full details for each rlimit value can be found in *getrlimit*(2).

\--pidfile <path>
	Write the PID of the newly spawned *<executable>* in *<path>*.

	If *<path>* is a regular file, it is exclusive-locked and truncated prior
	to writing the PID. The lock is kept for the lifetime of the inner process,
	and *bst* aborts if it cannot be acquired.

	To avoid lock races with other processes sharing a common pidfile path, the
	file is never removed.

\--tty[=<options>]
	Allocate a pty for the process.

	_--tty_ optionally takes a list of flags or key=value pairs to set specific
	termios options and control characters for the newly allocated pty.

	Options take no value and can be negated by prepending _'-'_ to the option
	name (e.g. _-echo_). Supported options are: *brkint*, *clocal*, *cmspar*,
	*cr0*, *cr1*, *cr2*, *cr3*, *cread*, *crtscts*, *cstopb*, *echo*, *echoctl*,
	*echoe*, *echok*, *echoke*, *echonl*, *echoprt*, *extproc*, *ff0*, *ff1*,
	*flusho*, *hupcl*, *icanon*, *icrnl*, *iexten*, *ignbrk*, *igncr*, *ignpar*,
	*inlcr*, *inpck*, *isig*, *istrip*, *iuclc*, *iutf8*, *ixany*, *ixoff*,
	*ixon*, *nl0*, *nl1*, *noflsh*, *ocrnl*, *ofill*, *olcuc*, *onlcr*, *onlret*,
	*onocr*, *opost*, *parenb*, *parmrk*, *parodd*, *tab0*, *tab1*, *tab2*,
	*tab3*, *tostop*, *vt0*, and *vt1*.

	Control characters are specified as a key-value pair, _<cc>=<val>_. Values
	can be specified using the caret notation, or a backslash-escaped octal
	(\\nnn) or hexadecimal (\\xnn) value. Supported control characters are: *veof*,
	*veol*, *veol2*, *verase*, *vintr*, *vkill*, *vlnext*, *vquit*, *vreprint*,
	*vstart*, *vstop*, *vsusp*, and *vwerase*.

	A comprehensive description of what these options and control characters do
	can be found in the *termios*(3) manual.

	Other bst-specific options are:

	- *ptmx*=<path>: use the specified ptmx device (relative to the target root)
	  to allocated the pty.

	By default bst inherits the parent's terminal device (or lack thereof).  Use
	the --tty option to allocate a new pty for the child process.

\--close-fd[=<fd>|<from>-[to]]
	Close the specified file descriptor or fd range.

	In its first form, _--close-fd=<fd>_ is equivalent to _--close-fd=<fd>-<fd>_.

	In its second form, _from_ designates the starting file descriptor to close,
	and _to_ designates the end file descriptor to close. All file descriptors
	between _from_ and _to_, inclusive, are then closed before _executable_
	is started.

	Note that setup programs still have access to the inherited file
	descriptors -- that is, file descriptors specified via --close-fd will
	only get closed after the setup program finishes executing. This can
	be useful to pass out-of-band data to the setup program without leaking
	file descriptors to the spacetime process.

\--fix-stat-32bit-overflow
	Hijack calls to the stat64 family of system calls and return quantities
	within 32-bit boundaries.

	On most i686 distributions, glibc implements stat() for programs compiled
	without -D_FILE_OFFSET_BITS=64 by calling the corresponding stat64 system
	call, and if any of the 64-bit quantities in the statbuf are larger than
	2^32-1, the glibc wrapper pretends the file does not exist by returning
	ENOENT.

	This flag mitigates the issue by pulling the rug under glibc and rewriting
	the quantities to stay within bounds. For timestamps, a fixed date within
	range is used. For inode numbers, the value is rewritten in a way that
	keeps the (device, inode) pair unique.

	This flag has no effect on programs running with a 64-bit personality.

\--no-copy-hard-rlimits
	Do not copy hard limit values to soft limits for all resources mentioned above.

	By default, *bst* copies the hard limit to the soft limit for all of the resources mentioned
	above.  To avoid setting any resource values, except as directed by --rlimit-<limit> options,
	use this option.

\--no-fake-devtmpfs
	Do not replace devtmpfs mounts with a fake devtmpfs.

	By default, *bst* constructs the contents of a fake devtmpfs with a minimal
	set of devices and symlinks. In particular, because devtmpfses cannot be
	mounted in user namespaces, this allows programs wishing to run in a user
	namespace yet still have access to non-problematic devices like _/dev/null_
	to pass in _--mount dev,/dev,devtmpfs_ and have this work out of the box.

\--no-derandomize
	Do not try to reduce sources of randomness.

	By default, *bst* tries to run inner processes in a somewhat more deterministic
	environment. So far, it does so by symlinking _/dev/random_ and _/dev/urandom_ to
	_/dev/zero_, and by disabling ASLR for the inner process.

\--no-cgroup-remount
	Do not remount the existing /sys/fs/cgroup mount if in a mount and cgroup namespace.

	By default, *bst* automatically tries to mount a new cgroup2 on top of
	/sys/fs/cgroup if it detects it to be on another filesystem than _/_.

\--no-proc-remount
	Do not remount the existing _/proc_ mount if in a mount and pid namespace.

	By default, *bst* automatically tries to mount a new procfs on top of _/proc_
	if it detects it to be on another filesystem than _/_.

\--no-loopback-setup
	Do not bring up the _lo_ interface.

	By default, *bst* automatically brings up _lo_ and adds the address
	127.0.0.1/8 to it when in a network namespace.

	This does nothing when used with _--share=net_.

\--no-env
	Clear the environment before running _executable_.

	By default, the environment of the parent process is inherited as-is into
	the spacetime process. This can cause issues for environment variables like
	PATH if the rootfs layout is different than the host.

# PRIVILEGE MODEL

*bst* strives to be runnable by unprivileged users.  However, some code paths
within *bst* need some sets of capabilities that the calling user usually does
not have in order to perform its job correctly.  One such path is the path that
maps IDs into newly created user namespaces.

To this end, we define what the privilege model is.  The *bst* binary typically
has permitted (but not effective) file capabilities, and gives itself select
effective capabilities only when needed.  If file capabilities are unavailable,
the executable must be setuid and owned by root, and *bst* takes care to drop
privileges when it no longer needs them.

*bst* never gives users more privilges than they have access to.  For instance,
trying to operate on a mount namespace requires the calling user to have the
requisite capabilities in the user namespace that the mount namespace belongs
to, which typically belong to the root user of that namespace.

*bst* never implicitly changes any sort of resource in any of the original
namespaces that the calling process belong in.  For instance, *bst* will flat-out
refuse to perform a mount if it were to stay in the original mount namespace.
Another case is network interfaces: *bst* will not allow unprivileged users
to create new interfaces on the host, which does make veth unfortunately not
fit within that privilege model as one end has to exist on the host while the
other exists within the spacetime.  We expect instead system administrators
to configure interfaces on the host that unprivileged users can attach
MACVLANs or IPVLANs to.

## User namespaces and sub-IDs

When creating new user namespaces, *bst* consults _/etc/subuid_ and _/etc/subgid_
to find out what UIDs and GIDs are owned by the real UID/GID.  Mapped IDs
in the user namespace that do not belong in these sets for your real UID/GID
are rejected (see _--uid-map_ and _--gid-map_).

A consequence of this is that overlapping ID ranges in /etc/sub[ug]id for
different users mean that both users will be able to have complete control
over any file owned by that sub[ug]id.

In a default mapping, the real [UG]ID typically gets mapped as _0_ (root) in the
spacetime.  The privileges allotted to this root user are defined within
the rules of user namespaces (see *user_namespaces*(7)): permission and access
errors in the parent user namespace will still result in _EACCES_ and _EPERM_
in the new user namespace.

# SETUP PROGRAMS

A setup program is a program that execute as part of the setup of a spacetime.

Within a *bst* invocation, exactly one setup program may be specified (see
_--setup_ and _--setup-exe_), and the program will be run after all
relevant namespaces have been unshared/entered and the main child process
has been forked, but before any other initialization occurs.

In particular, this means that the setup script will run before any mounts
occurs, and before *bst* pivots/chroots into filesystem root.

Because the setup process is run very early, any preparatory work done by
the process may be altered or undone by other command-line switches passed to
*bst* if not careful.

## Execution

The setup program is executed in the same current work directory as *bst*,
with the same privileges as the calling user (but note that in a user
namespace, the setup process has a full set of capabilities within that
namespace).

If the setup process exits with a non-zero exit status, the rest of the
setup is aborted and *bst* exits with the same exit status. *bst* will
always exit silently in these cases -- setup programs are expected to
print themselves their error conditions.

Setup processes have their standard output and error redirected to the
standard error of *bst*. Standard input and error are untouched, which means
it is technically possible to have interactive setup sessions via
_--setup-exe=sh_.

## Environment

The following environment variables are accessible to the setup program:

*ROOT*
	Set to the root directory (_--root_) we are expected to pivot/chroot
	into later on.

*EXECUTABLE*
	Set to the executable name that will be executed after the setup is done.

*CGROUP_PATH*
	Set to the path of the cgroup of the process that will be executed. Can
	be missing if bst could not determine the cgroup path (e.g. only cgroups v1
	are available, or /proc isn't mounted)

# NETWORKING

## Creating network interfaces

This section describes the supported interface types and options that can
be used with _--nic_ in a network namespace.

Supported interface types are:
- *dummy*
- *macvlan*
- *ipvlan*

*macvlan*
	*link=<host-interface>*: attach the MACVLAN interface to the specified
	host interface.

	*mode=<mode>*: MACVLAN mode. Supported values are:
	- *private* (default)
	- *vepa*
	- *bridge*
	- *passthru*
	- *source*

*ipvlan*
	*link=<host-interface>*: attach the IPVLAN interface to the specified
	host interface.

	*mode=<mode>[+<flag>]*: IPVLAN operating mode. Supported values are:
	- *l2* (default)
	- *l3*
	- *l3s*

	Mode flags can be optionally added to the mode, by appending the flag with
	a `+`. Supported values for the mode flag are:
	- *bridge* (default)
	- *private*
	- *vepa*

## Adding routes

This section describes the options that _--route_ supports.

*src*=<ip>
	Set the source IP.

*dst*=<ip>/<subnet>++
*dst*=default
	Set the destination subnet. If _"default"_, the destination is /0.

*gateway*=<ip>
	Set the IP of the gateway.

*dev*=<intf>
	Use the specified interface as the output device.

*metric*=<n>
	Set the metric (or priority) of the route.

*scope*=<scope>++
*scope*=<number>
	Set the scope of (or distance to) the destination of the route. Can be a scope
	name or a number.

	The following values for *<scope>* are supported:
	- *universe* -- Destination is more than one hop away (default for gatewayed unicast routes).
	- *site*     -- Destination is in the local autonomous system.
	- *link*     -- Destination is in the local network, one hop away (default for broadcast and direct unicast routes).
	- *host*     -- Destination is on the local host (default for local routes).
	- *nowhere*  -- Destination does not exist.

*type*=<type>
	Specify the type of the route.

	The following values for *<type>* are supported:
	- *unicast*     -- A regular route from source to destination (default).
	- *local*       -- A local interface route.
	- *broadcast*   -- A local broadcast route.
	- *anycast*     -- A local broadcast route, sent as unicast.
	- *multicast*   -- A multicast route.
	- *blackhole*   -- A packet-dropping route (packets are dropped silently).
	- *unreachable* -- A packet-dropping route (ICMP Host Unreachable message generated).
	- *prohibit*    -- A packet-dropping route (ICMP Communication Administratively Prohibited message generated).
	- *throw*       -- Continue routing lookup in another table.
	- *nat*         -- A Network Address Translation rule.
	- *xresolve*    -- Defer routing lookup to an external resolver.

*table*=<table>++
*table*=<number>
	Specify the table on which the route should be configured. Can be a table name
	or a number.

	The following values for *<table>* are supported:
	- *main*    -- The main table (default for most routes)
	- *local*   -- The local table (default for local, broadcast, anycast, and nat routes)
	- *default* -- The default table.

*proto*=<proto>++
*proto*=<number>
	Set the route protocol (or origin). Can be a protocol name, or an 8-bit number above
	4 (which will not be interpreted by the kernel).

	The following values for *<proto>* are supported:
	- *redirect* -- Route was installed by ICMP redirect.
	- *kernel*   -- Route was installed by the kernel.
	- *boot*     -- Route was installed as part of the boot sequence (default).
	- *static*   -- Route was installed by the administrator.

# EXAMPLES

## Using bst to get an isolated shell

The default invocation of bst will provide a shell as isolated as possible on
your host system.

*$ id*++
uid=1000(barney) gid=1000(barney) groups=1000(barney)++
*$ bst*

This shell sees all of its namespaces unshared. Most notably, you are root
inside the spacetime, by virtue of the user namespace being unshared:

*# id*++
uid=0(root) gid=0(root) groups=0(root)

Being root in a user namespace does give you full control over your
namespaces:

*# mount -t tempfs tmp /tmp*++
*# touch /tmp/greeting*++
*# ls /tmp*++
greeting

This does not mean that you got a magical privilege escalation -- the root user
for this user namespace is mapped to your outer UID:

*$ touch foo*++
*$ ls -l foo*++
-rw-r--r--  1 barney barney 0 10 août  22:45 foo++
*$ bst ls -l foo*++
-rw-r--r--  1 root root 0 10 août  22:45 foo

Similarly, some operations are restricted while in a user namespace, and cannot
be done without having host privileges, like mounting devices:

*# mount /dev/sda1 /mnt*++
mount: /mnt: permission denied.

A more comprehensive description of the capabilities within a user namespace
can be found in *user_namespaces*(7) § _"Effect of capabilities within a user namespace"_.

## Using bst as a fakeroot substitute

bst can be used in a similar manner as fakeroot to perform operations as if the
current user was root. For instance, here's how to build and package sudo
without ever needing root privileges to set the setuid bit, or passing a gaggle
of transformative flags to tar.

*$ git clone https://github.com/sudo-project/sudo*++
*$ cd sudo*++
*$ ./configure --prefix=/usr*++
*$ make -j$(nproc)*++
*$ bst make install DESTDIR=$(pwd)/out*++
*$ bst tar -cJf sudo.tar.xz -C out .*++
*$ tar -tvf sudo.tar.xz | grep /usr/bin/sudo*++
lrwxrwxrwx root/root         0 2020-10-15 14:34 ./usr/bin/sudoedit -> sudo++
-rwsr-xr-x root/root    644048 2020-10-15 14:34 ./usr/bin/sudo++
-rwxr-xr-x root/root    315960 2020-10-15 14:34 ./usr/bin/sudoreplay

## Creating and entering an Alpine-Linux-based rootfs

*$* # download a minirootfs archive from https://alpinelinux.org/downloads/++
*$ wget \<the minirootfs url\> -o alpine-minirootfs.tar.gz*

*$* # extract the rootfs into a directory++
*$ mkdir rootfs*++
*$ bst tar -xzf alpine-minirootfs.tar.gz -C rootfs*

*$* # enter the rootfs, with a few useful mounts++
*$ bst -r rootfs \\++
    \--mount source=proc,target=/proc,type=proc \\++
    \--mount source=dev,target=/dev,type=devtmpfs \\++
    \--mount source=run,target=/run,type=tmpfs \\++
    \--mount source=tmp,target=/tmp,type=tmpfs \\++
    /bin/sh*++
*# export PATH=/usr/bin:/bin:/usr/sbin:/sbin*++
*# cat /etc/os-release*++
NAME="Alpine Linux"++
ID=alpine++
VERSION_ID=3.12.0++
PRETTY_NAME="Alpine Linux v3.12"++
HOME_URL="https://alpinelinux.org/"++
BUG_REPORT_URL="https://bugs.alpinelinux.org/"

# SEE ALSO

*bst-unpersist*(1), *bst-init*(1), *namespaces*(7), *mount*(1), *setarch*(1), *getrlimit*(2)

bst(1) "bst" "Bestie"

# NAME

bst - run executables in their own spacetime.

# SYNOPSIS

bst [options] [--] <executable> [args...]

# DESCRIPTION

Runs *<executable>* in their own isolated environment.
The meaning of isolated depends on the platform or the version of bst, but bst
generally tries to unshare every available namespace and arrange the inner
environment to be as deterministic as possible within these parameters.

Because of the relativistic nature of these isolated environments with
regard to the executable being run, we call these environments "spacetimes".
Spacetimes may define their own meaning about devices, randomness, locale,
time, namespaces, and filesystem structure.

Users of bst may choose to opt-out of some of the isolation.

# OPTIONS

\--argv0 <string>
	Run *<executable>* with the specified value for _argv[0]_.
	By default, _argv[0]_ is *<executable>* itself.

\--share <ns>[,ns]...
	Share the specified namespaces with the host.

	Available namespaces are:
	- *cgroup* (since Linux 4.6)
	- *ipc* (since Linux 2.6.19)
	- *mount*
	- *network* (since Linux 2.6.24)
	- *pid* (since Linux 3.8)
	- *time* (since Linux 5.6)
	- *uts* (since Linux 2.6.19)
	- *user* (since Linux 3.8)

\--workdir <dir>
	Change the current work directory for the inner process to *<dir>*.

	*<dir>* must be an absolute path relative to the current root, or, if
	a new root has been specified with _--root_, the new root.

\--root <dir>
	Change the root directory for the inner process to *<dir>*.

\--mount <source>,<target>,<type>,<options...>
	Perform a mount in the inner process' mount namespace.

	*<target>* must be an absolute path relative to the current root, or, if
	a new root has been specified with _--root_, the new root.

	*<source>* can be a path relative to the initial work directory, or an
	absolute path relative to the inner root directory.

	*<type>* is the filesystem type, or _none_ if ignored.
	Consult _/proc/filesystems_ for a list of supported filesystem types.

	*<options>* are mount options. Recognized options are the same as with
	*mount*(1).

	You cannot use this option with _--share=mount_.

\--mutable <dir>
	Make *<dir>* mutable. This is useful for making specific subtrees writeable
	when the parent directory has been mounted read-only.

	*<dir>* must be an absolute path relative to the current root, or, if
	a new root has been specified with _--root_, the new root.

	Any changes to the contents of *<dir>* are discarded when the inner process
	and all of its descendants exits.

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

# SEE ALSO

*namespaces*(7), *mount*(1), *setarch*(1)

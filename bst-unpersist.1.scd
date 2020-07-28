bst-unpersist(1) "bst" "Bestie"

# NAME

bst-unpersist - release persisted namespace files

# SYNOPSIS

bst-unpersist [options] <path> [path...]

# DESCRIPTION

Releases persisted specified namespace files, or all known namespace files
in the specified directories.

*bst*(1) can persist created namespaces on entry via the _--persist_ option.
A typical way to release these persisted namespaces is through the unmounting
of these files, but this requires the user to be privileged.

*bst-unpersist* gives unprivilged users a way to release these persisted
namespaces without privilege escalation.

A user is allowed to release an arbitrary namespace file only if:

. It is an nsfs mount,
. The user has write permissions over the containing directory, or has
  CAP_DAC_OVERRIDE.

# OPTIONS

\--no-unlink
	Do not remove namespace file mountpoints after they get unmounted.  This
	use-case is atypical, but is useful if you plan to layer multiple nsfs
	mounts on top of each other, and don't want the removal to fail with EBUSY.

# SEE ALSO

*bst*(1)

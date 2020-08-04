bst-init(1) "bst" "Bestie"

# NAME

bst-init - default bst init process.

# SYNOPSIS

bst-init [executable [args...]]

# DESCRIPTION

*bst-init* is the default init process employed by *bst*(1) when unsharing
the PID namespace.

*bst-init* forks and executes _<executable>_, only reaps zombies, and
immediately terminates when _<executable>_ exits.

# SEE ALSO

*bst*(1), *init*(1), *pid_namespaces*(7)

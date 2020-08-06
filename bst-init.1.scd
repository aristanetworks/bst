bst-init(1) "bst" "Bestie"

# NAME

bst-init - default bst init process.

# SYNOPSIS

bst-init [executable [args...]]

# DESCRIPTION

*bst-init* is the default init process employed by *bst*(1) when unsharing
the PID namespace.

*bst-init* has the following responsibilities:

- spawns _<executable>_, and puts the main process into a new foreground process group;
- reaps zombies;
- detaches inherited ptraced processes;
- forwards user-sent signals to the main process group;
- immediately terminates when the main process exits.

# SEE ALSO

*bst*(1), *init*(1), *pid_namespaces*(7)

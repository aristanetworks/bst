#!/usr/bin/env cram.sh

Allocate a PTY for the spacetime
	$ bst --tty --mount devpts,/dev/pts,devpts,mode=620,ptmxmode=666 tty
	/dev/pts/0

Check that redirections still work

	$ echo hello | bst --tty cat
	hello
	hello

	$ bst --tty echo hello | cat
	hello

Ensure we send the correct VEOF control character

	$ yes '' | head -c 32768 | timeout 1 bst --tty sh -c 'stty eof ^B && cat' >/dev/null

Ensure that we send VEOF twice in case there is pending input in the pty buffer

	$ echo -n hello | bst --tty cat
	hellohello

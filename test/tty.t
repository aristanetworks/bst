#!/usr/bin/env cram.sh

Allocate a PTY for the spacetime
	$ bst --tty --mount devpts,/dev/pts,devpts,mode=620,ptmxmode=666 tty
	/dev/pts/0

Check that redirections still work

	$ echo hello | bst --tty --mount devpts,/dev/pts,devpts,mode=620,ptmxmode=666 cat
	hello
	hello

	$ bst --tty --mount devpts,/dev/pts,devpts,mode=620,ptmxmode=666 echo hello | cat
	hello

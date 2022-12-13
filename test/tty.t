#!/usr/bin/env cram.sh

Allocate a PTY for the spacetime

	$ bst --tty --mount devpts,/dev/pts,devpts,mode=620,ptmxmode=666 tty | cat -e
	/dev/pts/0^M$

	$ bst --tty=ptmx=/dev/pts/ptmx --mount devpts,/dev/pts,devpts,mode=620,ptmxmode=666 tty | cat -e
	/dev/pts/0^M$

	$ </dev/null bst --tty stty -g | cat -e
	500:5:bf:8a3b:3:1c:7f:15:4:0:1:0:11:13:1a:0:12:f:17:16:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0^M$

Check that redirections still work

	$ echo hello | bst --tty=-echo,-onlcr cat
	hello

	$ bst --tty=-onlcr echo bonjour | cat
	bonjour

Change flags and control characters

	$ exp=$(bst --tty sh -c 'stty -echo -onlcr -icanon eof ^B intr 04 quit 16 && stty -g')
	> act=$(bst --tty='-echo,-onlcr,-icanon,veof=^B,vintr=\4,vquit=\x10' stty -g)
	> [ "$exp" = "$act" ] || echo -e "+$act\n-$exp"

	$ nexp=$(bst --tty sh -c 'stty -g')
	> act=$(bst --tty='-echo,-onlcr,-icanon,veof=^B,vintr=\4,vquit=\x10' stty -g)
	> [ "$nexp" != "$act" ] || echo "actual: $act, unexpected: $nexp"

Ensure we send the correct VEOF control character

	$ yes '' | head -c 32768 | timeout 1 bst --tty=veof=^B cat >/dev/null

	$ yes '' | head -c 32768 | timeout 1 bst --tty sh -c 'head -c 1 && stty eof ^B && cat' >/dev/null

Ensure that we send VEOF twice in case there is pending input in the pty buffer

	$ echo -n hola | bst --tty=-echo,-onlcr cat
	hola

Inner PTYs should inherit their parent termios:

	$ bst --tty sh -c '[ "$(stty -g)" = "$(bst --tty stty -g | tr -d "\r")" ]'

	$ raw=-ignbrk,-brkint,-ignpar,-parmrk,-inpck,-istrip,-inlcr,-igncr,-icrnl,-ixon,-ixoff,-icanon,-opost,-isig,-iuclc,-ixany
	> [ "$(bst --tty=$raw stty -g)" = "$(bst --tty=$raw bst --tty stty -g)" ]

#!/usr/bin/env cram.sh

Allocate a PTY for the spacetime

	$ bst --tty --mount devpts,/dev/pts,devpts,mode=620,ptmxmode=666 tty | cat -e
	/dev/pts/0^M$

	$ bst --tty=ptmx=/dev/pts/ptmx --mount devpts,/dev/pts,devpts,mode=620,ptmxmode=666 tty | cat -e
	/dev/pts/0^M$

	$ </dev/null bst --tty stty -a | cat -e
	speed 38400 baud; rows 0; columns 0; line = 0;^M$
	intr = ^C; quit = ^\; erase = ^?; kill = ^U; eof = ^D; eol = <undef>;^M$
	eol2 = <undef>; swtch = <undef>; start = ^Q; stop = ^S; susp = ^Z; rprnt = ^R;^M$
	werase = ^W; lnext = ^V; discard = ^O; min = 1; time = 0;^M$
	-parenb -parodd -cmspar cs8 -hupcl -cstopb cread -clocal -crtscts^M$
	-ignbrk -brkint -ignpar -parmrk -inpck -istrip -inlcr -igncr icrnl ixon -ixoff^M$
	-iuclc -ixany -imaxbel -iutf8^M$
	opost -olcuc -ocrnl onlcr -onocr -onlret -ofill -ofdel nl0 cr0 tab0 bs0 vt0 ff0^M$
	isig icanon iexten echo echoe echok -echonl -noflsh -xcase -tostop -echoprt^M$
	echoctl echoke -flusho -extproc^M$

Check that redirections still work

	$ echo hello | bst --tty=-echo,-onlcr cat
	hello

	$ bst --tty=-onlcr echo bonjour | cat
	bonjour

Change flags and control characters

	$ bst --tty='-echo,-onlcr,-icanon,veof=^B,vintr=\4,vquit=\x10' stty
	speed 38400 baud; line = 0;
	intr = ^D; quit = ^P; eof = ^B; min = 1; time = 0;
	-brkint -imaxbel
	-onlcr
	-icanon -echo

Ensure we send the correct VEOF control character

	$ yes '' | head -c 32768 | timeout 1 bst --tty=veof=^B cat >/dev/null

	$ yes '' | head -c 32768 | timeout 1 bst --tty sh -c 'head -c 1 && stty eof ^B && cat' >/dev/null

Ensure that we send VEOF twice in case there is pending input in the pty buffer

	$ echo -n hola | bst --tty=-echo,-onlcr cat
	hola

Inner PTYs should inherit their parent termios:

	$ bst --tty sh -c '[ "$(stty -a)" = "$(bst --tty stty -a | tr -d "\r")" ]'

	$ raw=-ignbrk,-brkint,-ignpar,-parmrk,-inpck,-istrip,-inlcr,-igncr,-icrnl,-ixon,-ixoff,-icanon,-opost,-isig,-iuclc,-ixany
	> [ "$(bst --tty=$raw stty -a)" = "$(bst --tty=$raw bst --tty stty -a)" ]

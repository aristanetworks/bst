#!/bin/sh -e

usage() {
	cat <<-EOF
	usage: $0 [options] <test file>
	       $0 [options] [directory]

	In the first form, $0 runs the system test defined in the specified file.
	In the second form, it finds all files suffixed with .t under directory.
	If the directory is not specified, the current work directory is used
	instead.

	The options are as follows:
	  -p/--patch  If there is a difference between the expeted output and the
	              actual output, the expected output in the file will be patched
	              by the actual output. Setting the environment variable
	              'CRAM_PATCH' has the same effect. The environment variable
	              can be used when passing command line option is not possible.

	The file format understood by $0 is a subset of the format used by cram
	or the glib test suite.

	Unindented lines are ignored.

	Indented lines that start with $ will execute the command that follows as
	if it was called with `sh -c 'command'`.
	Any lines below the command that are at the same indentation level are the
	expected mix of the program output and error.

	At the end of the program output, and at the same indentation level, one may
	add [exit status] to test for the program exit code when it is nonzero.

	Example:

	#!/usr/bin/env cram.sh

	Testing foo

	    $ echo foo
	    foo

	Testing something failing

	    $ echo bar; exit 1
	    bar
	    [1]
	EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
		-p|--patch) CRAM_PATCH=1;;
		-h|--help) usage; exit;;
		-*)
			>&2 echo "$0: unknown flag $1."
			>&2 usage
			exit 1;;

		--) break;;
		*)  break;;
	esac
	shift;
done

export CRAM_PATCH

what=$1

# when dir is not passed, we run in interpreter mode
if [ -f "$what" -a -x "$what" ]; then

	# reset environment, and define sensible defaults
	env -i PATH="$PATH:$(dirname $0)" LC_ALL=C TERM=dumb CRAM_PATH=$(dirname $0) \
		gawk -v what="$what" <"$what" >"$what".err '
	# This awk script does two things: first, it scans a test file and
	# executes each test command within according to the cram format.
	# Second, it outputs an "expected" test file, which looks like the input
	# test file, but has all of the stdout, stderr, and exit status of the
	# invoked commands substituted in at the right place. This means that one
	# can diff the input test file with the output of this awk script and
	# figure out quickly any difference in output or exit status.

	# maybe_exec executes (if necessary) the currently accumulated commands
	# in the cmd array, and writes its stdout/stderr and exit status, with
	# indentation.
	function maybe_exec() {
		if (cmd != "") {
			while ( ( "( set -eu\n" cmd "\n) 2>&1 || echo \\[$?\\]" | getline ln ) > 0 ) {
				if (ln == "[80]") {
					print what ":" NR ": [skipped]" | "cat 1>&2"
					cmd = ""
					exit 80
				}
				print indent ln
			}
			cmd = ""
			indent = ""
			next_re = ""
		}
	}

	# Match a command and initialize the cmd array. Commands are indented,
	# and start with `$`.
	#
	# E.g:
	#
	#    $ some command
	#
	# This also
	match($0, /^([[:space:]]+)\$([[:space:]])(.*)$/, m) {
		maybe_exec()
		print $0

		cmd = m[3]
		indent = m[1]
		# Setup the match for subsequent multi-line commands.
		next_re = "^" indent ">(" m[2] ")?(.*)$"
	}

	# Match command continuations, if we previously matched a command,
	# and append them to the cmd array. Continuations are indented, and
	# start with `>`.
	#
	# E.g:
	#
	#    $ some command
	#    > some other command
	#
	{
		if (next_re != "") {
			if (match($0, next_re, m)) {
				print $0
				cmd = cmd "\n" m[2]
			}
		}
	}

	# Match a blank or an empty line. This can only happen between two commands,
	# and therefore after an output; try to execute the accumulated cmd array.
	/^([^[:space:]].*|)$/ {
		maybe_exec()
		print $0
	}

	# EOF -- try to execute the accumulated cmd array, which if set contains the
	# last test of the file
	END {
		maybe_exec()
	}
	'
	status=$?
	set -e

	if [ "$status" -eq 80 ]; then
		# skip file
		exit 0
	elif [ "$status" -ne 0 ]; then
		exit "$status"
	fi

	# git diff complains when there are differences on the x bit
	# busybox doesn't support --reference
	if [ -x "$what" ]; then
	    chmod a+x "$what.err"
	fi

	set +e
	git diff --exit-code --text --no-index "$what" "$what.err"
	status=$?
	set -e

	if [ "$status" -eq 1 -a -n "$CRAM_PATCH" ]; then
		cp -f "$what.err" "$what"
		>&2 echo "patched $what with new changes."
	fi

	rm -f "$what.err"
	exit "$status"
fi

# Avoid going into an infinite recursive loop if $what is a
# non-directory non-executable.
if [ -n "$what" -a ! -d "$what" ]; then
    echo "cram.sh: expecting argument to be either an executable file, or a directory" 1>&2
    exit 1
fi

# $what can be empty, in which case this defaults to cwd.
find $what -name '*.t' -print0 | xargs -0 -n1 --no-run-if-empty $0

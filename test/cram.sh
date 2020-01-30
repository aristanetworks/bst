#!/bin/sh -e

usage() {
	cat <<-EOF
	usage: $0 [options] <test file>
	       $0 [options] [directory]

	In the first form, $0 runs the system test defined in the specified file.
	In the second form, it finds all files suffixed with .t under directory.
	If the directory is not specified, the current work directory is used
	instead.

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
	env -i PATH="$PATH" LC_ALL=C TERM=dumb CRAM_PATH=$(dirname $0) \
		gawk <"$what" >"$what".err '
	match($0, /^([[:space:]]+)\$(.*)$/, m) {
		print $0
		while ( ( "(" m[2] ") 2>&1 || echo [$?]" | getline ln ) > 0 ) {
			print m[1] ln
		}
	}
	/^([^[:space:]].*|)$/ {
		print $0
	}
	'

	# git diff complains when there are differences on the x bit
	# busybox doesn't support --reference
	if [ -x "$what" ]; then
	    chmod a+x "$what.err"
	fi

	set +e
	git diff --exit-code --no-index "$what" "$what.err"
	status=$?
	set -e

	if [ "$status" -eq 1 -a -n "$CRAM_PATCH" ]; then
		cp -f "$what.err" "$what"
		>&2 echo "patched $what with new changes."
	fi

	exit "$status"
fi

# $what can be empty, in which case this defaults to cwd.
find $what -name '*.t' -print0 | xargs -0 -n1 --no-run-if-empty $0


manpages = [
	'bst.1.scd',
	'bst-init.1.scd',
	'bst-unpersist.1.scd',
]

gzip = find_program('gzip')

foreach manpage : manpages
	section = manpage.split('.')[-2]
	target = '.gz'.join(manpage.split('.scd'))
	custom_target(target,
		input: manpage,
		output: target,

		command: [sh, '-c', '@0@ <$1 | @1@ -c >$2'.format(scdoc.path(), gzip.path()), '-', '@INPUT@', '@OUTPUT@'],
		install_dir: join_paths(get_option('mandir'), 'man' + section),
		install: true)
endforeach

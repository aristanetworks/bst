project('bst', 'c',
		meson_version   : '>= 0.51.0',
		license         : 'MIT',
		version         : '0.0.1',
		default_options : ['c_std=c11', 'warning_level=3'])

prefix     = get_option('prefix')
bindir     = join_paths(prefix, get_option('bindir'))
libexecdir = join_paths(prefix, get_option('libexecdir'))

git = find_program('git', required: false)

# Get the right version

is_git_repo = run_command(['[', '-d', '.git', ']']).returncode() == 0

version = 'v' + meson.project_version()
if get_option('version') != ''
	version = get_option('version')
elif git.found() and is_git_repo
	git_version = run_command([git.path(), 'describe', '--dirty', '--tags']).stdout().strip()
	branch = run_command([git.path(), 'rev-parse', '--abbrev-ref', 'HEAD']).stdout().strip()
	if branch == 'HEAD'
		branch = run_command([git.path(), 'rev-parse', 'HEAD']).stdout().strip()
	endif
	if git_version != ''
		version = git_version
	endif
	if branch != 'main'
		version = '@0@ (@1@)'.format(version, branch)
	endif
endif

cc = meson.get_compiler('c')

add_project_arguments(
	cc.get_supported_arguments([
		'-Wno-unused-parameter',
		'-Wno-unused-value',
		'-fno-strict-aliasing',
	]),
	'-D_GNU_SOURCE',
	language: ['c'])

config = configuration_data()
config.set('package', meson.project_name())
config.set('bindir', bindir)
config.set('libexecdir', libexecdir)
config.set('version', version)

configure_file(input: 'config.h.in', output: 'config.h', configuration: config)

bst_init_sources = [
	'init.c',
	'sig.c',
]

init = executable('bst-init', bst_init_sources,
	link_args: cc.get_supported_arguments([
		'-static',
	]),
	install: true)

bst_unpersist_sources = [
	'capable.c',
	'ns.c',
	'path.c',
	'unpersist.c',
]

unpersist = executable('bst-unpersist', bst_unpersist_sources, install: true)

bst_sources = [
	'bst_limits.c',
	'capable.c',
	'cp.c',
	'enter.c',
	'kvlist.c',
	'main.c',
	'mount.c',
	'net.c',
	'ns.c',
	'outer.c',
	'path.c',
	'setarch.c',
	'sig.c',
	'timens.c',
	'usage.c',
	'userns.c',
]

executable('bst', bst_sources, install: true)

if not get_option('no-setcap-or-suid')
	capabilities = {
		'bst': [
			'cap_dac_override',
			'cap_net_admin',
			'cap_setgid',
			'cap_setuid',
			'cap_sys_admin',
			'cap_sys_chroot',
			'cap_sys_ptrace',
		],
		'bst-unpersist': [
			'cap_sys_admin',
		],
	}

	setcap = find_program('setcap', '/usr/sbin/setcap', '/sbin/setcap', required: false)
	if setcap.found()
		foreach bin, caps : capabilities
			meson.add_install_script('/bin/sh', '-c', '@0@ @1@ ${MESON_INSTALL_DESTDIR_PREFIX}/bin/@2@'.format(setcap.path(), ','.join(caps) + '=p', bin))
		endforeach
	else
		chmod = find_program('chmod')
		foreach bin, _ : capabilities
			meson.add_install_script('/bin/sh', '-c', '@0@ u+s ${MESON_INSTALL_DESTDIR_PREFIX}/bin/@1@'.format(chmod.path(), bin))
		endforeach
	endif
endif

if get_option('tests')
	subdir('test')
endif

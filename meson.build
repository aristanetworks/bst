project('bst', 'c',
		meson_version   : '>= 0.51.0',
		license         : 'MIT',
		version         : '1.0.0-rc1',
		default_options : ['c_std=c11', 'warning_level=3'])

prefix     = get_option('prefix')
bindir     = join_paths(prefix, get_option('bindir'))
libexecdir = join_paths(prefix, get_option('libexecdir'))

sh    = find_program('sh')
git   = find_program('git', required: false)
scdoc = find_program('scdoc', required: get_option('man-pages'))

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

# Add source fortification by default; requires -O1 or higher.
if get_option('optimization') != '0'
	add_project_arguments(
		'-D_FORTIFY_SOURCE=2',
		language: ['c'])
endif

arch = host_machine.cpu_family()

config = configuration_data()
config.set('package', meson.project_name())
config.set('bindir', bindir)
config.set('libexecdir', libexecdir)
config.set('version', version)

config.set('ARCH', arch)
config.set('ARCH_@0@'.format(arch.to_upper()), 1)

config.set('HAVE_SYS_mount_setattr', cc.has_header_symbol('syscall.h', 'SYS_mount_setattr'))
config.set('HAVE_close_range', cc.has_function('close_range'))

libdbus = dependency('dbus-1', required: false)
config.set('HAVE_SYSTEMD', libdbus.found())

has_seccomp_unotify = cc.has_header_symbol('linux/seccomp.h', 'SECCOMP_FILTER_FLAG_NEW_LISTENER')
config.set('HAVE_SECCOMP_UNOTIFY', has_seccomp_unotify)

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
	'compat.c',
	'cgroup.c',
	'cgroup_native.c',
	'enter.c',
	'err.c',
	'fd.c',
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
	'tty.c',
	'usage.c',
	'userns.c',
]

if libdbus.found()
	bst_sources += ['cgroup_systemd.c']
endif

if has_seccomp_unotify
	bst_sources += [
		'arch/@0@/syscall.c'.format(arch),
		'proc.c',
		'sec.c',
	]
endif

executable('bst', bst_sources, install: true, dependencies: [libdbus])

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
			'cap_mknod',
		],
		'bst-unpersist': [
			'cap_sys_admin',
		],
	}

	setcap = find_program('setcap', '/usr/sbin/setcap', '/sbin/setcap', required: false)
	if setcap.found()
		foreach bin, caps : capabilities
			meson.add_install_script(sh.path(), '-c', '@0@ @1@ ${MESON_INSTALL_DESTDIR_PREFIX}/bin/@2@'.format(setcap.path(), ','.join(caps) + '=p', bin))
		endforeach
	else
		if not get_option('suid-fallback')
			error('no setcap program available, and suid-fallback=true was not set')
		endif
		chmod = find_program('chmod')
		foreach bin, _ : capabilities
			meson.add_install_script(sh.path(), '-c', '@0@ u+s ${MESON_INSTALL_DESTDIR_PREFIX}/bin/@1@'.format(chmod.path(), bin))
		endforeach
	endif
endif

doc_files = [
	'ChangeLog',
	'README.md',
	'LICENSE',
]

install_data(doc_files,
	install_dir: '@0@/doc/bst'.format(get_option('datadir')),
)

if get_option('tests')
	subdir('test')
endif

if scdoc.found()
	subdir('man')
endif

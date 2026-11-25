test_limits = executable('test_limits', ['test_limit_parsing.c', '../bst_limits.c'])

test('test_limits', test_limits)

cram_depends = []

foreach abi : ['X86', 'AARCH64']
	parser_test = executable('test_mock_syscall_' + abi.to_lower(),
		['test_mock_syscall.c', '../mock_syscall.c'],
		c_args: ['-DMOCK_SYSCALL_TEST_' + abi])
	test('test_mock_syscall_' + abi.to_lower(), parser_test)
endforeach

if has_seccomp_unotify
	mock_probe = executable('mock_probe', 'mock_probe.c', link_args: ['-static'])
	cram_depends += [mock_probe]
	if arch == 'x86_64' or arch == 'x86'
		foreach pair : [['i386', '-m32'], ['x32', '-mx32']]
			compat_flags = [pair[1], '-nostdlib', '-static', '-no-pie']
			if cc.links('void _start(void) {}', args: compat_flags,
					name: 'freestanding ' + pair[0] + ' executable')
				compat_probe = executable('mock_compat_' + pair[0], 'mock_compat.S',
					c_args: [pair[1]], link_args: compat_flags)
				test('test_mock_compat_' + pair[0], sh,
					args: [files('test_mock_compat.sh'), compat_probe, bst, pair[0], mock_probe],
					timeout: 60)
			endif
		endforeach
	endif
	foreach pair : [['X86', 'x86'], ['AARCH64', 'aarch64']]
		filter_test = executable('test_mock_filter_' + pair[1],
			['test_mock_filter.c', '../mock_filter.c', '../mock_syscall.c',
			 '../arch/' + pair[1] + '/syscall.c'],
			c_args: ['-DMOCK_SYSCALL_TEST_' + pair[0]])
		test('test_mock_filter_' + pair[1], filter_test)
	endforeach

	kernel_test = executable('test_mock_kernel',
		['test_mock_kernel.c', '../mock_filter.c', '../mock_syscall.c',
		 '../arch/' + arch + '/syscall.c'],
		include_directories: include_directories('..'))
	test('test_mock_kernel', kernel_test, timeout: 20)
endif

cram_sh = find_program('cram.sh')

executable('print_limits', ['print_limits.c'])

test('cram tests', cram_sh, args: [meson.current_source_dir()], depends: cram_depends)

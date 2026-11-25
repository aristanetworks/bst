test_limits = executable('test_limits', ['test_limit_parsing.c', '../bst_limits.c'])

test('test_limits', test_limits)

foreach abi : ['X86', 'AARCH64']
	parser_test = executable('test_mock_syscall_' + abi.to_lower(),
		['test_mock_syscall.c', '../mock_syscall.c'],
		c_args: ['-DMOCK_SYSCALL_TEST_' + abi])
	test('test_mock_syscall_' + abi.to_lower(), parser_test)
endforeach

cram_sh = find_program('cram.sh')

executable('print_limits', ['print_limits.c'])

test('cram tests', cram_sh, args: [meson.current_source_dir()])

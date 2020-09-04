test_limits = executable('test_limits', ['test_limit_parsing.c', '../bst_limits.c'])

test('test_limits', test_limits)

cram_sh = find_program('cram.sh')

executable('print_limits', ['print_limits.c'])

test('cram tests', cram_sh, args: [meson.current_source_dir()])

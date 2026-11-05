# r2frida XPS integration for radare2.
# Included from libr/xps/meson.build when r2frida sources live under
# libr/xps/p/r2frida/. Appends sources, include paths and the frida-core
# devkit to the r_core aggregate so the static plugin is linked into libr_core.

r2frida_root = meson.current_source_dir() / '..'
if not fs.exists(r2frida_root / 'ext' / 'frida' / 'frida-core.h') or not fs.exists(r2frida_root / 'config.h') or not fs.exists(r2frida_root / 'src' / '_agent.h')
  message('Preparing r2frida (frida-core devkit, config.h and agent)')
  run_command(find_program('gmake', 'make'), '-C', meson.current_source_dir(), check: true)
endif

if not is_variable('r_core_additional_deps')
  error('r2frida needs a radare2 that supports r_core_additional_deps in libr/meson.build')
endif

# frida-core bundles zlib, which clashes with the one embedded in otezip
if get_option('use_zip') and not get_option('use_sys_zip')
  error('r2frida needs -Duse_sys_zip=true (or -Duse_zip=false) to avoid duplicate zlib symbols')
endif

core_plugins += ['r2frida']

r_core_additional_inc += include_directories('../ext/frida')

r_core_additional_sources += files(
  '../src/io_frida.c',
  '../src/diagnostics.c',
  '../src/systrace.c',
  'core/core_r2frida.c',
)

r2frida_cc = meson.get_compiler('c')
r2frida_link_args = [r2frida_root / 'ext' / 'frida' / 'libfrida-core.a']
r2frida_ext_deps = [dependency('threads')]
if host_machine.system() == 'darwin'
  r2frida_link_args += ['-Wl,-no_compact_unwind', '-lbsm']
  r2frida_ext_deps += dependency('appleframeworks',
    modules: ['Foundation', 'IOKit', 'Security', 'AppKit', 'CoreFoundation', 'CoreServices'])
endif
if host_machine.system() == 'android'
  r2frida_ext_deps += [r2frida_cc.find_library('android'), r2frida_cc.find_library('log')]
else
  r2frida_ext_deps += r2frida_cc.find_library('resolv', required: false)
endif
r2frida_ext_deps += [r2frida_cc.find_library('m', required: false), r2frida_cc.find_library('dl', required: false)]

r_core_additional_deps += declare_dependency(
  link_args: r2frida_link_args,
  dependencies: r2frida_ext_deps)

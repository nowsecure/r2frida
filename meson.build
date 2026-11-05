project('r2frida', 'c',
  version: '6.2.4',
  license: 'LGPL-3.0-only',
  meson_version: '>=0.60.0',
  default_options: ['warning_level=1', 'werror=true'])

fs = import('fs')
cc = meson.get_compiler('c')
host_os = host_machine.system()

# make.bat is the single source of truth for the frida version (same as the Makefile)
frida_version = ''
r2frida_version = ''
foreach line : fs.read('make.bat').split('\n')
  line = line.strip()
  if line.startswith('set frida_version=')
    frida_version = line.split('=')[1].strip()
  elif line.startswith('set r2frida_version=')
    r2frida_version = line.split('=')[1].strip()
  endif
endforeach
if frida_version == ''
  error('Cannot find frida_version in make.bat')
endif
if r2frida_version != meson.project_version()
  error('Version mismatch: meson.build says @0@ but make.bat says @1@'.format(
    meson.project_version(), r2frida_version))
endif
frida_version_major = frida_version.split('.')[0]

# radare2
r2_deps = [
  dependency('r_core'),
  dependency('r_io'),
  dependency('r_util'),
]
r2 = find_program('r2', 'radare2', required: false)

# Frida SDK
frida_sdk_dir = get_option('frida_sdk')
if frida_sdk_dir == ''
  frida_sdk_dir = 'ext/frida'
  if not fs.exists(frida_sdk_dir / 'frida-core.h')
    message('Downloading the Frida @0@ SDK into ext/frida'.format(frida_version))
    make = find_program('gmake', 'make')
    run_command(make, '-C', meson.current_source_dir(), 'ext/frida', check: true)
  endif
endif
if not fs.exists(frida_sdk_dir / 'frida-core.h')
  error('Cannot find frida-core.h in @0@'.format(frida_sdk_dir))
endif
frida_inc = include_directories(frida_sdk_dir)
frida_link_args = [meson.current_source_dir() / frida_sdk_dir / 'libfrida-core.a']
frida_ext_deps = [dependency('threads')]

if host_os == 'darwin'
  frida_link_args += ['-Wl,-no_compact_unwind', '-lbsm']
  frida_ext_deps += dependency('appleframeworks',
    modules: ['Foundation', 'IOKit', 'Security', 'AppKit', 'CoreFoundation', 'CoreServices'])
elif host_os == 'ios'
  frida_ext_deps += dependency('appleframeworks',
    modules: ['Foundation', 'UIKit', 'CoreGraphics'])
endif
if host_os != 'android'
  frida_ext_deps += cc.find_library('resolv', required: false)
else
  frida_ext_deps += [cc.find_library('android'), cc.find_library('log')]
endif
frida_ext_deps += [cc.find_library('m', required: false), cc.find_library('dl', required: false)]

frida_dep = declare_dependency(
  include_directories: frida_inc,
  link_args: frida_link_args,
  dependencies: frida_ext_deps)

if host_os in ['linux', 'android']
  # libfrida-core.a requires its archive members to be resolved together
  frida_dep = declare_dependency(
    include_directories: frida_inc,
    link_args: ['-Wl,--start-group'] + frida_link_args + ['-Wl,--end-group'],
    dependencies: frida_ext_deps)
endif

c_args = [
  '-DFRIDA_VERSION_STRING="@0@"'.format(frida_version),
  '-DFRIDA_VERSION_MAJOR=@0@'.format(frida_version_major),
  '-DWANT_SESSION_DEBUGGER=@0@'.format(get_option('session_debugger') ? 1 : 0),
]

# Installation paths
r2_plugdir = get_option('r2_plugdir')
if r2_plugdir == '' and r2.found()
  r2_plugdir = run_command(r2, '-H',
    get_option('user_install') ? 'R2_USER_PLUGINS' : 'R2_LIBR_PLUGINS',
    check: true).stdout().strip()
endif
if r2_plugdir == ''
  r2_plugdir = get_option('libdir') / 'radare2' / dependency('r_core').version()
endif

# src/io_frida.c and src/r2frida-compile.c include "../config.h",
# which resolves to <builddir>/config.h through the src include dir.
conf = configuration_data()
conf.set('PREFIX', get_option('prefix'))
conf.set('DATADIR', get_option('prefix') / get_option('datadir'))
conf.set('VERSION', meson.project_version())
configure_file(input: 'config.h.acr', output: 'config.h', configuration: conf)
src_inc = include_directories('.', 'src')

if fs.exists('config.h') or fs.exists('src/_agent.h')
  warning('Stale config.h or src/_agent.h found in the source tree, they will shadow the meson-generated ones. Run "make clean" to remove them.')
endif

# r2frida-compile
bindir = get_option('bindir')
if get_option('user_install')
  bindir = run_command('r2pm', '-H', 'R2PM_BINDIR', check: true).stdout().strip()
endif
r2frida_compile = executable('r2frida-compile',
  'src/r2frida-compile.c', 'src/pkgmgr.c', 'src/diagnostics.c',
  c_args: c_args,
  include_directories: src_inc,
  dependencies: [r2_deps[2], frida_dep],
  install: true,
  install_dir: bindir)

# Agent: TypeScript -> _agent.js + _agent.h
python = find_program('python3', 'python')
if get_option('precompiled_agent') != ''
  agent_js = fs.copyfile(get_option('precompiled_agent'), '_agent.js')
  agent_h = custom_target('_agent.h',
    input: agent_js,
    output: '_agent.h',
    command: [python, '-c', '''
import sys
data = open(sys.argv[1], "rb").read()
with open(sys.argv[2], "w") as f:
    for i in range(0, len(data), 10):
        f.write("  " + ", ".join("0x%02x" % b for b in data[i:i + 10]) + "," + chr(10))
''', '@INPUT@', '@OUTPUT@'])
else
  agent_srcs = run_command(python, '-c',
    'import glob, sys; print("\\n".join(sorted(glob.glob(sys.argv[1] + "/src/agent/**/*.ts", recursive=True))))',
    meson.current_source_dir(),
    check: true).stdout().strip().split('\n')
  agent = custom_target('agent',
    input: ['src/agent/index.ts'] + agent_srcs,
    output: ['_agent.js', '_agent.h'],
    command: [find_program('sys/meson-agent.sh'), r2frida_compile,
      meson.current_source_dir(), '@INPUT0@', '@OUTPUT0@', '@OUTPUT1@'],
    depend_files: ['package.json', 'tsconfig.json'])
  agent_h = agent[1]
endif

# io_frida plugin
plugin_link_args = []
if host_os == 'darwin'
  plugin_link_args += '-Wl,-exported_symbol,_radare_plugin'
else
  plugin_link_args += [
    '-Wl,--version-script,@0@'.format(meson.current_source_dir() / 'ld.script'),
    '-Wl,--gc-sections',
  ]
endif
if host_os == 'linux'
  plugin_link_args += '-Wl,-z,noexecstack'
endif

shared_module('io_frida',
  'src/io_frida.c', 'src/diagnostics.c', 'src/systrace.c', agent_h,
  name_prefix: '',
  name_suffix: host_os == 'darwin' ? 'dylib' : [],
  c_args: c_args,
  include_directories: src_inc,
  dependencies: r2_deps + [frida_dep],
  link_args: plugin_link_args,
  link_depends: host_os == 'darwin' ? [] : files('ld.script'),
  install: true,
  install_dir: r2_plugdir)

# Docs
if get_option('user_install')
  r2pm_mandir = run_command('r2pm', '-H', 'R2PM_MANDIR', check: true).stdout().strip()
  install_data('r2frida.1', 'r2frida-compile.1', install_dir: r2pm_mandir / 'man1')
else
  install_man('r2frida.1', 'r2frida-compile.1')
endif
fortunes_dir = r2_plugdir / '..' / 'fortunes'
if not get_option('user_install') and get_option('r2_plugdir') == '' and r2.found()
  fortunes_dir = run_command(r2, '-H', 'R2_MAGICPATH', check: true).stdout().strip() / '..' / 'fortunes'
endif
install_data('doc/fortunes.txt',
  rename: 'r2frida.txt',
  install_dir: fortunes_dir)

summary({
  'r2frida': meson.project_version(),
  'frida': frida_version,
  'frida sdk': frida_sdk_dir,
  'plugin dir': r2_plugdir,
  'precompiled agent': get_option('precompiled_agent') != '',
})

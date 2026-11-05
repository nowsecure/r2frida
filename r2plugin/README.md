# r2plugin

This directory contains the make and meson files required to link r2frida
statically inside radare2 using the `libr/xps` (eXternal PluginS) machinery.

`io_frida.c` depends on `r_core`, so instead of going into `libr_io` it is
linked into `libr_core` together with a tiny core plugin (`core/core_r2frida.c`)
that registers the `frida://` io plugin at startup.

## Building with make

```console
git clone https://github.com/radareorg/radare2
cd radare2
git clone https://github.com/nowsecure/r2frida libr/xps/p/r2frida
cp -f libr/xps/p/r2frida/r2plugin/config.mk libr/xps/config.mk
make -C libr/xps/p/r2frida/r2plugin
make -C libr/xps
./configure && make -j && sudo make install
```

`make -C r2plugin` downloads the frida-core devkit and the precompiled agent
for the current release, and generates `config.h`. It does not need radare2
to be installed. If `src/_agent.js` already exists (built with `make -C src/agent`)
it is used instead of the released one, or set `R2FRIDA_AGENT_URL`.

## Building with meson

The meson build runs the prepare step automatically. It requires radare2 to
support `r_core_additional_deps` to link the frida-core devkit, and the system
libzip (`-Duse_sys_zip=true`) because the zlib bundled with otezip clashes
with the one inside frida-core.

```console
cp -f libr/xps/p/r2frida/r2plugin/config.mk libr/xps/config.mk
make -C libr/xps
meson setup b -Duse_sys_zip=true && ninja -C b
```

## Verify

```console
r2 -L~frida
r2 -c 'Lc~r2frida' --
```

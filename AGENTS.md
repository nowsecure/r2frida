# Agentic development guidelines for r2frida

r2frida is a Radare2 I/O plugin that bridges Frida's dynamic
instrumentation into radare2.

## Architecture

It's made of two components:

* Radare2 C plugin (`src/io_frida.c`) 
* Frida agent in TypeScript (`src/agent/`) that runs inside the process

```
radare2 ←→ io_frida.c (C plugin, I/O layer) ←→ Frida runtime ←→ agent (TypeScript, in-target)
```

## Build Commands

*Do not use node or custom gcc one-liners, always use make commands. We just use deno for indentation and r2frida-compile to build the typescript code*

- First Time: `./configure;make -j;make user-install`
- Clean: `make clean` or `make mrproper` to purge downloads
- Test: `make -C test`

**Build pipeline**: TypeScript → `frida-compile` → `_agent.js` → hex-encoded into `_agent.h` → linked into the C plugin.

## Code Style

- TypeScript: strict mode, ES2020 target, 8-space indentation
- C: formatted with `clang-format-radare2`
- ESLint with TypeScript recommended rules (many strict checks relaxed for Frida API compatibility)
- Indent C and TS code: `make fmt`

## Key Source Files

- `src/io_frida.c` — Main C plugin (device management, session lifecycle, r2 integration)
- `src/agent/index.ts` — Agent entry point and command dispatcher
- `src/agent/config.ts` — Runtime configuration
- `src/agent/lib/debug/` — Breakpoints, tracing, stalker, interceptor
- `src/agent/lib/info/` — Process maps, symbols, classes
- `src/agent/lib/fs.ts` — Remote filesystem operations
- `src/agent/lib/search.ts` — Memory search
- `src/agent/lib/java/` — Android/Java bridge
- `src/agent/lib/darwin/` — macOS/iOS + Swift support

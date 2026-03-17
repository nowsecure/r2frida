# Agentic development guidelines for r2frida

r2frida bridges Frida's dynamic instrumentation into radare2, enabling runtime analysis across Linux, macOS, Windows, iOS, and Android.

## Architecture

Two components communicate via JSON messages over the Frida runtime:

* **C plugin** (`src/io_frida.c`) — Radare2 I/O layer: device discovery, session lifecycle, memory I/O, message dispatch
* **TypeScript agent** (`src/agent/`) — Runs inside the target, 100+ commands for introspection, hooking, tracing

```
radare2 ←→ io_frida.c ←→ Frida runtime ←→ agent (TypeScript, in-target)
```

C side sends JSON requests; agent processes them and returns results.

## Build Commands

*Always use make commands. We use deno for indentation and r2frida-compile to build the TypeScript agent.*

- First time: `./configure && make -j && make user-install`
- Rebuild agent only: `make -C src/agent`
- Clean: `make clean` or `make mrproper`
- Format: `make fmt`
- Test: `make -C test`

**Build pipeline**: TypeScript → `frida-compile` → `_agent.js` → `r2frida-compile` hex-encodes into `_agent.h` → linked into C plugin.

## Testing

Tests use **r2r** framework. Test files in `test/db/extras/`:

```
NAME=test description
FILE=frida://0
CMDS=<<EOF
:commands_here
EOF
EXPECT=<<EOF
expected_output
EOF
RUN
```

Run: `make -C test` or `r2r -u db/extras`.

## Code Style

- TypeScript: strict mode, ES2020, 8-space indentation, explicit `.js` extensions in imports
- C: 4-space indentation, `clang-format-radare2`
- ESLint with many strict checks relaxed for Frida API compatibility

## Key Source Files

### C side (`src/`)

- `io_frida.c` — Main plugin
- `io_frida.h` — Data structures
- `r2frida-compile.c` — TS→hex-encoded C header compiler
- `systrace.c` — Syscall tracing

### TypeScript agent (`src/agent/`)

- `index.ts` — Entry point and command dispatcher
- `plugin.ts` — Plugin registration API
- `config.ts` — Runtime configuration (`:e key=value`)
- `io.ts` — Memory I/O
- `r2pipe-frida.ts` — R2 command bridge (native, host, agent modes)

### Agent libraries (`src/agent/lib/`)

- `debug/` — Breakpoints, tracing, stalker, interceptor, syscall tracing
- `info/` — Process maps, symbols, classes, ELF/Mach-O parsing
- `java/` — Android/Java bridge
- `darwin/` — macOS/iOS + Swift support
- `search.ts` — Memory search
- `trace.ts` — Function/instruction tracing
- `fs.ts`, `sys.ts`, `utils.ts`, `anal.ts`, `disasm.ts`

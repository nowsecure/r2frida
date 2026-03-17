# Agentic development guidelines for r2frida

r2frida is a Radare2 I/O plugin that bridges Frida's dynamic
instrumentation into radare2, enabling runtime analysis of processes
across Linux, macOS, Windows, iOS, and Android.

## Architecture

Two components communicate via JSON messages over the Frida runtime:

* **C plugin** (`src/io_frida.c`) — Radare2 I/O layer handling device discovery, session lifecycle, memory I/O, and message dispatch
* **TypeScript agent** (`src/agent/`) — Runs inside the target process, exposes 100+ commands for introspection, hooking, and tracing

```
radare2 ←→ io_frida.c (C plugin, I/O layer) ←→ Frida runtime ←→ agent (TypeScript, in-target)
```

The C side sends JSON requests; the agent processes them and returns results. R2Pipe bridges r2 commands back from the agent in three modes: **native** (direct libr_core calls), **host** (`r2frida.hostCmd`), and **agent** (`r2frida.cmd`).

## URI Format

```
frida://[action]/[link]/[device]/[target]
```

- **action**: `list`, `apps`, `attach`, `spawn`, `launch`
- **link**: `local`, `usb`, `remote host:port`
- **target**: pid, appname, process-name, program-in-PATH, or abspath

Examples: `frida://0` (attach to self), `frida://rax2` (spawn), `frida://list/usb//` (list USB processes).

## Build Commands

*Do not use node or custom gcc one-liners, always use make commands. We use deno for indentation and r2frida-compile to build the TypeScript agent.*

- First time: `./configure && make -j && make user-install`
- Rebuild agent only: `make -C src/agent`
- Clean: `make clean` or `make mrproper` to purge downloads
- Format code: `make fmt` (deno for TS, clang-format-radare2 for C)
- Test: `make -C test`
- Platform builds: `make android`, `make ios`

**Build pipeline**: TypeScript → `frida-compile` → `_agent.js` → `r2frida-compile` hex-encodes into `_agent.h` → linked into the C plugin (`io_frida.so`/`.dylib`).

## Testing

Tests use the **r2r** framework (radare2 regression testing). Test files live in `test/db/extras/` and follow this format:

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

Run tests with `make -C test` or directly with `r2r -u db/extras`.

## Code Style

- TypeScript: strict mode, ES2020 target, 8-space indentation
- C: 4-space indentation, formatted with `clang-format-radare2`
- ESLint with TypeScript recommended rules (many strict checks relaxed for Frida API compatibility — `no-explicit-any`, `no-unused-vars`, etc. are off)
- TypeScript imports use explicit `.js` extensions

## Key Source Files

### C side (`src/`)

- `io_frida.c` — Main C plugin (device management, session lifecycle, r2 integration, memory read/write)
- `io_frida.h` — Plugin data structures (`RIOFrida`, `RFPendingCmd`)
- `r2frida-compile.c` — Compiles TypeScript agent to hex-encoded C header
- `systrace.c` — Syscall tracing support
- `diagnostics.c` — Compilation diagnostics

### TypeScript agent (`src/agent/`)

- `index.ts` — Entry point; command dispatcher with 100+ handlers organized by prefix
- `plugin.ts` — Plugin registration API (`pluginRegister`, `pluginUnregister`, `pluginList`)
- `config.ts` — Runtime configuration system (`:e key=value` commands)
- `io.ts` — Memory I/O with safe and volatile modes
- `r2pipe-frida.ts` — R2 command bridge (native, host, agent modes)
- `log.ts` — Logging interface

### Agent libraries (`src/agent/lib/`)

- `debug/` — Breakpoints, tracing, stalker, interceptor, memory operations, syscall tracing
- `info/` — Process maps, symbols, classes, ELF/Mach-O parsing, lookups
- `java/` — Android/Java bridge (class enumeration, method hooking)
- `darwin/` — macOS/iOS specifics + Swift support
- `elf/` — ELF binary parsing
- `search.ts` — Memory search (strings, hex, values, instances)
- `fs.ts` — Remote filesystem operations
- `sys.ts` — System operations (env vars, dlopen, signals, kill)
- `trace.ts` — Function and instruction tracing
- `anal.ts` — Analysis helpers
- `disasm.ts` — Disassembly
- `utils.ts` — Shared utility functions

## Command Prefixes

Agent commands are invoked with `:` prefix from r2. Key groups:

- `:/` — Memory search (hex, strings, wide, values)
- `db` — Breakpoints and watchpoints
- `di` — Function interception/replacement
- `dl` — Dynamic library loading
- `dm` — Memory maps and allocation
- `dp` — Process and thread info
- `dr` — Register manipulation
- `dt` — Function tracing
- `dts` — Stalker-based code tracing
- `dd` — File descriptor operations
- `env` — Environment variables
- `:e` — Agent configuration (`:e key=value`, `:e key=?` for help)
- `:.` — Load external scripts (`.js` or `.ts`)

## Plugin System

r2frida is extensible via plugins loaded with `:. script.js` or `:. script.ts`. Example plugins live in `plugins/`. A plugin registers a command handler:

```javascript
r2frida.pluginRegister('myPlugin', function(name) {
    if (name === 'mycommand') {
        return function(args) { return 'result'; }
    }
});
```

## Agent Configuration

The agent has its own configuration layer accessed via `:e`. Key variables:

- `io.safe` — Safe memory I/O (avoids crashes on Android/thumb)
- `io.volatile` — Use Volatile IO API (requires Frida 16.1.0+)
- `search.in` — Memory ranges to search (`perm:r--`, `heap`, `current`, `path:pattern`)
- `stalker.event` — Stalker event type (`call`, `ret`, `exec`, `block`, `compile`)
- `stalker.timeout` — Stalker timeout in seconds (default 300)
- `hook.verbose`, `hook.backtrace`, `hook.time` — Tracing output controls
- `symbols.unredact` — Attempt to unredact symbol names (default on Darwin)
- `java.wait` — Wait for Java classloader readiness

## Environment Variables

- `R2FRIDA_SAFE_IO=0|1` — Workaround for Frida bug on Android/thumb
- `R2FRIDA_DEBUG=0|1` — Trace internal r2frida C and JS calls
- `R2FRIDA_RUNTIME=qjs|v8` — Select JavaScript engine for the agent (v8 is default)
- `R2FRIDA_AGENT_SCRIPT=[file]` — Override path to the agent script
- `R2FRIDA_COMPILER_DISABLE=0|1` — Disable TypeScript compiler for `:. foo.ts`
- `R2FRIDA_COMPILER_TYPECHECK=0|1` — Enable type checking in frida-compiler
- `R2FRIDA_STRICT_VERSION=0|1` — Require exact version match between client and server
- `R2FRIDA_DEBUG_URI=0|1` — Trace URI parsing and exit before connecting
- `R2FRIDA_R2SCRIPT` — Path to an r2 script to run on startup (default `~/.r2fridarc`)

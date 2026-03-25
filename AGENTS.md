# r2frida Agent Guide

r2frida connects radare2 to Frida for live process analysis.

## Main Parts

- C plugin: `src/io_frida.c`
  Handles devices, sessions, memory I/O, and JSON message dispatch.
  Commands that start with `:` go through the I/O callback.
- Agent: `src/agent/`
  Runs inside the target process. It implements commands for inspection, hooks, and tracing.
- Message flow:
  `radare2 <-> io_frida.c <-> Frida runtime <-> agent`

## Common Actions

- Build first time: `./configure && make -j && make user-install`
- Rebuild agent: `make -C src/agent`
- Format: `make fmt`
- Test: `make -C test`
- Clean: `make clean` or `make mrproper`
- Use `make` targets only. Do not run ad-hoc `gcc`, `node`, or `deno` commands.

Agent build path: TypeScript -> `_agent.js` -> `_agent.h` -> C plugin.

## Tests

- Location: `test/db/extras/`
- Runner: `make -C test` or `r2r -u db/extras`
- Format:

```sh
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

## Style

- TypeScript: strict mode, ES2020, 8-space indent, use `.js` in imports
- C: 4-space indent, format with `clang-format-radare2`
- ESLint rules are relaxed where Frida APIs need it

## Where To Edit

- C plugin: `src/io_frida.c`, `src/io_frida.h`
- Agent build tools: `src/r2frida-compile.c`
- Tracing in C: `src/systrace.c`
- Agent entry: `src/agent/index.ts`
- Agent config: `src/agent/config.ts`
- Agent I/O: `src/agent/io.ts`
- Plugin API: `src/agent/plugin.ts`
- R2 bridge: `src/agent/r2pipe-frida.ts`
- Agent libraries: `src/agent/lib/debug/`, `src/agent/lib/info/`, `src/agent/lib/java/`, `src/agent/lib/darwin/`
- Other agent helpers: `src/agent/lib/search.ts`, `src/agent/lib/trace.ts`, `src/agent/lib/fs.ts`, `src/agent/lib/sys.ts`, `src/agent/lib/utils.ts`, `src/agent/lib/anal.ts`, `src/agent/lib/disasm.ts`

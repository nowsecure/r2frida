# r2frida

Radare2 and Frida better together.

[![ci](https://github.com/nowsecure/r2frida/actions/workflows/ci.yml/badge.svg)](https://github.com/nowsecure/r2frida/actions/workflows/ci.yml)

<p align="center">
  <img src="r2frida.png" width="621px" height="372px">
</p>

## Description

This is a self-contained plugin for [radare2](https://www.radare.org) that
allows to instrument remote processes using [frida](https://www.frida.re). 

The radare project brings a complete toolchain for reverse engineering,
providing well maintained functionalities and extend its features with
other programming languages and tools.

Frida is a dynamic instrumentation toolkit that makes it easy to inspect
and manipulate running processes by injecting your own JavaScript, and
optionally also communicate with your scripts.

## Features

* Run unmodified Frida scripts (Use the `:.` command)
* Execute snippets in C, Javascript or TypeScript in any process
* Can attach, spawn or launch in local or remote systems
* List sections, symbols, exports, protocols, classes, methods
* Search for values in memory inside the agent or from the host
* Replace method implementations or create hooks with short commands
* Load libraries and frameworks in the target process
* Support Dalvik, Java, ObjC, Swift and C interfaces
* Manipulate file descriptors and environment variables
* Send signals to the process, continue, breakpoints
* The r2frida io plugin is also a filesystem **fs** and **debug** backend
* Automate r2 and frida using r2pipe
* Read/Write process memory
* Call functions, syscalls and raw code snippets
* Connect to frida-server via usb or tcp/ip
* Enumerate apps and processes
* Trace registers, arguments of functions
* Tested on x64, arm32 and arm64 for Linux, Windows, macOS, iOS and Android
* Doesn't require frida to be installed in the host (no need for frida-tools)
* Extend the r2frida commands with plugins that run in the agent
* Change page permissions, patch code and data
* Resolve symbols by name or address and import them as flags into r2
* Run r2 commands in the host from the agent
* Use r2 apis and run r2 commands inside the remote target process.
* Native breakpoints using the `:db` api
* Access remote filesystems using the `r_fs` api.

## Installation

The recommended way to install r2frida is via r2pm:

```sh
$ r2pm -ci r2frida
```

Binary builds that don't require compilation will be soon supported in
`r2pm` and `r2env`. Meanwhile feel free to download the last builds
from the [Releases page](https://github.com/nowsecure/r2frida/releases).

## Compilation

### Dependencies

* radare2
* pkg-config (not required on windows)
* curl or wget
* make, gcc
* npm, nodejs (will be soon removed)

In GNU/Debian you will need to install the following packages:

```sh
$ sudo apt install -y make gcc libzip-dev nodejs npm curl pkg-config git
```

### Instructions

```
$ git clone https://github.com/nowsecure/r2frida.git
$ cd r2frida
$ make
$ make user-install
```

### Windows

* Unzip the radare2 release zip in the root directory of the r2frida source
* rename it to `radare2` (instead of radare2-x.y.z)
* To make the VS compiler available in PATH run this batch (or r2's preconfigure.bat)

```
[Visual Studio Path]\VC\Auxiliary\Build\vcvarsall.bat [Your arch]
.\build.bat install
```

## Usage

For testing, use `r2 frida://0`, as attaching to the pid0 in frida is a special
session that runs in local. Now you can run the `:?` command to get the list
of commands available.

```
$ r2 'frida://?'
r2 frida://[action]/[link]/[device]/[target]
* action = list | apps | attach | spawn | launch
* link   = local | usb | remote host:port
* device = '' | host:port | device-id
* target = pid | appname | process-name | program-in-path | abspath
Local:
* frida://?                        # show this help
* frida://                         # list local processes
* frida://0                        # attach to frida-helper (no spawn needed)
* frida:///usr/local/bin/rax2      # abspath to spawn
* frida://rax2                     # same as above, considering local/bin is in PATH
* frida://spawn/$(program)         # spawn a new process in the current system
* frida://attach/(target)          # attach to target PID in current host
USB:
* frida://list/usb//               # list processes in the first usb device
* frida://apps/usb//               # list apps in the first usb device
* frida://attach/usb//12345        # attach to given pid in the first usb device
* frida://spawn/usb//appname       # spawn an app in the first resolved usb device
* frida://launch/usb//appname      # spawn+resume an app in the first usb device
Remote:
* frida://attach/remote/10.0.0.3:9999/558 # attach to pid 558 on tcp remote frida-server
Environment: (Use the `%` command to change the environment at runtime)
  R2FRIDA_SAFE_IO=0|1              # Workaround a Frida bug on Android/thumb
  R2FRIDA_DEBUG=0|1                # Used to debug argument parsing behaviour
  R2FRIDA_COMPILER_DISABLE=0|1     # Disable the new frida typescript compiler (`:. foo.ts`)
  R2FRIDA_AGENT_SCRIPT=[file]      # path to file of the r2frida agent
```

### Examples

```sh
$ r2 frida://0     # same as frida -p 0, connects to a local session
```

You can attach, spawn or launch to any program by name or pid, The following line will attach to the first process named `rax2` (run `rax2 -` in another terminal to test this line)

```sh
$ r2 frida://rax2  # attach to the first process named `rax2`
$ r2 frida://1234  # attach to the given pid
```

Using the absolute path of a binary to spawn will spawn the process:

```sh
$ r2 frida:///bin/ls
[0x00000000]> :dc        # continue the execution of the target program
```

Also works with arguments:

```sh
$ r2 frida://"/bin/ls -al"
```

For USB debugging iOS/Android apps use these actions. Note that `spawn`
can be replaced with `launch` or `attach`, and the process name can be
the bundleid or the PID.

```sh
$ r2 frida://spawn/usb/         # enumerate devices
$ r2 frida://spawn/usb//        # enumerate apps in the first iOS device
$ r2 frida://spawn/usb//Weather # Run the weather app
```

### Commands

These are the most frequent commands, so you must learn them and suffix it with `?` to get subcommands help.

```
:i        # get information of the target (pid, name, home, arch, bits, ..)
.:i*      # import the target process details into local r2
:?        # show all the available commands
:dm       # list maps. Use ':dm|head' and seek to the program base address
:iE       # list the exports of the current binary (seek)
:dt fread # trace the 'fread' function
:dt-*     # delete all traces
```

### Plugins

r2frida plugins run in the agent side and are registered with the `r2frida.pluginRegister` API.

See the `plugins/` directory for some more example plugin scripts.

```js
[0x00000000]> cat example.js
r2frida.pluginRegister('test', function(name) {
  if (name === 'test') {
    return function(args) {
      console.log('Hello Args From r2frida plugin', args);
      return 'Things Happen';
    }
  }
});
[0x00000000]> :. example.js   # load the plugin script
```

The `:.` command works like the r2's `.` command, but runs inside the agent.

```sh
:. a.js  # run script which registers a plugin
:.       # list plugins
:.-test  # unload a plugin by name
:.. a.js # eternalize script (keeps running after detach)
```

## Termux

If you are willing to install and use r2frida natively on Android via Termux, there are some caveats with the library dependencies because of some symbol resolutions. The way to make this work is by extending the `LD_LIBRARY_PATH` environment to point to the system directory *before* the termux libdir.

`$ LD_LIBRARY_PATH=/system/lib64:$LD_LIBRARY_PATH r2 frida://...`

## Troubleshooting

Ensure you are using a modern version of r2 (preferibly last release or git).

Run `r2 -L | grep frida` to verify if the plugin is loaded, if nothing is printed use the `R2_DEBUG=1` environment variable to get some debugging messages to find out the reason.

If you have problems compiling r2frida you can use `r2env` or fetch the release builds from the GitHub releases page, bear in mind that only MAJOR.MINOR version must match, this is r2-5.7.6 can load any plugin compiled on any version between 5.7.0 and 5.7.8.

## Design

```
 +---------+
 | radare2 |     The radare2 tool, on top of the rest
 +---------+
      :
 +----------+
 | io_frida |    r2frida io plugin
 +----------+
      :
 +---------+
 |  frida  |     Frida host APIs and logic to interact with target
 +---------+
      :
  +-------+
  |  app  |      Target process instrumented by Frida with Javascript
  +-------+
```

## Credits

This plugin has been developed by pancake aka Sergi Alvarez (the author of
radare2) for NowSecure.

I would like to thank Ole André for writing and maintaining Frida as well
as being so kind to proactively fix bugs and discuss technical details on
anything needed to make this union to work. Kudos

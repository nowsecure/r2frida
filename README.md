r2frida
=======

Radare2 and Frida better together.

| **TravisCI**  | [![Build Status](https://travis-ci.org/nowsecure/r2frida.svg?branch=master)](https://travis-ci.org/nowsecure/r2frida)|
![logo](r2frida.png)

Description
-----------
One of the main aims of the radare project is to provide a complete
toolchain for reverse engineering, providing well maintained functionalities
and extend its features with other programming languages and tools.

Frida is a dynamic instrumentation toolkit that makes it easy to inspect and
manipulate running processes by injecting your own JavaScript, and optionally
also communicate with your scripts.

For more information about those projects:

* http://github.com/radare/radare2
* http://www.frida.re

Installation
------------

In GNU/Debian you will need to install the following packages:

	$ sudo apt install -y make gcc libzip-dev nodejs npm curl pkg-config git

The recommended way to install r2frida is via r2pm:

	$ r2pm -ci r2frida

But you can always follow the standard way in here:

	$ git clone https://github.com/nowsecure/r2frida.git
	$ cd r2frida
	$ make
	$ sudo make install

Usage:
------

r2frida is used from r2 by specifying a process name:

	$ r2 frida://Twitter

Or a PID:

	$ r2 frida://1234

Or the absolute path of a binary to spawn:

	$ r2 frida:///bin/ls

also with arguments:

	$ r2 frida://"/bin/ls -al"

Alternatively also with a device ID that you retrieved through frida-ls-devices:

	$ r2 frida://device-id/Twitter

you can spawn an app on the device too, with an extra `/` and the package name (you can retrieve package names with frida-ps):

	$ r2 frida://device-id//com.atebits.Tweetie2

V8/JIT
------

In r2frida, the V8 runtime is enabled by default, set this variable to use duktape instead of v8:

	$ export R2FRIDA_DISABLE_V8=1

**Pros**: it's faster, supports ES6 and you can use the chrome tools to debug and run javascript in the agent side.
**Cons**: requires JIT permissions, so it's not working on all the iOS versions. Only on newest.

In case the target operating system doesnt supports RWX pages, frida-agent will fallback to duktape, so it's recommended to
check the `Script.runtime` variable that is also available in the `\i` r2frida command.

Once the agent is running you can run the `d.` command to start the chrometools debugger, after this load this URL in your Google Chrome:

	chrome://inspect

Termux
------
If you are willing to install and use r2frida natively on Android via Termux, there are some caveats with the library dependencies because of some symbol resolutions. The way to make this work is by extending the `LD_LIBRARY_PATH` environment to point to the system directory *before* the termux libdir.

`$ LD_LIBRARY_PATH=/system/lib64:$LD_LIBRARY_PATH r2 frida://...`

To debug plugin loading problems use the following environment variable and grep for `frida`:

`$ R_DEBUG=1 r2 -`

Design
------
	 +---------+
	 | radare2 |      The radare2 tool, on top of the rest
	 +---------+
	      :
	      :
	+-----------+
	| io_frida  |     r2frida io plugin
	+-----------+
	      :
	      :
	 +---------+
	 |  frida  |      Frida host APIs and logic to interact with target
	 +---------+
	      :
	      :
	  +--------+
	  | target |      Target process instrumented by Frida and Javascript
	  +--------+

Credits
-------
This tool has been developed by pancake aka Sergi Alvarez for NowSecure.

I would like to thank Ole André for being so nice answering and fix
bugs in Frida without those patches that would not be possible.

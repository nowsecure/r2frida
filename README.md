r2frida
=======

Radare2 and Frida better together.

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

Usage:
------
r2frida is used from r2 by specifying a process name:

	$ r2 frida://Twitter

Or a PID:

	$ r2 frida://1234

Alternatively also with a device ID that you retrieved through frida-ls-devices:

	$ r2 frida://device-id/Twitter

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

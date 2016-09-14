r2frida
=======

Radare2 and Frida better together.

Description
-----------
One of the main aims of the radare project is to provide a complete
toolchain for reverse engineering, providing well maintained functionalities
and extend its features with other programming languages and tools.

Frida is a tracer/code-injector tool that runs on top of the V8 Javascript
engine to allow interaction between host and target in a dynamic and
programatic way, which opens the door to create new tools on top of it.

The r2frida tool aims to join the power of radare2 and frida for better
analysis and understanding of running processes, mainly targetting
iOS and Android operating systems.

For more information about those projects:

* http://github.com/radare/radare2
* http://github.com/frida/frida


Usage:
------
r2frida can be used from r2:

	$ r2frida Safari

Or right from it's own NodeJS shell:

	$ r2frida -s Safari

Redirecting ports:
------------------
In order to use Frida on a remote device you need to forward the 27042 TCP
port where the `frida-server` is listening to the host machine and then
use the `-R` flag on the frida tools to use that port instead of local
instrumentation. (f.ex `frida-ps -R`)

For iOS:

	$ ssh -L 27042:localhost:27042 root@192.168.1.35

For Android:

	$ adb forward tcp:27042 tcp:27042

First session
-------------
To list processes in the target device

	$ r2frida -l   # same as frida-ps -R

Attach to a running process:

	$ r2frida Safari

Now we are ready to run some r2frida commands on it, in the r2 shell we can
run r2frida commands via the rio.system interface which is accessible with
the `=!` command prefix, this line will show the r2frida help:

	[0x00000000]> =!?
	Available r2frida commands
	dm             - show memory regions
	dp             - show current pid
	dpt            - show threads
	s <addr>       - seek to address
	b <size>       - change blocksize
	is <lib> <sym> - show address of symbol
	ie <lib>       - list exports/entrypoints of lib
	i              - show target information
	il             - list libraries
	dr             - show thread regs (see dpt)
	dt <addr> ..   - trace list of addresses
	dt-            - clear all tracing
	x @ addr       - hexdump at address
	q              - quit

Design
------

	 +---------+
	 | radare2 |      The radare2 tool, on top of the rest
	 +---------+
	      :
	      :
	+-----------+
	| r2io-pipe |     r2pipe abstraction for writing RIO plugins in NodeJS
	+-----------+
	      :
	      :
	 +---------+
	 | r2frida |      r2-like interface to interact with Frida
	 +---------+
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

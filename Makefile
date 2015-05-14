node_modules/frida:
	cp -rf /mnt/nowsecure/frida/build/frida_stripped-linux-x86_64/lib/node_modules/frida node_modules/frida
	#cp -rf /home/pancake/prg/frida/build/frida_stripped-linux-x86_64/lib/node_modules/frida node_modules/frida

run:
	r2 r2pipe://"node r2io-frida.js"

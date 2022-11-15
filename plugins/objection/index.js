// run ':. /tmp/objection-agent.js' inside an 'r2 frida://' session to load it
// run ':.-objection' to unload it and ':.' to list them all

const objectionHelp = "iosJailbreakEnable\n" + 
"iosJailbreakDisable\n" + 
"iosKeychainList\n";

r2frida.pluginRegister('objection', function(name) {
  if (name === 'objection') {
    return function(args) {
      const o = rpc.exports;
      if (args.length > 0) {
        if (args[0] === '-a') {
          return Object.keys(o).join('\n');
	}
        o[args[0]] (); // TODO: support passing arguments
        return '';
      } else {
        return objectionHelp; 
      }
    }
  }
});

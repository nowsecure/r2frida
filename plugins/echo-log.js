// run ':. echo-log.js' inside an 'r2 frida://' session to load it
// run ':e file.log=/tmp/log.txt'
// run ':echo hello world'
// run ':e-echo'

r2frida.pluginRegister('echo', function(name) {
  if (name === 'echo') {
    return function(args) {
      if (args.length === 0) {
        return 'Usage: :echo message';
      }
      const message = args.join(' ');
      r2frida.log(message);
      return '';
    }
  }
});

// run '\. plugin.js' inside an 'r2 frida://' session to load it
// run '\.-test' to unload it and '\.' to list hem all

r2frida.pluginRegister('test', function(name) {
  if (name === 'test') {
    return function(args) {
      console.log('Hello Args From r2frida plugin', args);
      return 'Things Happen';
    }
  }
});

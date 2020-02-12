// > '..immortal.js

var __printf = Module.findExportByName(null, 'printf');
Interceptor.attach(__printf, {
  onEnter: function(args) {
    this.newString = Memory.allocUtf8String('I wont die\n');
    args[0] = this.newString;
  }
});

// > '..immortal.js

var __printf = Module.getGlobalExportByName('printf');
Interceptor.attach(__printf, {
  onEnter: function(args) {
    this.newString = Memory.allocUtf8String('I wont die\n');
    args[0] = this.newString;
  }
});

'use strict';

var Cfg = {
};

var getEnvImpl = new NativeFunction(Module.findExportByName(
  'libsystem_c.dylib', 'getenv'), 'pointer', ['pointer']);
function getEnv(name) {
  return Memory.readUtf8String(getEnvImpl(Memory.allocUtf8String(name)));
}

var setEnvImpl = new NativeFunction(Module.findExportByName(
  'libsystem_c.dylib', 'setenv'), 'int', ['pointer', 'pointer', 'int']);

function setEnv(name, value, overwrite) {
  return setEnvImpl(Memory.allocUtf8String(name),
    Memory.allocUtf8String(value), overwrite ? 1 : 0);
}

var dlOpenImpl = new NativeFunction(Module.findExportByName(
  'libdyld.dylib', 'dlopen'), 'pointer', ['pointer', 'int']);

function dlOpen(lib, mode) {
  return dlOpenImpl(Memory.allocUtf8String(name),
    Memory.allocUtf8String(lib), mode);
}

function onMessage(msg) {
  var args = msg.name.split(/ /);
  var blocksize = msg.blocksize;
  function Symbol(a, t, b, c) {
    return {
      library: a,
      name: b,
      type: t,
      address: c
    };
  }
  function Message(a, b) {
    return {
      name: a,
      data: b
    };
  }
  switch (args[0]) {
    case 'dt-':
      try {
        Interceptor.detachAll();
        send(Message('dt-', {}));
      } catch (e) {
        send(Message('dt-', {
          'exception': '' + e
        }));
      }
      break;
    case 'dto':
      /* objc tracing */
      //const NSURLConnection = ObjC.classes.NSURLConnection;
      break;
    case 'dt':
      var i = 1;
      for (i = 1; i < args.length; i++) {
        (function(addr) {
          var name = '';
          // TODO: find name by offset
          Interceptor.attach(ptr(addr), {
            onEnter: function(args) {
              // get registers
              // read memory
              // execute format string to parse arguments
              var i = 1;
              var a = args[i].toInt32();
              //if (a < 0xfffff) return;
              // check if address is mapped
              var b = args[i + 1].toInt32() || 64;
              if (b > 0xfff) {
                b = 64;
              }
              var bt = Thread.backtrace(this.context).join(' ');
              //this.context, Backtracer.ACCURATE) .map(DebugSymbol.fromAddress).join(" ");
              try {
                var mem = Memory.readByteArray(ptr(args[i]), b > 0 ? b : 0);
                if (!mem) {
                  return;
                }
              } catch (err) {
                // do nothing
              }
              try {
                const obj = new ObjC.Object(args[0]);
              //const classname = obj.$className;
              //console.log (obj.$className);
              /*
                 if (obj.$kind == 'instance') {
                 if (!classname) {
                 classname = '';
                 }
                 }
              */
              } catch (e) {
                const classname = '';
              }
              send(Message('dt', {
                'addr': addr,
                'name': name,
                'bt': bt,
                'a0': args[0],
                'a1': args[1],
                'a2': args[2],
                'a3': args[3],
                'a0s': classname,
                'a1s': Memory.readUtf8String(ptr(args[1]))
              }), mem);
            },
            onLeave: function(retval) {}
          });
        })(args[i]);
      }
      break;
    case 'dl':
      var libname = args.slice(1);
      dlOpen(libname, 2);
      break;
    case 'di':
      var a = args.slice(1);
      if (a.length > 0) {
        //console.log ("Injecting call to "+a[0]+" with "+a.length-1+" args");
        var res;
        switch (a.length - 1) {
          case 1: res = (new NativeFunction(ptr(a[0]), 'int', ['int']))(a[1]);
            break;
          case 2: res = (new NativeFunction(ptr(a[0]), 'int', ['int', 'int']))(a[1], a[2]);
            break;
          case 3: res = (new NativeFunction(ptr(a[0]), 'int', ['int', 'int', 'int']))(a[1], a[2], a[3]);
            break;
          case 4: res = (new NativeFunction(ptr(a[0]), 'int', ['int', 'int', 'int', 'int']))(a[1], a[2], a[3], a[4]);
            break;
          default:
            console.log("error");
            break;
        }
        send(Message('di', {
          'res': res
        }));
      }
      break;
    case 'dt-':
      Interceptor.detachAll();
      break;
    case 'ping':
      send(Message('pong', msg));
      break;
    case 'e':
      var kv = args.slice(1).join('');
      var io = kv.indexOf('=');
      if (io != -1) {
        var k = kv.substring(0, io);
        var v = kv.substring(io + 1);
        if (v == 'false') {
          v = false;
        }
        Cfg[k] = v;
      }
      break;
    case 'env':
      var kv = args.slice(1).join('');
      var eq = kv.indexOf('=');
      if (eq) {
        var k = kv.substring(0, eq);
        var v = kv.substring(eq + 1);
        setEnvImpl(k, v, 1);
      } else {
        var v = getEnvImpl(kv);
        send(Message('env', {
          key: kv,
          value: v
        }));
      }
      break;
    case 'ie':
      if (args.length >= 2) {
        var objs = [];
        var ranges = Module.enumerateExports(args[1], {
          'onMatch': function(r) {
            objs.push(Symbol(args[1], r.type, r.name, r.address));
          },
          'onComplete': function() {
            send(Message('ie', objs));
          }
        });
      } else {
        send(Message('ie', undefined));
      }
      break;
    case 'is':
      if (args.length > 2) {
        var exp = Module.findExportByName(args[1], args[2]);
        send(Message('is', [Symbol(args[1], 'function', args[2], +exp)]));
      } else if (args.length == 2) {
        var objs = [];
        var ranges = Process.enumerateModules({
          'onMatch': function(r) {
            r.base_addr = Module.findBaseAddress(r.name);
            var e = Module.findExportByName(r.name, args[1]);
            if (e) {
              objs.push(Symbol(r.name, 'function', args[1], e));
            }
          },
          'onComplete': function() {
            send(Message('is', objs));
          }
        });
      } else if (args.length < 1) {
        send(Message('is', undefined));
      }
      break;
    case 'wx':
      try {
        var data = getDataFromArgs(args.splice(1).join(''));
        var mem = Memory.writeByteArray(ptr(msg.offset), data);
        send(Message(args[0], {
          offset: +msg.offset
        }));
      } catch (e) {
        send(Message(args[0], {
          offset: +msg.offset,
          exception: e
        }));
      }
      break;
    case 'p8':
    case 'x':
      try {
        var mem = Memory.readByteArray(ptr(msg.offset), 64); //+args[1] || blocksize);
        send(Message(args[0], {
          offset: +msg.offset
        }), mem);
      } catch (e) {
        send(Message(args[0], {
          offset: +msg.offset,
          exception: e
        }));
      }
      break;
    case 'ic':
      if (args.length > 1) {
        var classname = args[1];
        //      eval ('send(Message("ic",{methods:Object.keys(ObjC.classes.' + classname + ')}));');
        var methods = eval('Object.keys(ObjC.classes.' + classname + ');');
        var res = {};
        var instance = eval('ObjC.classes.' + classname);
        for (var i in methods) {
          var m = methods[i];
          try {
            var impl = instance[m].implementation;
            res[m] = impl;
          } catch (e) {
            res[m] = '' + e;
          // ignore
          }
        }
        send(Message('ic', {
          'methods': res
        }));
      } else {
        try {
          if (ObjC.available) {
            var classes = Object.keys(ObjC.classes);
          } else {
            var classes = [];
          }
          send(Message('ic', {
            'classes': classes
          }));
        } catch (e) {
          send(Message('ic', {
            'exception': '' + e
          }));
        }
      }
      break;
    case 'ip':
      if (args.length > 1) {
        var classname = args[1];
        eval('send(Message("ic",ObjC.classes["' + classname + '"]));');
      } else {
        try {
          if (ObjC.available) {
            var protos = Object.keys(ObjC.protocols);
          } else {
            var protos = [];
          }
          send(Message('ip', {
            'protocols': protos
          }));
        } catch (e) {
          send(Message('ip', {
            'exception': '' + e
          }));
        }
      }
      break;
    case 'i':
      var obj = {};
      obj.arch = Process.arch;
      obj.bits = Process.pointerSize * 8;
      obj.os = Process.platform;
      obj.pid = Process.getCurrentThreadId();
      obj.objc = ObjC.available;
      obj.dalvik = Dalvik.available;
      /*
      var view = UIAlertView.alloc().initWithTitle_message_delegate_cancelButtonTitle_otherButtonTitles_(
          "Frida",
          "Hello from Frida",
          ptr("0"),
          "OK",
          ptr("0"));
      view.show();
      view.release();
      */
      send(Message('i', obj));
      break;
    case 'il':
      var objs = [];
      var ranges = Process.enumerateModules({
        'onMatch': function(r) {
          r.base_addr = Module.findBaseAddress(r.name);
          objs.push(r);
        },
        'onComplete': function() {
          send(Message('il', objs));
        }
      });
      break;
    case 'dr':
      var objs = [];
      var pid = Process.getCurrentThreadId();
      var ranges = Process.enumerateThreads({
        'onMatch': function(r) {
          objs.push(r);
        },
        'onComplete': function() {
          send(Message('dr', {
            pid: pid,
            threads: objs
          }));
        }
      });
      break;
    case 'di':
      if (args.length > 1) {
        var code = args.splice(1).join(' ');
        eval(code);
        var objs = [];
        send(Message('di', objs));
      }
      /*
            var objs = [];
            var ranges = Process.enumerateThreads({
              'onMatch': function(r) {
                objs.push (r);
              },
              'onComplete': function() {
                send(Message('dpt', objs));
              }
            });
      */
      break;
    case 'dpt':
      var objs = [];
      var ranges = Process.enumerateThreads({
        'onMatch': function(r) {
          objs.push(r);
        },
        'onComplete': function() {
          send(Message('dpt', objs));
        }
      });
      break;
    case 'dm':
      var objs = [];
      var ranges = Process.enumerateRanges('---', {
        'onMatch': function(r) {
          objs.push(r);
        },
        'onComplete': function() {
          send(Message('dm', objs));
        }
      });
      break;
  }
  recv(onMessage);
}
recv(onMessage);


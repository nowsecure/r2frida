var Cfg = {};

function Offset(num, pad) {
  const hexNum = num.toString(16);
  if (hexNum.length < 8) {
    return '0x' + Array(8 - hexNum.length + 1).join('0') + hexNum;
  }
  return '0x' + hexNum;
}

var getEnvImpl = new NativeFunction(Module.findExportByName(
  'libsystem_c.dylib', 'getenv'), 'pointer', ['pointer']);
function getEnv (name) {
  return Memory.readUtf8String(getEnvImpl(Memory.allocUtf8String(name)));
}

var setEnvImpl = new NativeFunction(Module.findExportByName(
  'libsystem_c.dylib', 'setenv'), 'int', ['pointer', 'pointer', 'int']);

function setEnv (name, value, overwrite) {
  return setEnvImpl(Memory.allocUtf8String(name),
    Memory.allocUtf8String(value), overwrite ? 1 : 0);
}

var dlOpenImpl = new NativeFunction(Module.findExportByName(
  'libdyld.dylib', 'dlopen'), 'pointer', ['pointer', 'int']);

function dlOpen (lib, mode) {
  return dlOpenImpl(Memory.allocUtf8String(name),
    Memory.allocUtf8String(lib), mode);
}

function onMessage (msg) {
  var args = msg.name.split(/ /);
  var blocksize = msg.blocksize;
  function Symbol (a, t, b, c) {
    return {
      library: a,
      name: b,
      type: t,
      address: c
    };
  }
  function Message (a, b) {
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
      // const NSURLConnection = ObjC.classes.NSURLConnection;
      break;
    case 'dt':
      var i = 1;
      for (i = 1; i < args.length; i++) {
        (function (addr) {
          var name = '';
          console.log('Tracing ' + addr);
          // TODO: find name by offset
          if (addr[0] != '0' || addr[1] != 'x') {
            console.log('Argument must be an offset');
            return;
          }
          Interceptor.attach(ptr(addr), {
            onEnter: function (args) {
              // get registers
              // read memory
              // execute format string to parse arguments
              var i = 1;
              var a = args[i].toInt32();
              // if (a < 0xfffff) return;
              // check if address is mapped
              var b = args[i + 1].toInt32() || 64;
              if (b > 0xfff) {
                b = 64;
              }
              try {
                var bt = Thread.backtrace(this.context);
              // var bt = [this.returnAddress];
              } catch (e) {
	                                                                                                                                    console.log('' + e);
              }
              var bts = bt.join(' ');
              /*
              if (Cfg['trace.from'] && Cfg['trace.to']) {
              if (+Cfg['trace.from'] < bt[0] || +Cfg['trace.to'] > bt[0]) {
              console.log("skip");
              return;
              }
              }
              */
              // this.context, Backtracer.ACCURATE) .map(DebugSymbol.fromAddress).join(" ");
              try {
                var mem = Memory.readByteArray(ptr(args[i]), b > 0 ? b : 0);
                if (!mem) {
                  return;
                }
              } catch (err) {
                // do nothing
              }
              var classname = '';
              try {
                var methodname = Memory.readUtf8String(ptr(args[1]));
		                                                                                                                                                                if (args[0].isNull()) {
			                    classname = 'null';
		} else {
			// / XXX frida bug makes app crash here
			                    var obj = new ObjC.Object(args[0]);
			                    classname = obj.$className;
		}
              // classname = ''+obj;
              /*
              console.log("PRE",args[0]);
              console.log("POS", classname);
              classname = "";
              */
              // const classname = obj.$className;
              // console.log (obj.$className);
              /*
                 if (obj.$kind == 'instance') {
			 if (!classname) {
				 classname = '';
			 }
                 }
              */
              } catch (e) {
                var methodname = '';
              }
              console.log(classname, methodname);
              send(Message('dt', {
                'addr': addr,
                'name': name,
                'bt': bts, // must pass a string not an array
                'a0': args[0],
                'a1': args[1],
                'a2': args[2],
                'a3': args[3],
                'a0s': classname,
                'a1s': methodname
              }), mem);
            },
            onLeave: function (retval) {}
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
        // console.log ("Injecting call to "+a[0]+" with "+a.length-1+" args");
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
            console.log('error');
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
      const kv = args.slice(1).join('');
      const io = kv.indexOf('=');
      if (io !== -1) {
        var k = kv.substring(0, io);
        var v = kv.substring(io + 1);
        if (v === 'false') {
          v = false;
        }
        Cfg[k] = v;
      }
      break;
    case 'env': {
      const kv = args.slice(1).join('');
      const eq = kv.indexOf('=');
      if (eq) {
        const k = kv.substring(0, eq);
        const v = kv.substring(eq + 1);
        setEnvImpl(k, v, 1);
      } else {
        const v = getEnvImpl(kv);
        send(Message('env', {
          key: kv,
          value: v
        }));
      }
      } break;
    case 'ie':
      if (args.length >= 2) {
        var objs = [];
        var ranges = Module.enumerateExports(args[1], {
          'onMatch': function (r) {
            objs.push(Symbol(args[1], r.type, r.name, r.address));
          },
          'onComplete': function () {
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
      } else if (args.length === 2) {
        var objs = [];
        var ranges = Process.enumerateModules({
          'onMatch': function (r) {
            r.base_addr = Module.findBaseAddress(r.name);
            var e = Module.findExportByName(r.name, args[1]);
            if (e) {
              objs.push(Symbol(r.name, 'function', args[1], e));
            }
          },
          'onComplete': function () {
            send(Message('is', objs));
          }
        });
      } else if (args.length < 1) {
        send(Message('is', undefined));
      }
      break;
    case 'wx':
      try {
        const data = new Buffer(args.splice(1).join(''), 'hex');
        const mem = Memory.writeByteArray(ptr(msg.offset), data);
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
    case 'pd':
      try {
        var count = 10;
        var str = '';
        var at = ptr(msg.offset);
        for (var i = 0; i < count; i++) {
          try {
            let inst = Instruction.parse(at);
            str += Offset(+at, 10) + '   ' + inst + '\n';
            at = inst.next;
          } catch (e) {
            console.error(at, e);
            at = at.add(4);
          }
        }
        send(Message(args[0], {
          offset: +msg.offset,
          text: str
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
        var mem = Memory.readByteArray(ptr(msg.offset), 64); // +args[1] || blocksize);
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
        const classname = args[1];
        // eval ('send(Message("ic",{methods:Object.keys(ObjC.classes.' + classname + ')}));');
        const instance = ObjC.classes[classname];
        const methods = Object.keys(instance);
        const res = {};
        for (var mi in methods) {
          var m = methods[mi];
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
        'onMatch': function (r) {
          r.base_addr = Module.findBaseAddress(r.name);
          objs.push(r);
        },
        'onComplete': function () {
          send(Message('il', objs));
        }
      });
      break;
    case 'dr':
      var objs = [];
      var pid = Process.getCurrentThreadId();
      var ranges = Process.enumerateThreads({
        'onMatch': function (r) {
          // objs.push(JSON.parse(JSON.stringify(r)));
          objs.push(r);
        },
        'onComplete': function () {
          send(Message('dr', {
            pid: pid,
            threads: objs
          }));
        }
      });
      break;
/*
    case 'di':
      if (args.length > 1) {
        var code = args.splice(1).join(' ');
        eval(code);
        var objs = [];
        send(Message('di', objs));
      }
*/
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
      break;
      */
    case 'dpt':
      var objs = [];
      var ranges = Process.enumerateThreads({
        'onMatch': function (r) {
          objs.push(r);
        },
        'onComplete': function () {
          send(Message('dpt', objs));
        }
      });
      break;
    case 'dm':
      var objs = [];
      var ranges = Process.enumerateRanges('---', {
        'onMatch': function (r) {
          objs.push(r);
        },
        'onComplete': function () {
          send(Message('dm', objs));
        }
      });
      break;
  }
  recv(onMessage);
}
recv(onMessage);


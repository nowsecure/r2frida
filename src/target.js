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
              if (a < 0xfffff) return;
              // check if address is mapped
              var b = args[i + 1].toInt32() || 64;
              if (b > 0xfff) {
                b = 64;
              }
              try {
                var mem = Memory.readByteArray(ptr(a), b);
                if (!mem) {
                  return;
                }
              } catch ( err ) {
                // do nothing
              }
              send(Message('dt', {
                'addr': addr,
                'name': name,
                'a0': args[0].toInt32(),
                'a1': args[1].toInt32(),
                'a2': args[2].toInt32(),
                'a3': args[3].toInt32()
              }), mem);
            },
            onLeave: function(retval) {}
          });
        })(args[i]);
      }
      break;
    case 'dt-':
      Interceptor.detachAll();
      break;
    case 'ping':
      send(Message('pong', msg));
      break;
    case 'ie':
      if (args.length >= 2) {
        var objs = [];
        var ranges = Module.enumerateExports(args[1], {
          'onMatch': function(r) {
            objs.push (Symbol(args[1], r.type, r.name, r.address));
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
            r.base = Module.findBaseAddress(r.name);
            var e = Module.findExportByName(r.name, args[1]);
            if (e) {
              objs.push (Symbol(r.name, 'function', args[1], e));
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
    case 'x':
      try {
        var mem = Memory.readByteArray(ptr(msg.offset), +args[1] || blocksize);
        send ({
          name: 'x',
          offset: +msg.offset
        }, mem);
      } catch ( e ) {
        send ({
          name: 'x',
          offset: +msg.offset
        }); //[1,2,3]);
      }
      break;
    case 'ic':
      send(Message ('ic', ObjC.classes));
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
          r.base = Module.findBaseAddress(r.name);
          objs.push (r);
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
          objs.push (r);
        },
        'onComplete': function() {
          send(Message('dr', {
            pid: pid,
            threads: objs
          }));
        }
      });
      break;
    case 'dpt':
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
    case 'dm':
      var objs = [];
      var ranges = Process.enumerateRanges('---', {
        'onMatch': function(r) {
          objs.push (r);
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


/*
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
*/

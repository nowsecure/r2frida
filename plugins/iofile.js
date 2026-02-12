// iofile plugin - redirect r2frida IO to read/write from a file
// useful for reading /proc/pid/mem or any other remote file
// run ':. iofile.js' inside an 'r2 frida://' session to load it
// run ':.iofile' to show help

function sym(name, ret, arg) {
  try {
    return new NativeFunction(Module.getGlobalExportByName(name), ret, arg);
  } catch (e) {
    return null;
  }
}

const _open = sym('open', 'int', ['pointer', 'int']);
const _close = sym('close', 'int', ['int']);
const _read = sym('read', 'int', ['int', 'pointer', 'int']);
const _write = sym('write', 'int', ['int', 'pointer', 'int']);
const _lseek = sym('lseek', 'int64', ['int', 'int64', 'int']);

let currentFd = -1;
let currentPath = '';

function showHelp() {
  return 'iofile Commands:\n'
    + 'iofile [path]  - redirect IO to read/write from the given file\n'
    + 'iofile         - show current status\n'
    + 'iofile close   - close the file and restore normal IO\n'
    + '\n'
    + 'Examples:\n'
    + '  iofile /proc/1234/mem  - read memory of pid 1234\n'
    + '  iofile /dev/mem        - read physical memory (requires root)\n'
    + '  iofile /path/to/file   - read any file as if it were memory\n';
}

function hookedRead(offset, count) {
  if (currentFd < 0) {
    return [{}, []];
  }
  const offsetNum = (typeof offset === 'string') ? parseInt(offset, 16) : offset;
  const seeked = _lseek(currentFd, offsetNum, 0); // SEEK_SET = 0
  if (seeked < 0) {
    return [{}, []];
  }
  const buf = Memory.alloc(count);
  const bytesRead = _read(currentFd, buf, count);
  if (bytesRead <= 0) {
    return [{}, []];
  }
  const data = buf.readByteArray(bytesRead);
  return [{}, data];
}

function hookedWrite(offset, data) {
  if (currentFd < 0) {
    return [{}, null];
  }
  const offsetNum = (typeof offset === 'object') ? offset.toInt32() : 
                    (typeof offset === 'string') ? parseInt(offset, 16) : offset;
  const seeked = _lseek(currentFd, offsetNum, 0); // SEEK_SET = 0
  if (seeked < 0) {
    return [{}, null];
  }
  const count = data.byteLength;
  const buf = Memory.alloc(count);
  buf.writeByteArray(data);
  _write(currentFd, buf, count);
  return [{}, null];
}

function openFile(path) {
  if (currentFd >= 0) {
    _close(currentFd);
    currentFd = -1;
    currentPath = '';
  }
  const O_RDWR = 2;
  const O_RDONLY = 0;
  const pathPtr = Memory.allocUtf8String(path);
  let fd = _open(pathPtr, O_RDWR);
  if (fd < 0) {
    fd = _open(pathPtr, O_RDONLY);
  }
  if (fd < 0) {
    return 'ERROR: cannot open ' + path;
  }
  currentFd = fd;
  currentPath = path;
  r2frida.hookedRead = hookedRead;
  r2frida.hookedWrite = hookedWrite;
  return 'IO redirected to: ' + path + ' (fd=' + fd + ')';
}

function closeFile() {
  if (currentFd >= 0) {
    _close(currentFd);
    currentFd = -1;
    currentPath = '';
  }
  r2frida.hookedRead = null;
  r2frida.hookedWrite = null;
  return 'IO restored to normal';
}

function getStatus() {
  if (currentFd < 0) {
    return 'IO: normal (not redirected)';
  }
  return 'IO redirected to: ' + currentPath + ' (fd=' + currentFd + ')';
}

r2frida.pluginRegister('iofile', function(name) {
  if (name === 'iofile') {
    return function(args) {
      if (_open === null || _lseek === null || _read === null) {
        return 'ERROR: required libc symbols not found';
      }
      if (args.length === 0) {
        if (currentFd < 0) {
          return showHelp();
        }
        return getStatus();
      }
      const command = args[0];
      switch (command) {
        case 'help':
        case '-h':
        case '?':
          return showHelp();
        case 'close':
        case 'off':
        case 'noio':
          return closeFile();
        default:
          return openFile(command);
      }
    };
  }
});

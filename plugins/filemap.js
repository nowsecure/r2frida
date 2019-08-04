r2frida.pluginRegister('filemap', fileMap);

function sym (name, ret, arg) {
  try {
    return new NativeFunction(Module.findExportByName(null, name), ret, arg);
  } catch (e) {
    console.error(name, ':', e);
  }
}

const open = sym('open', 'int', ['pointer', 'int']);
const lseek = sym('lseek', 'int', ['int', 'int', 'int']);
const mmap = sym('mmap', 'pointer', ['pointer', 'int', 'int', 'int', 'int', 'int']);

function fileMap (command) {
  return (command === 'fmap')
    ? hookFileMap : undefined;
}

function hookFileMap (args) {
  if (args.length === 0) {
    return 'Usage: fmap [path-to-file]';
  }
  const fileName = Memory.allocUtf8String(args[0]);
  const fd = open(fileName, 0);
  const fileSize = lseek(fd, 0, 2);
  const PROT_READ = 1;
  const MAP_FILE = 0;
  const MAP_PRIVATE = 2;
  const res = mmap(ptr(0), fileSize, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
  return ['wtf', args[0], fileSize, '@', res].join(' ');
  // return 'Address: ' + res + '\n' + 'Size: ' + filesize + '\n';
}

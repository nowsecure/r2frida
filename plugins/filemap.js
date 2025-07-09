r2frida.pluginRegister('filemap', fileMap);

function sym (name, ret, arg) {
  try {
    return new NativeFunction(Module.getGlobalExportByName(name), ret, arg);
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
  const pathName = args[0];
  const heapName = Memory.allocUtf8String(args[0]);
  const slash = pathName.lastIndexOf('/');
  const fileName = pathName.substring (slash + 1);
  const fd = open(heapName, 0);
  const fileSize = lseek(fd, 0, 2);
  const PROT_READ = 1;
  const MAP_FILE = 0;
  const MAP_PRIVATE = 2;
  const res = mmap(ptr(0), fileSize, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
  return ['wtf', fileName, fileSize, '@', res].join(' ');
}

const MIN_PTR = ptr('0x100000000');
const ISA_MASK = ptr('0x0000000ffffffff8');
const ISA_MAGIC_MASK = ptr('0x000003f000000001');
const ISA_MAGIC_VALUE = ptr('0x000001a000000001');

module.exports = isObjC;

function isObjC (p) {
  const klass = getObjCClassPtr(p);
  if (klass.isNull()) {
    return false;
  }
  return true;
}

function getObjCClassPtr (p) {
  if (!looksValid(p)) {
    return NULL;
  }
  const isa = p.readPointer();
  let classP = isa;
  if (classP.and(ISA_MAGIC_MASK).equals(ISA_MAGIC_VALUE)) {
    classP = isa.and(ISA_MASK);
  }
  if (looksValid(classP)) {
    return classP;
  }
  return NULL;
}

function looksValid (p) {
  return p.compare(MIN_PTR) >= 0 && isReadable(p);
}

function isReadable (p) {
  // TODO: catching access violation isn't compatible with jailed testing
  try {
    p.readU8(p);
    return true;
  } catch (e) {
    return false;
  }
}

'use strict';

const handlers = {
  seek: seek,
  read: read
};

let currentOffset = NULL;
let cachedRanges = null;
let firstRange = null;
let lastRange = null;
let lastRangeEnd = NULL;

function seek(params) {
  const {whence, offset} = params;
  const offsetPtr = ptr(offset);

  if (cachedRanges === null) {
    cachedRanges = Process.enumerateRangesSync({
      protection: 'r--',
      coalesce: true
    });
    firstRange = cachedRanges[0];
    lastRange = cachedRanges[cachedRanges.length - 1];
    lastRangeEnd = lastRange.base.add(lastRange.size);
  }

  switch (whence) {
    case 'SEEK_SET':
      performSeek(offsetPtr);
      break;
    case 'SEEK_CUR':
      performSeek(currentOffset.add(offsetPtr));
      break;
    case 'SEEK_END':
      performSeek(lastRangeEnd.sub(offsetPtr));
      break;
  }

  return [{
      offset: currentOffset
    },
    null
  ];
}

function performSeek(offset) {
  if (offset.compare(firstRange.base) === -1) {
    currentOffset = firstRange.base;
  } else {
    if (offset.compare(lastRangeEnd) === 1)
      currentOffset = lastRangeEnd.sub(Process.pageSize);
    else
      currentOffset = offset;
  }
}

function read(params) {
  const {count} = params;

  const bytes = Memory.readByteArray(currentOffset, count);

  return [{}, bytes];
}

function onStanza(stanza) {
  const handler = handlers[stanza.type];
  if (handler !== undefined) {
    try {
      const [replyStanza, replyBytes] = handler(stanza.payload);
      send(replyStanza, replyBytes);
    } catch (e) {
      send({
        error: e.message
      });
    }
  } else {
    console.error('Unhandled stanza: ' + stanza.type);
  }

  recv(onStanza);
}
recv(onStanza);

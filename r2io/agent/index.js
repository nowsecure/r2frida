'use strict';

const handlers = {
  read: read
};

function read(params) {
  const {offset, count} = params;

  const bytes = Memory.readByteArray(ptr(offset), count);

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

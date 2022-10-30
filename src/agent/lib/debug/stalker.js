/* eslint-disable comma-dangle */
'use strict';

const config = require('../../config');
const disasm = require('../disasm');
const debug = require('../debug');
const utils = require('../utils');

const eventsByThread = {};
const inModules = [];

function stalkFunction (config, address) {
  return new Promise((resolve, reject) => {
    const recursiveCountByThread = {};
    const threads = new Set();
    const completedThreads = new Set();
    let aliveTimeout = null;

    _clearEvents();
    _initModules(config);

    const hook = Interceptor.attach(address, {
      onEnter () {
        tickAlive();

        this.myThreadId = Process.getCurrentThreadId();
        let recursiveCount = recursiveCountByThread[this.myThreadId] || 0;
        recursiveCount++;
        recursiveCountByThread[this.myThreadId] = recursiveCount;

        if (recursiveCount === 1) {
          threads.add(this.myThreadId);
          _followHere(config);
        }
      },

      onLeave () {
        tickAlive();

        let recursiveCount = recursiveCountByThread[this.myThreadId];
        recursiveCount--;
        recursiveCountByThread[this.myThreadId] = recursiveCount;

        if (recursiveCount === 0) {
          threads.delete(this.myThreadId);
          completedThreads.add(this.myThreadId);
          _unfollowHere();
          if (threads.size === 0) {
            hook.detach();
            if (aliveTimeout !== null) {
              clearTimeout(aliveTimeout);
              aliveTimeout = null;
            }
            _notifyEvents(completedThreads, resolve);
          }
        }
      }
    });

    tickAlive();

    function tickAlive () {
      if (config.timeout === 0) {
        return;
      }
      if (aliveTimeout !== null) {
        clearTimeout(aliveTimeout);
      }
      const milliseconds = (config.timeout >> 0) * 1000;
      aliveTimeout = setTimeout(selfDestruct, milliseconds);
    }

    function selfDestruct () {
      hook.detach();
      unfollowAll();
      Stalker.garbageCollect();

      const tids = Object.keys(eventsByThread);
      tids.forEach((threadId) => {
        delete eventsByThread[threadId];
      });

      reject(new Error('Stalker timeout reached'));
    }
  });
}

function stalkEverything (config, timeout) {
  return new Promise((resolve, reject) => {
    _clearEvents();
    _initModules(config);

    const threads = Process.enumerateThreadsSync();
    for (const thread of threads) {
      _followThread(config, thread.id);
    }

    let _timeout = timeout || config.timeout;
    if (_timeout === 0) {
      _timeout = 30;
    }

    setTimeout(() => {
      for (const thread of threads) {
        Stalker.unfollow(thread.id);
      }
      _notifyEvents(threads.map((thread) => thread.id), resolve);
    }, (_timeout >> 0) * 1000);
  });
}

function _notifyEvents (completedThreads, resolve) {
  Stalker.garbageCollect();
  setTimeout(() => {
    const result = {};
    for (const threadId of completedThreads) {
      if (threadId in eventsByThread) {
        result[threadId] = eventsByThread[threadId];
        delete eventsByThread[threadId];
      }
    }
    resolve(result);
  }, 1000);
}

function _clearEvents () {
  const threadIds = Object.keys(eventsByThread);
  for (const threadId of threadIds) {
    delete eventsByThread[threadId];
  }
}

function _followHere (config) {
  const threadId = Process.getCurrentThreadId();

  _followThread(config, threadId);

  return threadId;
}

function _followThread (config, threadId) {
  Stalker.follow(threadId, {
    events: _eventsFromConfig(config),
    onReceive: function (events) {
      const parsed = Stalker
        .parse(events, { annotate: false })
        .filter(_filterEvent);

      if (parsed.length === 0) {
        return;
      }

      if (threadId in eventsByThread) {
        eventsByThread[threadId].push(...parsed);
      } else {
        eventsByThread[threadId] = parsed;
      }
    }
  });
}

function _unfollowHere () {
  Stalker.unfollow();
}

function unfollowAll () {
  const threads = Process.enumerateThreadsSync();
  for (const thread of threads) {
    Stalker.unfollow(thread.id);
  }
}

function _eventsFromConfig (config) {
  const events = {
    call: false,
    ret: false,
    exec: false,
    block: false,
    compile: false
  };

  events[config.event] = true;

  return events;
}

function _filterEvent (event) {
  if (inModules.length === 0) {
    return true;
  }

  const address = event[0];
  return inModules.some(([start, end]) => {
    return address.compare(start) >= 0 && address.compare(end) <= 0;
  });
}

function _initModules (config) {
  inModules.splice(0, -1);

  switch (config.stalkin) {
    case 'app': {
      const appModule = Process.enumerateModulesSync()[0];
      inModules.push([appModule.base, appModule.base.add(appModule.size)]);
      return;
    }
    case 'modules': {
      inModules.push(...Process.enumerateModulesSync().map((module) => {
        return [module.base, module.base.add(module.size)];
      }));
      break;
    }
    default:
      break;
  }
}

function stalkTraceEverything (args) {
  if (args.length === 0) {
    return 'Warning: dts is experimental and slow\nUsage: dts [symbol]';
  }
  return _stalkTraceSomething(_stalkEverythingAndGetEvents, args);
}

function stalkTraceEverythingHelp () {
  return `Usage: dts[j*] [symbol|address] - Trace given symbol using the Frida Stalker
dtsf[*j] [sym|addr]        Trace address or symbol using the stalker
dts[*j] seconds            Trace all threads for given seconds using the stalker
`;
}

function stalkTraceEverythingJson (args) {
  if (args.length === 0) {
    return 'Warning: dts is experimental and slow\nUsage: dtsj [symbol]';
  }
  return _stalkTraceSomethingJson(_stalkEverythingAndGetEvents, args);
}

function stalkTraceEverythingR2 (args) {
  if (args.length === 0) {
    return 'Warning: dts is experimental and slow\nUsage: dts* [symbol]';
  }
  return _stalkTraceSomethingR2(_stalkEverythingAndGetEvents, args);
}

function stalkTraceFunction (args) {
  return _stalkTraceSomething(_stalkFunctionAndGetEvents, args);
}

function stalkTraceFunctionJson (args) {
  return _stalkTraceSomethingJson(_stalkFunctionAndGetEvents, args);
}

function stalkTraceFunctionR2 (args) {
  return _stalkTraceSomethingR2(_stalkFunctionAndGetEvents, args);
}

function _stalkTraceSomething (getEvents, args) {
  return getEvents(args, (isBlock, events) => {
    let previousSymbolName;
    const result = [];
    const threads = Object.keys(events);

    for (const threadId of threads) {
      result.push(`; --- thread ${threadId} --- ;`);
      if (isBlock) {
        result.push(..._mapBlockEvents(events[threadId], (address) => {
          const pd = disasmOne(address, previousSymbolName);
          previousSymbolName = _getSymbolName(address);
          return pd;
        }, (begin, end) => {
          previousSymbolName = null;
          return '';
        }));
      } else {
        result.push(...events[threadId].map((event) => {
          const address = event[0];
          const target = event[1];
          const pd = disasmOne(address, previousSymbolName, target);
          previousSymbolName = _getSymbolName(address);
          return pd;
        }));
      }
    }
    return result.join('\n') + '\n';
  });

  function disasmOne (address, previousSymbolName, target) {
    let pd = disasm(address, 1, previousSymbolName);
    if (pd.endsWith('\n')) {
      pd = pd.slice(0, -1);
    }
    if (target) {
      pd += ` ; ${target} ${_getSymbolName(target)}`;
    }
    return pd;
  }
}

function _stalkTraceSomethingR2 (getEvents, args) {
  return getEvents(args, (isBlock, events) => {
    const result = [];
    const threads = Object.keys(events);

    for (const threadId of threads) {
      if (isBlock) {
        result.push(..._mapBlockEvents(events[threadId], (address) => {
          return `dt+ ${address} 1`;
        }));
      } else {
        result.push(...events[threadId].map((event) => {
          const commands = [];

          const location = event[0];
          commands.push(`dt+ ${location} 1`);

          const target = event[1];
          if (target) {
            commands.push(`CC ${target} ${_getSymbolName(target)} @ ${location}`);
          }
          return commands.join('\n') + '\n';
        }));
      }
    }

    return result.join('\n') + '\n';
  });
}

function _stalkTraceSomethingJson (getEvents, args) {
  return getEvents(args, (isBlock, events) => {
    const result = {
      event: config.get('stalker.event'),
      threads: events
    };

    return result;
  });
}

function _stalkFunctionAndGetEvents (args, eventsHandler) {
  utils.requireFridaVersion(10, 3, 13);

  const at = utils.getPtr(args[0]);
  const conf = {
    event: config.get('stalker.event'),
    timeout: config.get('stalker.timeout'),
    stalkin: config.get('stalker.in')
  };
  const isBlock = conf.event === 'block' || conf.event === 'compile';

  const operation = stalkFunction(conf, at)
    .then((events) => {
      return eventsHandler(isBlock, events);
    });

  debug.breakpointContinue([]);
  return operation;
}

function _stalkEverythingAndGetEvents (args, eventsHandler) {
  utils.requireFridaVersion(10, 3, 13);

  const timeout = (args.length > 0) ? +args[0] : null;
  const conf = {
    event: config.get('stalker.event'),
    timeout: config.get('stalker.timeout'),
    stalkin: config.get('stalker.in')
  };
  const isBlock = conf.event === 'block' || conf.event === 'compile';

  const operation = stalkEverything(conf, timeout)
    .then((events) => {
      return eventsHandler(isBlock, events);
    });

  debug.breakpointContinue([]);
  return operation;
}

function _mapBlockEvents (events, onInstruction, onBlock) {
  const result = [];

  events.forEach(([begin, end]) => {
    if (typeof onBlock === 'function') {
      result.push(onBlock(begin, end));
    }
    let cursor = begin;
    while (cursor < end) {
      const [instr, next] = disasm.tolerantInstructionParse(cursor);
      if (instr !== null) {
        result.push(onInstruction(cursor));
      }
      cursor = next;
    }
  });
  return result;
}

function _getSymbolName (address) {
  const ds = DebugSymbol.fromAddress(address);
  return (ds.name === null || ds.name.indexOf('0x') === 0) ? '' : ds.name;
}

module.exports = {
  stalkFunction,
  stalkEverything,
  stalkTraceEverything,
  stalkTraceEverythingHelp,
  stalkTraceEverythingJson,
  stalkTraceEverythingR2,
  stalkTraceFunction,
  stalkTraceFunctionJson,
  stalkTraceFunctionR2
};

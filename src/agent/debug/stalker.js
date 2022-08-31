/* eslint-disable comma-dangle */
'use strict';

const eventsByThread = {};
const inModules = [];

module.exports = {
  stalkFunction: stalkFunction,
  stalkEverything: stalkEverything,
};

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
    case 'app':
      const appModule = Process.enumerateModulesSync()[0];
      inModules.push([appModule.base, appModule.base.add(appModule.size)]);
      return;
    case 'modules':
      inModules.push(...Process.enumerateModulesSync().map((module) => {
        return [module.base, module.base.add(module.size)];
      }));
      break;
    default:
      break;
  }
}

/* globals Interceptor, Stalker */

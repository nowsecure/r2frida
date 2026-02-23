import config from "../../config.js";
import disasm from "../disasm.js";
import * as debug from "./index.js";
import * as breakpoints from "./breakpoints.js";
import * as utils from "../utils.js";

const eventsByThread: any = {};
const inModules: any = [];

function stalkFunction(config: any, address: any) {
    return new Promise((resolve, reject) => {
        const recursiveCountByThread: any = {};
        const threads = new Set();
        const completedThreads = new Set();
        let aliveTimeout: any = null;
        _clearEvents();
        _initModules(config);
        const hook = Interceptor.attach(address, {
            onEnter() {
                tickAlive();
                this.myThreadId = Process.getCurrentThreadId();
                let recursiveCount = recursiveCountByThread[this.myThreadId] ||
                    0;
                recursiveCount++;
                recursiveCountByThread[this.myThreadId] = recursiveCount;
                if (recursiveCount === 1) {
                    threads.add(this.myThreadId);
                    _followHere(config);
                }
            },
            onLeave() {
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
            },
        });
        tickAlive();
        function tickAlive() {
            if (config.timeout === 0) {
                return;
            }
            if (aliveTimeout !== null) {
                clearTimeout(aliveTimeout);
            }
            const milliseconds = (config.timeout >> 0) * 1000;
            aliveTimeout = setTimeout(selfDestruct, milliseconds);
        }
        function selfDestruct() {
            hook.detach();
            unfollowAll();
            Stalker.garbageCollect();
            const tids = Object.keys(eventsByThread);
            tids.forEach((threadId) => {
                delete eventsByThread[threadId];
            });
            reject(new Error("Stalker timeout reached"));
        }
    });
}

function stalkEverything(config: any, timeout: number) {
    return new Promise((resolve, reject) => {
        _clearEvents();
        _initModules(config);
        const threads = Process.enumerateThreads();
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
            _notifyEvents(threads.map((thread: any) => thread.id), resolve);
        }, (_timeout >> 0) * 1000);
    });
}

function _notifyEvents(completedThreads: any, resolve: any) {
    Stalker.garbageCollect();
    setTimeout(() => {
        const result: any = {};
        for (const threadId of completedThreads) {
            if (threadId in eventsByThread) {
                result[threadId] = eventsByThread[threadId];
                delete eventsByThread[threadId];
            }
        }
        resolve(result);
    }, 1000);
}

function _clearEvents() {
    const threadIds = Object.keys(eventsByThread);
    for (const threadId of threadIds) {
        delete eventsByThread[threadId];
    }
}

function _followHere(config: any) {
    const threadId = Process.getCurrentThreadId();
    _followThread(config, threadId);
    return threadId;
}

function _followThread(config: any, threadId: any) {
    Stalker.follow(threadId, {
        events: _eventsFromConfig(config),
        onReceive: function (events) {
            const parsed = Stalker
                .parse(events, { annotate: false });
            // XXX api break .filter(_filterEvent);
            if (parsed.length === 0) {
                return;
            }
            if (threadId in eventsByThread) {
                eventsByThread[threadId].push(...parsed);
            } else {
                eventsByThread[threadId] = parsed;
            }
        },
    });
}

function _unfollowHere() {
    Stalker.unfollow();
}

function unfollowAll() {
    const threads = Process.enumerateThreads();
    for (const thread of threads) {
        Stalker.unfollow(thread.id);
    }
}

function _eventsFromConfig(config: any) {
    const events = {
        call: false,
        ret: false,
        exec: false,
        block: false,
        compile: false,
    };
    (events as any)[config.event] = true;
    return events;
}

function _filterEvent(event: any): any {
    if (inModules.length === 0) {
        return true;
    }
    const address = event[0];
    return inModules.some((range: NativePointer[]) => {
        const [start, end] = range;
        return address.compare(start) >= 0 && address.compare(end) <= 0;
    });
}

function _initModules(config: any) {
    inModules.splice(0, -1);
    switch (config.stalkin) {
        case "app": {
            const appModule = Process.mainModule;
            inModules.push([
                appModule.base,
                appModule.base.add(appModule.size),
            ]);
            return;
        }
        case "modules": {
            inModules.push(
                ...Process.enumerateModules().map((module) => {
                    return [module.base, module.base.add(module.size)];
                }),
            );
            break;
        }
        default:
            break;
    }
}

function stalkTraceEverything(args: string[]) {
    if (args.length === 0) {
        return "Warning: dts is experimental and slow\nUsage: dts [symbol]";
    }
    return _stalkTraceSomething(_stalkEverythingAndGetEvents, args);
}

function stalkTraceEverythingHelp() {
    return `Usage: dts[j*] [symbol|address] - Trace given symbol using the Frida Stalker
  dtsf[*j] [sym|addr]        Trace address or symbol using the stalker
  dts[*j] seconds            Trace all threads for given seconds using the stalker
  `;
}

function stalkTraceEverythingJson(args: string[]) {
    if (args.length === 0) {
        return "Warning: dts is experimental and slow\nUsage: dtsj [symbol]";
    }
    return _stalkTraceSomethingJson(_stalkEverythingAndGetEvents, args);
}

export function stalkTraceEverythingR2(args: string[]) {
    if (args.length === 0) {
        return "Warning: dts is experimental and slow\nUsage: dts* [symbol]";
    }
    return _stalkTraceSomethingR2(_stalkEverythingAndGetEvents, args);
}

export function stalkTraceFunction(args: string[]) {
    return _stalkTraceSomething(_stalkFunctionAndGetEvents, args);
}

export function stalkTraceFunctionJson(args: string[]) {
    return _stalkTraceSomethingJson(_stalkFunctionAndGetEvents, args);
}

export function stalkTraceFunctionR2(args: string[]) {
    return _stalkTraceSomethingR2(_stalkFunctionAndGetEvents, args);
}

function _stalkTraceSomething(getEvents: any, args: string[]) {
    return getEvents(args, (isBlock: any, events: any) => {
        let previousSymbolName: string | null = null;
        const result = [];
        const threads = Object.keys(events);
        for (const threadId of threads) {
            result.push(`; --- thread ${threadId} --- ;`);
            if (isBlock) {
                result.push(
                    ..._mapBlockEvents(
                        events[threadId],
                        (address: NativePointer) => {
                            const pd = disasmOne(address, previousSymbolName);
                            previousSymbolName = _getSymbolName(address);
                            return pd;
                        },
                        (begin: any, end: any) => {
                            previousSymbolName = null;
                            return "";
                        },
                    ),
                );
            } else {
                result.push(...events[threadId].map((event: any) => {
                    const address = event[0];
                    const target = event[1];
                    const pd = disasmOne(address, previousSymbolName, target);
                    previousSymbolName = _getSymbolName(address);
                    return pd;
                }));
            }
        }
        return result.join("\n") + "\n";
    });
    function disasmOne(
        address: NativePointer,
        previousSymbolName: any,
        target?: any,
    ) {
        let pd = disasm.disasm(address, 1, previousSymbolName);
        if (pd.endsWith("\n")) {
            pd = pd.slice(0, -1);
        }
        if (target !== undefined) {
            pd += ` ; ${target} ${_getSymbolName(target)}`;
        }
        return pd;
    }
}

function _stalkTraceSomethingR2(getEvents: any, args: any) {
    return getEvents(args, (isBlock: any, events: any) => {
        const result: string[] = [];
        const threads = Object.keys(events);
        for (const threadId of threads) {
            if (isBlock) {
                const blocks = _mapBlockEvents(
                    events[threadId],
                    (address: NativePointer) => {
                        return `dt+ ${address} 1`;
                    },
                );
                for (const block of blocks) {
                    result.push(block);
                }
            } else {
                result.push(...events[threadId].map((event: any) => {
                    const commands = [];
                    const location = event[0];
                    commands.push(`dt+ ${location} 1`);
                    const target = event[1];
                    if (target) {
                        commands.push(
                            `CC ${target} ${
                                _getSymbolName(target)
                            } @ ${location}`,
                        );
                    }
                    return commands.join("\n") + "\n";
                }));
            }
        }
        return result.join("\n") + "\n";
    });
}

function _stalkTraceSomethingJson(getEvents: any, args: string[]) {
    return getEvents(args, (isBlock: boolean, events: any) => {
        const result = {
            event: config.get("stalker.event"),
            threads: events,
        };
        return result;
    });
}

function _stalkFunctionAndGetEvents(args: string[], eventsHandler: any) {
    utils.requireFridaVersion(10, 3, 13);
    const at = utils.getPtr(args[0]);
    const conf = {
        event: config.get("stalker.event"),
        timeout: config.get("stalker.timeout"),
        stalkin: config.get("stalker.in"),
    };
    const isBlock = conf.event === "block" || conf.event === "compile";
    const operation = stalkFunction(conf, at)
        .then((events) => {
            return eventsHandler(isBlock, events);
        });
    breakpoints.breakpointContinue([]);
    return operation;
}

function _stalkEverythingAndGetEvents(args: string[], eventsHandler: any) {
    utils.requireFridaVersion(10, 3, 13);
    const timeout = (args.length > 0) ? +args[0] : 0;
    const conf = {
        event: config.get("stalker.event"),
        timeout: config.get("stalker.timeout"),
        stalkin: config.get("stalker.in"),
    };
    const isBlock = conf.event === "block" || conf.event === "compile";
    const operation = stalkEverything(conf, timeout)
        .then((events) => {
            return eventsHandler(isBlock, events);
        });
    breakpoints.breakpointContinue([]);
    return operation;
}

function _mapBlockEvents(events: any, onInstruction: any, onBlock?: any) {
    const result: any[] = [];
    events.forEach((range: NativePointer[]) => {
        const [begin, end] = range;
        if (typeof onBlock === "function") {
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

export function _getSymbolName(address: NativePointer) {
    const ds = DebugSymbol.fromAddress(address);
    return (ds.name === null || ds.name.indexOf("0x") === 0) ? "" : ds.name;
}

export default {
    stalkFunction,
    stalkEverything,
    stalkTraceEverything,
    stalkTraceEverythingHelp,
    stalkTraceEverythingJson,
    stalkTraceEverythingR2,
    stalkTraceFunction,
    stalkTraceFunctionJson,
    stalkTraceFunctionR2,
};

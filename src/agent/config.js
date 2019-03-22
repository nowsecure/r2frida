'use strict';

const config = {
  'patch.code': true,
  'search.in': 'perm:r--',
  'search.quiet': false,
  'stalker.event': 'compile',
  'stalker.timeout': 5 * 60,
  'stalker.in': 'raw',
  'hook.backtrace': true,
  'hook.verbose': true
};

const configHelp = {
  'search.in': configHelpSearchIn,
  'stalker.event': configHelpStalkerEvent,
  'stalker.timeout': configHelpStalkerTimeout,
  'stalker.in': configHelpStalkerIn,
  'hook.backtrace': configHelpHookBacktrace,
  'hook.verbose': configHelpHookVerbose
};

const configValidator = {
  'search.in': configValidateSearchIn,
  'stalker.event': configValidateStalkerEvent,
  'stalker.timeout': configValidateStalkerTimeout,
  'stalker.in': configValidateStalkerIn,
  'hook.backtrace': configValidateHookBacktrace,
  'hook.verbose': configValidateHookVerbose
};

function configHelpSearchIn () {
  return `Specify which memory ranges to search in, possible values:

    perm:---        filter by permissions (default: 'perm:r--')
    current         search the range containing current offset
    heap            search inside the heap allocated regions
    path:pattern    search ranges mapping paths containing 'pattern'
  `;
}

function configValidateSearchIn (val) {
  if (val === 'heap') {
    return true;
  }
  const valSplit = val.split(':');
  const [scope, param] = valSplit;

  if (param === undefined) {
    if (scope === 'current') {
      return valSplit.length === 1;
    }
    return false;
  }
  if (scope === 'perm') {
    const paramSplit = param.split('');
    if (paramSplit.length !== 3 || valSplit.length > 2) {
      return false;
    }
    const [r, w, x] = paramSplit;
    return (r === 'r' || r === '-') &&
      (w === 'w' || w === '-') &&
      (x === 'x' || x === '-');
  }
  return scope === 'path';
}

function configHelpStalkerEvent () {
  return `Specify the event to use when stalking, possible values:

    call            trace calls
    ret             trace returns
    exec            trace every instruction
    block           trace basic block execution (every time)
    compile         trace basic blocks once (this is the default)
  `;
}

function configValidateStalkerEvent (val) {
  return ['call', 'ret', 'exec', 'block', 'compile'].indexOf(val) !== -1;
}

function configHelpStalkerTimeout () {
  return `Time after which the stalker gives up (in seconds). Defaults to 5 minutes,
 set to 0 to disable.`;
}

function configValidateStalkerTimeout (val) {
  return val >= 0;
}

function configHelpHookVerbose () {
  return `Show trace messages to the console. They are also logged in \\dtl

    true | false    to enable or disable the option
  `;
}

function configHelpHookBacktrace () {
  return `Append the backtrace on each trace hook registered with \\dt commands

    true | false    to enable or disable the option
  `;
}

function configHelpStalkerIn () {
  return `Restrict stalker results based on where the event has originated:

    raw             stalk everywhere (the default)
    app             stalk only in the app module
    modules         stalk in app module and all linked libraries
  `;
}

function configValidateHookVerbose (val) {
  if (typeof (val) === 'boolean') {
    return true;
  }
  return ['true', 'false'].indexOf(val) !== -1;
}

function configValidateHookBacktrace (val) {
  return ['true', 'false'].indexOf(val) !== -1;
}

function configValidateStalkerIn (val) {
  return ['raw', 'app', 'modules'].indexOf(val) !== -1;
}

function isTrue (x) {
  return (x === true || x === 1 || x === 'true');
}
function asR2Script () {
  Object.keys(config)
    .map(k => 'e ' + k + '=' + config[k])
    .join('\n');
}
function set (k, v) {
  if (configValidator[k] !== undefined) {
    if (!configValidator[k](v)) {
      console.error(`Invalid value for ${k}`);
      return '';
    }
  }
  config[k] = v;
}

function helpFor (k) {
  if (configHelp[k] !== undefined) {
    return configHelp[k]();
  }
  console.error(`no help for ${k}`);
  return '';
}

module.exports = {
  values: config, // bad practice, dont expose
  set: set, // c(k, v) => config[k] = v,
  get: (k) => config[k],
  getBoolean: (k) => isTrue(config[k]),
  getString: (k) => (config[k]) ? '' + config[k] : '',
  asR2Script: asR2Script,
  helpFor: helpFor
};

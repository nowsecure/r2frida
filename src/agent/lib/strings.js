function isPrintable(ch) {
    return (ch >= 32 && ch <= 126);
}
function parseOptions(options) {
    const opts = {
        minLength: 15,
        maxLength: 128,
        filter: false,
        urls: false,
        base: 0
    };
    if (typeof options === 'object') {
        for (const key of Object.keys(options)) {
            opts[key] = options[key];
        }
    }
    return opts;
}
function parseStrings(data, options) {
    const opt = parseOptions(options);
    const strs = [];
    let str = '';
    let off = 0;
    let cur = 0;
    data.forEach(ch => {
        if (isPrintable(ch)) {
            if (str === '') {
                cur = off;
            }
            str += String.fromCharCode(ch);
        }
        else {
            if (str.length > opt.minLength && str.length < opt.maxLength) {
                let valid = true;
                if (opt.filter && !isValidString(str)) {
                    valid = false;
                }
                if (opt.urls && !isValidURL(str)) {
                    valid = false;
                }
                if (valid) {
                    strs.push({ base: opt.base.add(cur), text: str });
                }
            }
            str = '';
        }
        off++;
    });
    return strs;
}
function isValidString(s) {
    if (s.indexOf('://') !== -1) {
        return false;
    }
    if (+s) {
        return false;
    }
    const invalidChars = '<\\)?@)>{~}^()=/!-"*:]%\';` $';
    for (const ic of invalidChars) {
        if (s.indexOf(ic) !== -1) {
            return false;
        }
    }
    return true;
}
function isValidURL(s) {
    if (s.indexOf('://') === -1) {
        return false;
    }
    const invalidChars = '<\\)?)>{~}^()=!-"*]\'` $';
    for (const ic of invalidChars) {
        if (s.indexOf(ic) !== -1) {
            return false;
        }
    }
    return true;
}
export default parseStrings;

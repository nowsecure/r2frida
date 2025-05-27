function isPrintable(ch: number) {
    return (ch >= 32 && ch <= 126);
}

function parseOptions(options: any) {
    const opts: any = {
        minLength: 15,
        maxLength: 128,
        filter: false,
        base: new NativePointer(0),
        urls: false,
    };
    if (typeof options === "object") {
        for (const key of Object.keys(options)) {
            opts[key as keyof any] = options[key];
        }
    }
    return opts;
}
export default function parseStrings(data: any, options: any) {
    const opt = parseOptions(options);
    const strs: any[] = []; // {base, text}
    let str = "";
    let off = 0;
    let cur = 0;
    data.forEach((ch: number) => {
        if (isPrintable(ch)) {
            if (str === "") {
                cur = off;
            }
            str += String.fromCharCode(ch);
        } else {
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
            str = "";
        }
        off++;
    });
    return strs;
}

function isValidString(s: string) {
    if (s.indexOf("://") !== -1) {
        return false;
    }
    if (+s) {
        return false;
    }
    const invalidChars = "<\\)?@)>{~}^()=/!-\"*:]%';` $";
    for (const ic of invalidChars) {
        if (s.indexOf(ic) !== -1) {
            return false;
        }
    }
    return true;
}

function isValidURL(s: string) {
    if (s.indexOf("://") === -1) {
        return false;
    }
    const invalidChars = "<\\)?)>{~}^()=!-\"*]'` $";
    for (const ic of invalidChars) {
        if (s.indexOf(ic) !== -1) {
            return false;
        }
    }
    return true;
}

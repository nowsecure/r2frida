const lookup: string[] = [];
const revLookup: any[] = [];
const Arr = typeof Uint8Array !== "undefined" ? Uint8Array : Array;

const code = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

for (let i = 0, len = code.length; i < len; ++i) {
    lookup[i] = code[i];
    revLookup[code.charCodeAt(i)] = i;
}

// Support decoding URL-safe base64 strings, as Node.js does.
// See: https://en.wikipedia.org/wiki/Base64#URL_applications
revLookup["-".charCodeAt(0)] = 62;
revLookup["_".charCodeAt(0)] = 63;

type LengthPair = [number, number];

function getLens(b64: string): LengthPair {
    const len = b64.length;

    if (len % 4 > 0) {
        throw new Error("Invalid string. Length must be a multiple of 4");
    }

    // Trim off extra bytes after placeholder bytes are found
    // See: https://github.com/beatgammit/base64-js/issues/42
    let validLen = b64.indexOf("=");
    if (validLen === -1) validLen = len;

    const placeHoldersLen = validLen === len ? 0 : 4 - (validLen % 4);

    return [validLen, placeHoldersLen];
}

// base64 is 4/3 + up to two characters of the original data
function byteLength(b64: string): number {
    const lens = getLens(b64);
    const validLen = lens[0];
    const placeHoldersLen = lens[1];
    return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen;
}

function _byteLength(
    b64: string,
    validLen: number,
    placeHoldersLen: number,
): number {
    return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen;
}

export function toByteArray(b64: string) {
    const lens = getLens(b64);
    const validLen = lens[0];
    const placeHoldersLen = lens[1];

    const arr = new Arr(_byteLength(b64, validLen, placeHoldersLen));
    let curByte = 0;

    // if there are placeholders, only get up to the last complete 4 chars
    const len = placeHoldersLen > 0 ? validLen - 4 : validLen;

    let i;
    for (i = 0; i < len; i += 4) {
        const tmp = (revLookup[b64.charCodeAt(i)] << 18) |
            (revLookup[b64.charCodeAt(i + 1)] << 12) |
            (revLookup[b64.charCodeAt(i + 2)] << 6) |
            revLookup[b64.charCodeAt(i + 3)];
        arr[curByte++] = (tmp >> 16) & 0xFF;
        arr[curByte++] = (tmp >> 8) & 0xFF;
        arr[curByte++] = tmp & 0xFF;
    }

    if (placeHoldersLen === 2) {
        const tmp = (revLookup[b64.charCodeAt(i)] << 2) |
            (revLookup[b64.charCodeAt(i + 1)] >> 4);
        arr[curByte++] = tmp & 0xFF;
    }

    if (placeHoldersLen === 1) {
        const tmp = (revLookup[b64.charCodeAt(i)] << 10) |
            (revLookup[b64.charCodeAt(i + 1)] << 4) |
            (revLookup[b64.charCodeAt(i + 2)] >> 2);
        arr[curByte++] = (tmp >> 8) & 0xFF;
        arr[curByte++] = tmp & 0xFF;
    }
    return arr;
}

function tripletToBase64(num: number): string {
    return lookup[num >> 18 & 0x3F] +
        lookup[num >> 12 & 0x3F] +
        lookup[num >> 6 & 0x3F] +
        lookup[num & 0x3F];
}

function encodeChunk(uint8: any, start: number, end: number) {
    const output: string[] = [];
    for (let i = start; i < end; i += 3) {
        const tmp = ((uint8[i] << 16) & 0xFF0000) +
            ((uint8[i + 1] << 8) & 0xFF00) +
            (uint8[i + 2] & 0xFF);
        output.push(tripletToBase64(tmp));
    }
    return output.join("");
}

export function fromByteArray(uint8: any): string {
    const len = uint8.length;
    const extraBytes = len % 3; // if we have 1 byte left, pad 2 bytes
    const parts: string[] = [];
    const maxChunkLength = 16383; // must be multiple of 3

    // go through the array every three bytes, we'll deal with trailing stuff later
    for (let i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
        parts.push(
            encodeChunk(
                uint8,
                i,
                (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength),
            ),
        );
    }

    // pad the end with zeros, but make sure to not forget the extra bytes
    if (extraBytes === 1) {
        const tmp = uint8[len - 1];
        parts.push(
            lookup[tmp >> 2] +
                lookup[(tmp << 4) & 0x3F] +
                "==",
        );
    } else if (extraBytes === 2) {
        const tmp = (uint8[len - 2] << 8) + uint8[len - 1];
        parts.push(
            lookup[tmp >> 10] +
                lookup[(tmp >> 4) & 0x3F] +
                lookup[(tmp << 2) & 0x3F] +
                "=",
        );
    }

    return parts.join("");
}

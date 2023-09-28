exports.id = 232;
exports.ids = [232];
exports.modules = {

/***/ 82966:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.MAC_LENGTH = exports.IV_LENGTH = exports.KEY_LENGTH = exports.PREFIX_LENGTH = exports.RIPEMD160_NODE_ALGO = exports.SHA512_NODE_ALGO = exports.SHA256_NODE_ALGO = exports.HMAC_NODE_ALGO = exports.AES_NODE_ALGO = exports.SHA512_BROWSER_ALGO = exports.SHA256_BROWSER_ALGO = exports.HMAC_BROWSER = exports.HMAC_BROWSER_ALGO = exports.AES_BROWSER_ALGO = exports.HMAC_LENGTH = exports.AES_LENGTH = void 0;
const length_1 = __webpack_require__(58445);
exports.AES_LENGTH = length_1.LENGTH_256;
exports.HMAC_LENGTH = length_1.LENGTH_256;
exports.AES_BROWSER_ALGO = "AES-CBC";
exports.HMAC_BROWSER_ALGO = `SHA-${exports.AES_LENGTH}`;
exports.HMAC_BROWSER = "HMAC";
exports.SHA256_BROWSER_ALGO = "SHA-256";
exports.SHA512_BROWSER_ALGO = "SHA-512";
exports.AES_NODE_ALGO = `aes-${exports.AES_LENGTH}-cbc`;
exports.HMAC_NODE_ALGO = `sha${exports.HMAC_LENGTH}`;
exports.SHA256_NODE_ALGO = "sha256";
exports.SHA512_NODE_ALGO = "sha512";
exports.RIPEMD160_NODE_ALGO = "ripemd160";
exports.PREFIX_LENGTH = length_1.LENGTH_1;
exports.KEY_LENGTH = length_1.LENGTH_32;
exports.IV_LENGTH = length_1.LENGTH_16;
exports.MAC_LENGTH = length_1.LENGTH_32;
//# sourceMappingURL=default.js.map

/***/ }),

/***/ 26511:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UTF8_ENC = exports.HEX_ENC = void 0;
exports.HEX_ENC = "hex";
exports.UTF8_ENC = "utf8";
//# sourceMappingURL=encoding.js.map

/***/ }),

/***/ 52176:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ERROR_BAD_MAC = void 0;
exports.ERROR_BAD_MAC = "Bad MAC";
//# sourceMappingURL=error.js.map

/***/ }),

/***/ 62477:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __webpack_require__(97316);
tslib_1.__exportStar(__webpack_require__(82966), exports);
tslib_1.__exportStar(__webpack_require__(26511), exports);
tslib_1.__exportStar(__webpack_require__(52176), exports);
tslib_1.__exportStar(__webpack_require__(58445), exports);
tslib_1.__exportStar(__webpack_require__(82827), exports);
//# sourceMappingURL=index.js.map

/***/ }),

/***/ 58445:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.LENGTH_1024 = exports.LENGTH_512 = exports.LENGTH_256 = exports.LENGTH_128 = exports.LENGTH_64 = exports.LENGTH_32 = exports.LENGTH_16 = exports.LENGTH_1 = exports.LENGTH_0 = void 0;
exports.LENGTH_0 = 0;
exports.LENGTH_1 = 1;
exports.LENGTH_16 = 16;
exports.LENGTH_32 = 32;
exports.LENGTH_64 = 64;
exports.LENGTH_128 = 128;
exports.LENGTH_256 = 256;
exports.LENGTH_512 = 512;
exports.LENGTH_1024 = 1024;
//# sourceMappingURL=length.js.map

/***/ }),

/***/ 82827:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.VERIFY_OP = exports.SIGN_OP = exports.DECRYPT_OP = exports.ENCRYPT_OP = void 0;
exports.ENCRYPT_OP = "encrypt";
exports.DECRYPT_OP = "decrypt";
exports.SIGN_OP = "sign";
exports.VERIFY_OP = "verify";
//# sourceMappingURL=operations.js.map

/***/ }),

/***/ 85635:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __webpack_require__(97316);
tslib_1.__exportStar(__webpack_require__(93829), exports);
//# sourceMappingURL=env.js.map

/***/ }),

/***/ 60571:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __webpack_require__(97316);
tslib_1.__exportStar(__webpack_require__(85635), exports);
tslib_1.__exportStar(__webpack_require__(79211), exports);
tslib_1.__exportStar(__webpack_require__(26986), exports);
tslib_1.__exportStar(__webpack_require__(25165), exports);
//# sourceMappingURL=index.js.map

/***/ }),

/***/ 79211:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.pkcs7 = void 0;
const PADDING = [
    [16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16],
    [15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15],
    [14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14],
    [13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13],
    [12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12],
    [11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11],
    [10, 10, 10, 10, 10, 10, 10, 10, 10, 10],
    [9, 9, 9, 9, 9, 9, 9, 9, 9],
    [8, 8, 8, 8, 8, 8, 8, 8],
    [7, 7, 7, 7, 7, 7, 7],
    [6, 6, 6, 6, 6, 6],
    [5, 5, 5, 5, 5],
    [4, 4, 4, 4],
    [3, 3, 3],
    [2, 2],
    [1],
];
exports.pkcs7 = {
    pad(plaintext) {
        const padding = PADDING[plaintext.byteLength % 16 || 0];
        const result = new Uint8Array(plaintext.byteLength + padding.length);
        result.set(plaintext);
        result.set(padding, plaintext.byteLength);
        return result;
    },
    unpad(padded) {
        return padded.subarray(0, padded.byteLength - padded[padded.byteLength - 1]);
    },
};
//# sourceMappingURL=pkcs7.js.map

/***/ }),

/***/ 26986:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
//# sourceMappingURL=types.js.map

/***/ }),

/***/ 25165:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.isConstantTime = exports.assert = void 0;
function assert(condition, message) {
    if (!condition) {
        throw new Error(message || "Assertion failed");
    }
}
exports.assert = assert;
function isConstantTime(arr1, arr2) {
    if (arr1.length !== arr2.length) {
        return false;
    }
    let res = 0;
    for (let i = 0; i < arr1.length; i++) {
        res |= arr1[i] ^ arr2[i];
    }
    return res === 0;
}
exports.isConstantTime = isConstantTime;
//# sourceMappingURL=validators.js.map

/***/ }),

/***/ 74004:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.nodeRipemd160 = exports.nodeSha512 = exports.nodeSha256 = exports.nodeHmacSha512Sign = exports.nodeHmacSha256Sign = exports.nodeAesDecrypt = exports.nodeAesEncrypt = void 0;
const tslib_1 = __webpack_require__(97316);
const crypto_1 = tslib_1.__importDefault(__webpack_require__(6113));
const encoding_1 = __webpack_require__(2921);
const constants_1 = __webpack_require__(62477);
function nodeAesEncrypt(iv, key, data) {
    const cipher = crypto_1.default.createCipheriv(constants_1.AES_NODE_ALGO, Buffer.from(key), Buffer.from(iv));
    return encoding_1.bufferToArray(encoding_1.concatBuffers(cipher.update(Buffer.from(data)), cipher.final()));
}
exports.nodeAesEncrypt = nodeAesEncrypt;
function nodeAesDecrypt(iv, key, data) {
    const decipher = crypto_1.default.createDecipheriv(constants_1.AES_NODE_ALGO, Buffer.from(key), Buffer.from(iv));
    return encoding_1.bufferToArray(encoding_1.concatBuffers(decipher.update(Buffer.from(data)), decipher.final()));
}
exports.nodeAesDecrypt = nodeAesDecrypt;
function nodeHmacSha256Sign(key, data) {
    const buf = crypto_1.default
        .createHmac(constants_1.HMAC_NODE_ALGO, Buffer.from(key))
        .update(Buffer.from(data))
        .digest();
    return encoding_1.bufferToArray(buf);
}
exports.nodeHmacSha256Sign = nodeHmacSha256Sign;
function nodeHmacSha512Sign(key, data) {
    const buf = crypto_1.default
        .createHmac(constants_1.SHA512_NODE_ALGO, Buffer.from(key))
        .update(Buffer.from(data))
        .digest();
    return encoding_1.bufferToArray(buf);
}
exports.nodeHmacSha512Sign = nodeHmacSha512Sign;
function nodeSha256(data) {
    const buf = crypto_1.default
        .createHash(constants_1.SHA256_NODE_ALGO)
        .update(Buffer.from(data))
        .digest();
    return encoding_1.bufferToArray(buf);
}
exports.nodeSha256 = nodeSha256;
function nodeSha512(data) {
    const buf = crypto_1.default
        .createHash(constants_1.SHA512_NODE_ALGO)
        .update(Buffer.from(data))
        .digest();
    return encoding_1.bufferToArray(buf);
}
exports.nodeSha512 = nodeSha512;
function nodeRipemd160(data) {
    const buf = crypto_1.default
        .createHash(constants_1.RIPEMD160_NODE_ALGO)
        .update(Buffer.from(data))
        .digest();
    return encoding_1.bufferToArray(buf);
}
exports.nodeRipemd160 = nodeRipemd160;
//# sourceMappingURL=node.js.map

/***/ }),

/***/ 49423:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.aesCbcDecrypt = exports.aesCbcEncrypt = void 0;
const tslib_1 = __webpack_require__(97316);
const node_1 = __webpack_require__(74004);
function aesCbcEncrypt(iv, key, data) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const result = node_1.nodeAesEncrypt(iv, key, data);
        return result;
    });
}
exports.aesCbcEncrypt = aesCbcEncrypt;
function aesCbcDecrypt(iv, key, data) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const result = node_1.nodeAesDecrypt(iv, key, data);
        return result;
    });
}
exports.aesCbcDecrypt = aesCbcDecrypt;
//# sourceMappingURL=aes.js.map

/***/ }),

/***/ 85029:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.hmacSha512Verify = exports.hmacSha512Sign = exports.hmacSha256Verify = exports.hmacSha256Sign = void 0;
const tslib_1 = __webpack_require__(97316);
const helpers_1 = __webpack_require__(60571);
const node_1 = __webpack_require__(74004);
function hmacSha256Sign(key, msg) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const result = node_1.nodeHmacSha256Sign(key, msg);
        return result;
    });
}
exports.hmacSha256Sign = hmacSha256Sign;
function hmacSha256Verify(key, msg, sig) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const expectedSig = node_1.nodeHmacSha256Sign(key, msg);
        const result = helpers_1.isConstantTime(expectedSig, sig);
        return result;
    });
}
exports.hmacSha256Verify = hmacSha256Verify;
function hmacSha512Sign(key, msg) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const result = node_1.nodeHmacSha512Sign(key, msg);
        return result;
    });
}
exports.hmacSha512Sign = hmacSha512Sign;
function hmacSha512Verify(key, msg, sig) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const expectedSig = node_1.nodeHmacSha512Sign(key, msg);
        const result = helpers_1.isConstantTime(expectedSig, sig);
        return result;
    });
}
exports.hmacSha512Verify = hmacSha512Verify;
//# sourceMappingURL=hmac.js.map

/***/ }),

/***/ 41210:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __webpack_require__(97316);
tslib_1.__exportStar(__webpack_require__(10651), exports);
tslib_1.__exportStar(__webpack_require__(49423), exports);
tslib_1.__exportStar(__webpack_require__(85029), exports);
tslib_1.__exportStar(__webpack_require__(45955), exports);
tslib_1.__exportStar(__webpack_require__(60571), exports);
tslib_1.__exportStar(__webpack_require__(62477), exports);
//# sourceMappingURL=index.js.map

/***/ }),

/***/ 45955:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ripemd160 = exports.sha512 = exports.sha256 = void 0;
const tslib_1 = __webpack_require__(97316);
const node_1 = __webpack_require__(74004);
function sha256(msg) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const result = node_1.nodeSha256(msg);
        return result;
    });
}
exports.sha256 = sha256;
function sha512(msg) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const result = node_1.nodeSha512(msg);
        return result;
    });
}
exports.sha512 = sha512;
function ripemd160(msg) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const result = node_1.nodeRipemd160(msg);
        return result;
    });
}
exports.ripemd160 = ripemd160;
//# sourceMappingURL=sha2.js.map

/***/ }),

/***/ 2921:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.removeHexLeadingZeros = exports.sanitizeHex = exports.addHexPrefix = exports.removeHexPrefix = exports.padRight = exports.padLeft = exports.sanitizeBytes = exports.swapHex = exports.swapBytes = exports.splitBytes = exports.calcByteLength = exports.trimRight = exports.trimLeft = exports.concatArrays = exports.concatBuffers = exports.getEncoding = exports.getType = exports.isArrayBuffer = exports.isTypedArray = exports.isBuffer = exports.isHexString = exports.isBinaryString = exports.binaryToNumber = exports.binaryToUtf8 = exports.binaryToHex = exports.binaryToArray = exports.binaryToBuffer = exports.numberToBinary = exports.numberToUtf8 = exports.numberToHex = exports.numberToArray = exports.numberToBuffer = exports.utf8ToBinary = exports.utf8ToNumber = exports.utf8ToHex = exports.utf8ToArray = exports.utf8ToBuffer = exports.hexToBinary = exports.hexToNumber = exports.hexToUtf8 = exports.hexToArray = exports.hexToBuffer = exports.arrayToBinary = exports.arrayToNumber = exports.arrayToUtf8 = exports.arrayToHex = exports.arrayToBuffer = exports.bufferToBinary = exports.bufferToNumber = exports.bufferToUtf8 = exports.bufferToHex = exports.bufferToArray = void 0;
const tslib_1 = __webpack_require__(97316);
const is_typedarray_1 = tslib_1.__importDefault(__webpack_require__(38943));
const typedarray_to_buffer_1 = tslib_1.__importDefault(__webpack_require__(56144));
const ENC_HEX = "hex";
const ENC_UTF8 = "utf8";
const ENC_BIN = "binary";
const TYPE_BUFFER = "buffer";
const TYPE_ARRAY = "array";
const TYPE_TYPED_ARRAY = "typed-array";
const TYPE_ARRAY_BUFFER = "array-buffer";
const STRING_ZERO = "0";
function bufferToArray(buf) {
    return new Uint8Array(buf);
}
exports.bufferToArray = bufferToArray;
function bufferToHex(buf, prefixed = false) {
    const hex = buf.toString(ENC_HEX);
    return prefixed ? addHexPrefix(hex) : hex;
}
exports.bufferToHex = bufferToHex;
function bufferToUtf8(buf) {
    return buf.toString(ENC_UTF8);
}
exports.bufferToUtf8 = bufferToUtf8;
function bufferToNumber(buf) {
    return buf.readUIntBE(0, buf.length);
}
exports.bufferToNumber = bufferToNumber;
function bufferToBinary(buf) {
    return arrayToBinary(bufferToArray(buf));
}
exports.bufferToBinary = bufferToBinary;
function arrayToBuffer(arr) {
    return typedarray_to_buffer_1.default(arr);
}
exports.arrayToBuffer = arrayToBuffer;
function arrayToHex(arr, prefixed = false) {
    return bufferToHex(arrayToBuffer(arr), prefixed);
}
exports.arrayToHex = arrayToHex;
function arrayToUtf8(arr) {
    return bufferToUtf8(arrayToBuffer(arr));
}
exports.arrayToUtf8 = arrayToUtf8;
function arrayToNumber(arr) {
    return bufferToNumber(arrayToBuffer(arr));
}
exports.arrayToNumber = arrayToNumber;
function arrayToBinary(arr) {
    return Array.from(arr)
        .map(numberToBinary)
        .join("");
}
exports.arrayToBinary = arrayToBinary;
function hexToBuffer(hex) {
    return Buffer.from(removeHexPrefix(hex), ENC_HEX);
}
exports.hexToBuffer = hexToBuffer;
function hexToArray(hex) {
    return bufferToArray(hexToBuffer(hex));
}
exports.hexToArray = hexToArray;
function hexToUtf8(hex) {
    return bufferToUtf8(hexToBuffer(hex));
}
exports.hexToUtf8 = hexToUtf8;
function hexToNumber(hex) {
    return arrayToNumber(hexToArray(hex));
}
exports.hexToNumber = hexToNumber;
function hexToBinary(hex) {
    return arrayToBinary(hexToArray(hex));
}
exports.hexToBinary = hexToBinary;
function utf8ToBuffer(utf8) {
    return Buffer.from(utf8, ENC_UTF8);
}
exports.utf8ToBuffer = utf8ToBuffer;
function utf8ToArray(utf8) {
    return bufferToArray(utf8ToBuffer(utf8));
}
exports.utf8ToArray = utf8ToArray;
function utf8ToHex(utf8, prefixed = false) {
    return bufferToHex(utf8ToBuffer(utf8), prefixed);
}
exports.utf8ToHex = utf8ToHex;
function utf8ToNumber(utf8) {
    const num = parseInt(utf8, 10);
    assert(isDefined(num), "Number can only safely store up to 53 bits");
    return num;
}
exports.utf8ToNumber = utf8ToNumber;
function utf8ToBinary(utf8) {
    return arrayToBinary(utf8ToArray(utf8));
}
exports.utf8ToBinary = utf8ToBinary;
function numberToBuffer(num) {
    return binaryToBuffer(numberToBinary(num));
}
exports.numberToBuffer = numberToBuffer;
function numberToArray(num) {
    return binaryToArray(numberToBinary(num));
}
exports.numberToArray = numberToArray;
function numberToHex(num, prefixed) {
    return binaryToHex(numberToBinary(num), prefixed);
}
exports.numberToHex = numberToHex;
function numberToUtf8(num) {
    return `${num}`;
}
exports.numberToUtf8 = numberToUtf8;
function numberToBinary(num) {
    const bin = (num >>> 0).toString(2);
    return sanitizeBytes(bin);
}
exports.numberToBinary = numberToBinary;
function binaryToBuffer(bin) {
    return arrayToBuffer(binaryToArray(bin));
}
exports.binaryToBuffer = binaryToBuffer;
function binaryToArray(bin) {
    return new Uint8Array(splitBytes(bin).map(x => parseInt(x, 2)));
}
exports.binaryToArray = binaryToArray;
function binaryToHex(bin, prefixed) {
    return arrayToHex(binaryToArray(bin), prefixed);
}
exports.binaryToHex = binaryToHex;
function binaryToUtf8(bin) {
    return arrayToUtf8(binaryToArray(bin));
}
exports.binaryToUtf8 = binaryToUtf8;
function binaryToNumber(bin) {
    return arrayToNumber(binaryToArray(bin));
}
exports.binaryToNumber = binaryToNumber;
function isBinaryString(str) {
    if (typeof str !== "string" || !new RegExp(/^[01]+$/).test(str)) {
        return false;
    }
    if (str.length % 8 !== 0) {
        return false;
    }
    return true;
}
exports.isBinaryString = isBinaryString;
function isHexString(str, length) {
    if (typeof str !== "string" || !str.match(/^0x[0-9A-Fa-f]*$/)) {
        return false;
    }
    if (length && str.length !== 2 + 2 * length) {
        return false;
    }
    return true;
}
exports.isHexString = isHexString;
function isBuffer(val) {
    return Buffer.isBuffer(val);
}
exports.isBuffer = isBuffer;
function isTypedArray(val) {
    return is_typedarray_1.default.strict(val) && !isBuffer(val);
}
exports.isTypedArray = isTypedArray;
function isArrayBuffer(val) {
    return (!isTypedArray(val) &&
        !isBuffer(val) &&
        typeof val.byteLength !== "undefined");
}
exports.isArrayBuffer = isArrayBuffer;
function getType(val) {
    if (isBuffer(val)) {
        return TYPE_BUFFER;
    }
    else if (isTypedArray(val)) {
        return TYPE_TYPED_ARRAY;
    }
    else if (isArrayBuffer(val)) {
        return TYPE_ARRAY_BUFFER;
    }
    else if (Array.isArray(val)) {
        return TYPE_ARRAY;
    }
    else {
        return typeof val;
    }
}
exports.getType = getType;
function getEncoding(str) {
    if (isBinaryString(str)) {
        return ENC_BIN;
    }
    if (isHexString(str)) {
        return ENC_HEX;
    }
    return ENC_UTF8;
}
exports.getEncoding = getEncoding;
function concatBuffers(...args) {
    const result = Buffer.concat(args);
    return result;
}
exports.concatBuffers = concatBuffers;
function concatArrays(...args) {
    let result = [];
    args.forEach(arg => (result = result.concat(Array.from(arg))));
    return new Uint8Array([...result]);
}
exports.concatArrays = concatArrays;
function trimLeft(data, length) {
    const diff = data.length - length;
    if (diff > 0) {
        data = data.slice(diff);
    }
    return data;
}
exports.trimLeft = trimLeft;
function trimRight(data, length) {
    return data.slice(0, length);
}
exports.trimRight = trimRight;
function calcByteLength(length, byteSize = 8) {
    const remainder = length % byteSize;
    return remainder
        ? ((length - remainder) / byteSize) * byteSize + byteSize
        : length;
}
exports.calcByteLength = calcByteLength;
function splitBytes(str, byteSize = 8) {
    const bytes = sanitizeBytes(str).match(new RegExp(`.{${byteSize}}`, "gi"));
    return Array.from(bytes || []);
}
exports.splitBytes = splitBytes;
function swapBytes(str) {
    return splitBytes(str)
        .map(reverseString)
        .join("");
}
exports.swapBytes = swapBytes;
function swapHex(str) {
    return binaryToHex(swapBytes(hexToBinary(str)));
}
exports.swapHex = swapHex;
function sanitizeBytes(str, byteSize = 8, padding = STRING_ZERO) {
    return padLeft(str, calcByteLength(str.length, byteSize), padding);
}
exports.sanitizeBytes = sanitizeBytes;
function padLeft(str, length, padding = STRING_ZERO) {
    return padString(str, length, true, padding);
}
exports.padLeft = padLeft;
function padRight(str, length, padding = STRING_ZERO) {
    return padString(str, length, false, padding);
}
exports.padRight = padRight;
function removeHexPrefix(hex) {
    return hex.replace(/^0x/, "");
}
exports.removeHexPrefix = removeHexPrefix;
function addHexPrefix(hex) {
    return hex.startsWith("0x") ? hex : `0x${hex}`;
}
exports.addHexPrefix = addHexPrefix;
function sanitizeHex(hex) {
    hex = removeHexPrefix(hex);
    hex = sanitizeBytes(hex, 2);
    if (hex) {
        hex = addHexPrefix(hex);
    }
    return hex;
}
exports.sanitizeHex = sanitizeHex;
function removeHexLeadingZeros(hex) {
    const prefixed = hex.startsWith("0x");
    hex = removeHexPrefix(hex);
    hex = hex.startsWith(STRING_ZERO) ? hex.substring(1) : hex;
    return prefixed ? addHexPrefix(hex) : hex;
}
exports.removeHexLeadingZeros = removeHexLeadingZeros;
function isUndefined(value) {
    return typeof value === "undefined";
}
function isDefined(value) {
    return !isUndefined(value);
}
function assert(assertion, errorMessage) {
    if (!assertion) {
        throw new Error(errorMessage);
    }
}
function reverseString(str) {
    return str
        .split("")
        .reverse()
        .join("");
}
function padString(str, length, left, padding = STRING_ZERO) {
    const diff = length - str.length;
    let result = str;
    if (diff > 0) {
        const pad = padding.repeat(diff);
        result = left ? pad + str : str + pad;
    }
    return result;
}
//# sourceMappingURL=index.js.map

/***/ }),

/***/ 98491:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __webpack_require__(97316);
const legacy_types_1 = __webpack_require__(97117);
const legacy_utils_1 = __webpack_require__(10603);
const socket_1 = tslib_1.__importDefault(__webpack_require__(55218));
const events_1 = tslib_1.__importDefault(__webpack_require__(85350));
const storage_1 = tslib_1.__importDefault(__webpack_require__(14710));
const url_1 = __webpack_require__(13662);
class Connector {
    constructor(opts) {
        this.protocol = "wc";
        this.version = 1;
        this._bridge = "";
        this._key = null;
        this._clientId = "";
        this._clientMeta = null;
        this._peerId = "";
        this._peerMeta = null;
        this._handshakeId = 0;
        this._handshakeTopic = "";
        this._connected = false;
        this._accounts = [];
        this._chainId = 0;
        this._networkId = 0;
        this._rpcUrl = "";
        this._eventManager = new events_1.default();
        this._clientMeta = legacy_utils_1.getClientMeta() || opts.connectorOpts.clientMeta || null;
        this._cryptoLib = opts.cryptoLib;
        this._sessionStorage = opts.sessionStorage || new storage_1.default(opts.connectorOpts.storageId);
        this._qrcodeModal = opts.connectorOpts.qrcodeModal;
        this._qrcodeModalOptions = opts.connectorOpts.qrcodeModalOptions;
        this._signingMethods = [...legacy_types_1.SIGNING_METHODS, ...(opts.connectorOpts.signingMethods || [])];
        if (!opts.connectorOpts.bridge && !opts.connectorOpts.uri && !opts.connectorOpts.session) {
            throw new Error(legacy_types_1.ERROR_MISSING_REQUIRED);
        }
        if (opts.connectorOpts.bridge) {
            this.bridge = url_1.getBridgeUrl(opts.connectorOpts.bridge);
        }
        if (opts.connectorOpts.uri) {
            this.uri = opts.connectorOpts.uri;
        }
        const session = opts.connectorOpts.session || this._getStorageSession();
        if (session) {
            this.session = session;
        }
        if (this.handshakeId) {
            this._subscribeToSessionResponse(this.handshakeId, "Session request rejected");
        }
        this._transport =
            opts.transport ||
                new socket_1.default({
                    protocol: this.protocol,
                    version: this.version,
                    url: this.bridge,
                    subscriptions: [this.clientId],
                });
        this._subscribeToInternalEvents();
        this._initTransport();
        if (opts.connectorOpts.uri) {
            this._subscribeToSessionRequest();
        }
        if (opts.pushServerOpts) {
            this._registerPushServer(opts.pushServerOpts);
        }
    }
    set bridge(value) {
        if (!value) {
            return;
        }
        this._bridge = value;
    }
    get bridge() {
        return this._bridge;
    }
    set key(value) {
        if (!value) {
            return;
        }
        const key = legacy_utils_1.convertHexToArrayBuffer(value);
        this._key = key;
    }
    get key() {
        if (this._key) {
            const key = legacy_utils_1.convertArrayBufferToHex(this._key, true);
            return key;
        }
        return "";
    }
    set clientId(value) {
        if (!value) {
            return;
        }
        this._clientId = value;
    }
    get clientId() {
        let clientId = this._clientId;
        if (!clientId) {
            clientId = this._clientId = legacy_utils_1.uuid();
        }
        return this._clientId;
    }
    set peerId(value) {
        if (!value) {
            return;
        }
        this._peerId = value;
    }
    get peerId() {
        return this._peerId;
    }
    set clientMeta(value) {
    }
    get clientMeta() {
        let clientMeta = this._clientMeta;
        if (!clientMeta) {
            clientMeta = this._clientMeta = legacy_utils_1.getClientMeta();
        }
        return clientMeta;
    }
    set peerMeta(value) {
        this._peerMeta = value;
    }
    get peerMeta() {
        const peerMeta = this._peerMeta;
        return peerMeta;
    }
    set handshakeTopic(value) {
        if (!value) {
            return;
        }
        this._handshakeTopic = value;
    }
    get handshakeTopic() {
        return this._handshakeTopic;
    }
    set handshakeId(value) {
        if (!value) {
            return;
        }
        this._handshakeId = value;
    }
    get handshakeId() {
        return this._handshakeId;
    }
    get uri() {
        const _uri = this._formatUri();
        return _uri;
    }
    set uri(value) {
        if (!value) {
            return;
        }
        const { handshakeTopic, bridge, key } = this._parseUri(value);
        this.handshakeTopic = handshakeTopic;
        this.bridge = bridge;
        this.key = key;
    }
    set chainId(value) {
        this._chainId = value;
    }
    get chainId() {
        const chainId = this._chainId;
        return chainId;
    }
    set networkId(value) {
        this._networkId = value;
    }
    get networkId() {
        const networkId = this._networkId;
        return networkId;
    }
    set accounts(value) {
        this._accounts = value;
    }
    get accounts() {
        const accounts = this._accounts;
        return accounts;
    }
    set rpcUrl(value) {
        this._rpcUrl = value;
    }
    get rpcUrl() {
        const rpcUrl = this._rpcUrl;
        return rpcUrl;
    }
    set connected(value) {
    }
    get connected() {
        return this._connected;
    }
    set pending(value) {
    }
    get pending() {
        return !!this._handshakeTopic;
    }
    get session() {
        return {
            connected: this.connected,
            accounts: this.accounts,
            chainId: this.chainId,
            bridge: this.bridge,
            key: this.key,
            clientId: this.clientId,
            clientMeta: this.clientMeta,
            peerId: this.peerId,
            peerMeta: this.peerMeta,
            handshakeId: this.handshakeId,
            handshakeTopic: this.handshakeTopic,
        };
    }
    set session(value) {
        if (!value) {
            return;
        }
        this._connected = value.connected;
        this.accounts = value.accounts;
        this.chainId = value.chainId;
        this.bridge = value.bridge;
        this.key = value.key;
        this.clientId = value.clientId;
        this.clientMeta = value.clientMeta;
        this.peerId = value.peerId;
        this.peerMeta = value.peerMeta;
        this.handshakeId = value.handshakeId;
        this.handshakeTopic = value.handshakeTopic;
    }
    on(event, callback) {
        const eventEmitter = {
            event,
            callback,
        };
        this._eventManager.subscribe(eventEmitter);
    }
    off(event) {
        this._eventManager.unsubscribe(event);
    }
    createInstantRequest(instantRequest) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            this._key = yield this._generateKey();
            const request = this._formatRequest({
                method: "wc_instantRequest",
                params: [
                    {
                        peerId: this.clientId,
                        peerMeta: this.clientMeta,
                        request: this._formatRequest(instantRequest),
                    },
                ],
            });
            this.handshakeId = request.id;
            this.handshakeTopic = legacy_utils_1.uuid();
            this._eventManager.trigger({
                event: "display_uri",
                params: [this.uri],
            });
            this.on("modal_closed", () => {
                throw new Error(legacy_types_1.ERROR_QRCODE_MODAL_USER_CLOSED);
            });
            const endInstantRequest = () => {
                this.killSession();
            };
            try {
                const result = yield this._sendCallRequest(request);
                if (result) {
                    endInstantRequest();
                }
                return result;
            }
            catch (error) {
                endInstantRequest();
                throw error;
            }
        });
    }
    connect(opts) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (!this._qrcodeModal) {
                throw new Error(legacy_types_1.ERROR_QRCODE_MODAL_NOT_PROVIDED);
            }
            if (this.connected) {
                return {
                    chainId: this.chainId,
                    accounts: this.accounts,
                };
            }
            yield this.createSession(opts);
            return new Promise((resolve, reject) => tslib_1.__awaiter(this, void 0, void 0, function* () {
                this.on("modal_closed", () => reject(new Error(legacy_types_1.ERROR_QRCODE_MODAL_USER_CLOSED)));
                this.on("connect", (error, payload) => {
                    if (error) {
                        return reject(error);
                    }
                    resolve(payload.params[0]);
                });
            }));
        });
    }
    createSession(opts) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (this._connected) {
                throw new Error(legacy_types_1.ERROR_SESSION_CONNECTED);
            }
            if (this.pending) {
                return;
            }
            this._key = yield this._generateKey();
            const request = this._formatRequest({
                method: "wc_sessionRequest",
                params: [
                    {
                        peerId: this.clientId,
                        peerMeta: this.clientMeta,
                        chainId: opts && opts.chainId ? opts.chainId : null,
                    },
                ],
            });
            this.handshakeId = request.id;
            this.handshakeTopic = legacy_utils_1.uuid();
            this._sendSessionRequest(request, "Session update rejected", {
                topic: this.handshakeTopic,
            });
            this._eventManager.trigger({
                event: "display_uri",
                params: [this.uri],
            });
        });
    }
    approveSession(sessionStatus) {
        if (this._connected) {
            throw new Error(legacy_types_1.ERROR_SESSION_CONNECTED);
        }
        this.chainId = sessionStatus.chainId;
        this.accounts = sessionStatus.accounts;
        this.networkId = sessionStatus.networkId || 0;
        this.rpcUrl = sessionStatus.rpcUrl || "";
        const sessionParams = {
            approved: true,
            chainId: this.chainId,
            networkId: this.networkId,
            accounts: this.accounts,
            rpcUrl: this.rpcUrl,
            peerId: this.clientId,
            peerMeta: this.clientMeta,
        };
        const response = {
            id: this.handshakeId,
            jsonrpc: "2.0",
            result: sessionParams,
        };
        this._sendResponse(response);
        this._connected = true;
        this._setStorageSession();
        this._eventManager.trigger({
            event: "connect",
            params: [
                {
                    peerId: this.peerId,
                    peerMeta: this.peerMeta,
                    chainId: this.chainId,
                    accounts: this.accounts,
                },
            ],
        });
    }
    rejectSession(sessionError) {
        if (this._connected) {
            throw new Error(legacy_types_1.ERROR_SESSION_CONNECTED);
        }
        const message = sessionError && sessionError.message ? sessionError.message : legacy_types_1.ERROR_SESSION_REJECTED;
        const response = this._formatResponse({
            id: this.handshakeId,
            error: { message },
        });
        this._sendResponse(response);
        this._connected = false;
        this._eventManager.trigger({
            event: "disconnect",
            params: [{ message }],
        });
        this._removeStorageSession();
    }
    updateSession(sessionStatus) {
        if (!this._connected) {
            throw new Error(legacy_types_1.ERROR_SESSION_DISCONNECTED);
        }
        this.chainId = sessionStatus.chainId;
        this.accounts = sessionStatus.accounts;
        this.networkId = sessionStatus.networkId || 0;
        this.rpcUrl = sessionStatus.rpcUrl || "";
        const sessionParams = {
            approved: true,
            chainId: this.chainId,
            networkId: this.networkId,
            accounts: this.accounts,
            rpcUrl: this.rpcUrl,
        };
        const request = this._formatRequest({
            method: "wc_sessionUpdate",
            params: [sessionParams],
        });
        this._sendSessionRequest(request, "Session update rejected");
        this._eventManager.trigger({
            event: "session_update",
            params: [
                {
                    chainId: this.chainId,
                    accounts: this.accounts,
                },
            ],
        });
        this._manageStorageSession();
    }
    killSession(sessionError) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const message = sessionError ? sessionError.message : "Session Disconnected";
            const sessionParams = {
                approved: false,
                chainId: null,
                networkId: null,
                accounts: null,
            };
            const request = this._formatRequest({
                method: "wc_sessionUpdate",
                params: [sessionParams],
            });
            yield this._sendRequest(request);
            this._handleSessionDisconnect(message);
        });
    }
    sendTransaction(tx) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (!this._connected) {
                throw new Error(legacy_types_1.ERROR_SESSION_DISCONNECTED);
            }
            const parsedTx = tx;
            const request = this._formatRequest({
                method: "eth_sendTransaction",
                params: [parsedTx],
            });
            const result = yield this._sendCallRequest(request);
            return result;
        });
    }
    signTransaction(tx) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (!this._connected) {
                throw new Error(legacy_types_1.ERROR_SESSION_DISCONNECTED);
            }
            const parsedTx = tx;
            const request = this._formatRequest({
                method: "eth_signTransaction",
                params: [parsedTx],
            });
            const result = yield this._sendCallRequest(request);
            return result;
        });
    }
    signMessage(params) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (!this._connected) {
                throw new Error(legacy_types_1.ERROR_SESSION_DISCONNECTED);
            }
            const request = this._formatRequest({
                method: "eth_sign",
                params,
            });
            const result = yield this._sendCallRequest(request);
            return result;
        });
    }
    signPersonalMessage(params) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (!this._connected) {
                throw new Error(legacy_types_1.ERROR_SESSION_DISCONNECTED);
            }
            const request = this._formatRequest({
                method: "personal_sign",
                params,
            });
            const result = yield this._sendCallRequest(request);
            return result;
        });
    }
    signTypedData(params) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (!this._connected) {
                throw new Error(legacy_types_1.ERROR_SESSION_DISCONNECTED);
            }
            const request = this._formatRequest({
                method: "eth_signTypedData",
                params,
            });
            const result = yield this._sendCallRequest(request);
            return result;
        });
    }
    updateChain(chainParams) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (!this._connected) {
                throw new Error("Session currently disconnected");
            }
            const request = this._formatRequest({
                method: "wallet_updateChain",
                params: [chainParams],
            });
            const result = yield this._sendCallRequest(request);
            return result;
        });
    }
    unsafeSend(request, options) {
        this._sendRequest(request, options);
        this._eventManager.trigger({
            event: "call_request_sent",
            params: [{ request, options }],
        });
        return new Promise((resolve, reject) => {
            this._subscribeToResponse(request.id, (error, payload) => {
                if (error) {
                    reject(error);
                    return;
                }
                if (!payload) {
                    throw new Error(legacy_types_1.ERROR_MISSING_JSON_RPC);
                }
                resolve(payload);
            });
        });
    }
    sendCustomRequest(request, options) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (!this._connected) {
                throw new Error(legacy_types_1.ERROR_SESSION_DISCONNECTED);
            }
            switch (request.method) {
                case "eth_accounts":
                    return this.accounts;
                case "eth_chainId":
                    return legacy_utils_1.convertNumberToHex(this.chainId);
                case "eth_sendTransaction":
                case "eth_signTransaction":
                    if (request.params) {
                    }
                    break;
                case "personal_sign":
                    if (request.params) {
                    }
                    break;
                default:
                    break;
            }
            const formattedRequest = this._formatRequest(request);
            const result = yield this._sendCallRequest(formattedRequest, options);
            return result;
        });
    }
    approveRequest(response) {
        if (legacy_utils_1.isJsonRpcResponseSuccess(response)) {
            const formattedResponse = this._formatResponse(response);
            this._sendResponse(formattedResponse);
        }
        else {
            throw new Error(legacy_types_1.ERROR_MISSING_RESULT);
        }
    }
    rejectRequest(response) {
        if (legacy_utils_1.isJsonRpcResponseError(response)) {
            const formattedResponse = this._formatResponse(response);
            this._sendResponse(formattedResponse);
        }
        else {
            throw new Error(legacy_types_1.ERROR_MISSING_ERROR);
        }
    }
    transportClose() {
        this._transport.close();
    }
    _sendRequest(request, options) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const callRequest = this._formatRequest(request);
            const encryptionPayload = yield this._encrypt(callRequest);
            const topic = typeof (options === null || options === void 0 ? void 0 : options.topic) !== "undefined" ? options.topic : this.peerId;
            const payload = JSON.stringify(encryptionPayload);
            const silent = typeof (options === null || options === void 0 ? void 0 : options.forcePushNotification) !== "undefined"
                ? !options.forcePushNotification
                : legacy_utils_1.isSilentPayload(callRequest);
            this._transport.send(payload, topic, silent);
        });
    }
    _sendResponse(response) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const encryptionPayload = yield this._encrypt(response);
            const topic = this.peerId;
            const payload = JSON.stringify(encryptionPayload);
            const silent = true;
            this._transport.send(payload, topic, silent);
        });
    }
    _sendSessionRequest(request, errorMsg, options) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            this._sendRequest(request, options);
            this._subscribeToSessionResponse(request.id, errorMsg);
        });
    }
    _sendCallRequest(request, options) {
        this._sendRequest(request, options);
        this._eventManager.trigger({
            event: "call_request_sent",
            params: [{ request, options }],
        });
        return this._subscribeToCallResponse(request.id);
    }
    _formatRequest(request) {
        if (typeof request.method === "undefined") {
            throw new Error(legacy_types_1.ERROR_MISSING_METHOD);
        }
        const formattedRequest = {
            id: typeof request.id === "undefined" ? legacy_utils_1.payloadId() : request.id,
            jsonrpc: "2.0",
            method: request.method,
            params: typeof request.params === "undefined" ? [] : request.params,
        };
        return formattedRequest;
    }
    _formatResponse(response) {
        if (typeof response.id === "undefined") {
            throw new Error(legacy_types_1.ERROR_MISSING_ID);
        }
        const baseResponse = { id: response.id, jsonrpc: "2.0" };
        if (legacy_utils_1.isJsonRpcResponseError(response)) {
            const error = legacy_utils_1.formatRpcError(response.error);
            const errorResponse = Object.assign(Object.assign(Object.assign({}, baseResponse), response), { error });
            return errorResponse;
        }
        else if (legacy_utils_1.isJsonRpcResponseSuccess(response)) {
            const successResponse = Object.assign(Object.assign({}, baseResponse), response);
            return successResponse;
        }
        throw new Error(legacy_types_1.ERROR_INVALID_RESPONSE);
    }
    _handleSessionDisconnect(errorMsg) {
        const message = errorMsg || "Session Disconnected";
        if (!this._connected) {
            if (this._qrcodeModal) {
                this._qrcodeModal.close();
            }
            legacy_utils_1.removeLocal(legacy_types_1.MOBILE_LINK_CHOICE_KEY);
        }
        if (this._connected) {
            this._connected = false;
        }
        if (this._handshakeId) {
            this._handshakeId = 0;
        }
        if (this._handshakeTopic) {
            this._handshakeTopic = "";
        }
        if (this._peerId) {
            this._peerId = "";
        }
        this._eventManager.trigger({
            event: "disconnect",
            params: [{ message }],
        });
        this._removeStorageSession();
        this.transportClose();
    }
    _handleSessionResponse(errorMsg, sessionParams) {
        if (sessionParams) {
            if (sessionParams.approved) {
                if (!this._connected) {
                    this._connected = true;
                    if (sessionParams.chainId) {
                        this.chainId = sessionParams.chainId;
                    }
                    if (sessionParams.accounts) {
                        this.accounts = sessionParams.accounts;
                    }
                    if (sessionParams.peerId && !this.peerId) {
                        this.peerId = sessionParams.peerId;
                    }
                    if (sessionParams.peerMeta && !this.peerMeta) {
                        this.peerMeta = sessionParams.peerMeta;
                    }
                    this._eventManager.trigger({
                        event: "connect",
                        params: [
                            {
                                peerId: this.peerId,
                                peerMeta: this.peerMeta,
                                chainId: this.chainId,
                                accounts: this.accounts,
                            },
                        ],
                    });
                }
                else {
                    if (sessionParams.chainId) {
                        this.chainId = sessionParams.chainId;
                    }
                    if (sessionParams.accounts) {
                        this.accounts = sessionParams.accounts;
                    }
                    this._eventManager.trigger({
                        event: "session_update",
                        params: [
                            {
                                chainId: this.chainId,
                                accounts: this.accounts,
                            },
                        ],
                    });
                }
                this._manageStorageSession();
            }
            else {
                this._handleSessionDisconnect(errorMsg);
            }
        }
        else {
            this._handleSessionDisconnect(errorMsg);
        }
    }
    _handleIncomingMessages(socketMessage) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const activeTopics = [this.clientId, this.handshakeTopic];
            if (!activeTopics.includes(socketMessage.topic)) {
                return;
            }
            let encryptionPayload;
            try {
                encryptionPayload = JSON.parse(socketMessage.payload);
            }
            catch (error) {
                return;
            }
            const payload = yield this._decrypt(encryptionPayload);
            if (payload) {
                this._eventManager.trigger(payload);
            }
        });
    }
    _subscribeToSessionRequest() {
        this._transport.subscribe(this.handshakeTopic);
    }
    _subscribeToResponse(id, callback) {
        this.on(`response:${id}`, callback);
    }
    _subscribeToSessionResponse(id, errorMsg) {
        this._subscribeToResponse(id, (error, payload) => {
            if (error) {
                this._handleSessionResponse(error.message);
                return;
            }
            if (legacy_utils_1.isJsonRpcResponseSuccess(payload)) {
                this._handleSessionResponse(errorMsg, payload.result);
            }
            else if (payload.error && payload.error.message) {
                this._handleSessionResponse(payload.error.message);
            }
            else {
                this._handleSessionResponse(errorMsg);
            }
        });
    }
    _subscribeToCallResponse(id) {
        return new Promise((resolve, reject) => {
            this._subscribeToResponse(id, (error, payload) => {
                if (error) {
                    reject(error);
                    return;
                }
                if (legacy_utils_1.isJsonRpcResponseSuccess(payload)) {
                    resolve(payload.result);
                }
                else if (payload.error && payload.error.message) {
                    reject(payload.error);
                }
                else {
                    reject(new Error(legacy_types_1.ERROR_INVALID_RESPONSE));
                }
            });
        });
    }
    _subscribeToInternalEvents() {
        this.on("display_uri", () => {
            if (this._qrcodeModal) {
                this._qrcodeModal.open(this.uri, () => {
                    this._eventManager.trigger({
                        event: "modal_closed",
                        params: [],
                    });
                }, this._qrcodeModalOptions);
            }
        });
        this.on("connect", () => {
            if (this._qrcodeModal) {
                this._qrcodeModal.close();
            }
        });
        this.on("call_request_sent", (error, payload) => {
            const { request } = payload.params[0];
            if (legacy_utils_1.isMobile() && this._signingMethods.includes(request.method)) {
                const mobileLinkUrl = legacy_utils_1.getLocal(legacy_types_1.MOBILE_LINK_CHOICE_KEY);
                if (mobileLinkUrl) {
                    window.location.href = mobileLinkUrl.href;
                }
            }
        });
        this.on("wc_sessionRequest", (error, payload) => {
            if (error) {
                this._eventManager.trigger({
                    event: "error",
                    params: [
                        {
                            code: "SESSION_REQUEST_ERROR",
                            message: error.toString(),
                        },
                    ],
                });
            }
            this.handshakeId = payload.id;
            this.peerId = payload.params[0].peerId;
            this.peerMeta = payload.params[0].peerMeta;
            const internalPayload = Object.assign(Object.assign({}, payload), { method: "session_request" });
            this._eventManager.trigger(internalPayload);
        });
        this.on("wc_sessionUpdate", (error, payload) => {
            if (error) {
                this._handleSessionResponse(error.message);
            }
            this._handleSessionResponse("Session disconnected", payload.params[0]);
        });
    }
    _initTransport() {
        this._transport.on("message", (socketMessage) => this._handleIncomingMessages(socketMessage));
        this._transport.on("open", () => this._eventManager.trigger({ event: "transport_open", params: [] }));
        this._transport.on("close", () => this._eventManager.trigger({ event: "transport_close", params: [] }));
        this._transport.on("error", () => this._eventManager.trigger({
            event: "transport_error",
            params: ["Websocket connection failed"],
        }));
        this._transport.open();
    }
    _formatUri() {
        const protocol = this.protocol;
        const handshakeTopic = this.handshakeTopic;
        const version = this.version;
        const bridge = encodeURIComponent(this.bridge);
        const key = this.key;
        const uri = `${protocol}:${handshakeTopic}@${version}?bridge=${bridge}&key=${key}`;
        return uri;
    }
    _parseUri(uri) {
        const result = legacy_utils_1.parseWalletConnectUri(uri);
        if (result.protocol === this.protocol) {
            if (!result.handshakeTopic) {
                throw Error("Invalid or missing handshakeTopic parameter value");
            }
            const handshakeTopic = result.handshakeTopic;
            if (!result.bridge) {
                throw Error("Invalid or missing bridge url parameter value");
            }
            const bridge = decodeURIComponent(result.bridge);
            if (!result.key) {
                throw Error("Invalid or missing key parameter value");
            }
            const key = result.key;
            return { handshakeTopic, bridge, key };
        }
        else {
            throw new Error(legacy_types_1.ERROR_INVALID_URI);
        }
    }
    _generateKey() {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (this._cryptoLib) {
                const result = yield this._cryptoLib.generateKey();
                return result;
            }
            return null;
        });
    }
    _encrypt(data) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const key = this._key;
            if (this._cryptoLib && key) {
                const result = yield this._cryptoLib.encrypt(data, key);
                return result;
            }
            return null;
        });
    }
    _decrypt(payload) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const key = this._key;
            if (this._cryptoLib && key) {
                const result = yield this._cryptoLib.decrypt(payload, key);
                return result;
            }
            return null;
        });
    }
    _getStorageSession() {
        let result = null;
        if (this._sessionStorage) {
            result = this._sessionStorage.getSession();
        }
        return result;
    }
    _setStorageSession() {
        if (this._sessionStorage) {
            this._sessionStorage.setSession(this.session);
        }
    }
    _removeStorageSession() {
        if (this._sessionStorage) {
            this._sessionStorage.removeSession();
        }
    }
    _manageStorageSession() {
        if (this._connected) {
            this._setStorageSession();
        }
        else {
            this._removeStorageSession();
        }
    }
    _registerPushServer(pushServerOpts) {
        if (!pushServerOpts.url || typeof pushServerOpts.url !== "string") {
            throw Error("Invalid or missing pushServerOpts.url parameter value");
        }
        if (!pushServerOpts.type || typeof pushServerOpts.type !== "string") {
            throw Error("Invalid or missing pushServerOpts.type parameter value");
        }
        if (!pushServerOpts.token || typeof pushServerOpts.token !== "string") {
            throw Error("Invalid or missing pushServerOpts.token parameter value");
        }
        const pushSubscription = {
            bridge: this.bridge,
            topic: this.clientId,
            type: pushServerOpts.type,
            token: pushServerOpts.token,
            peerName: "",
            language: pushServerOpts.language || "",
        };
        this.on("connect", (error, payload) => tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (error) {
                throw error;
            }
            if (pushServerOpts.peerMeta) {
                const peerName = payload.params[0].peerMeta.name;
                pushSubscription.peerName = peerName;
            }
            try {
                const response = yield fetch(`${pushServerOpts.url}/new`, {
                    method: "POST",
                    headers: {
                        Accept: "application/json",
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify(pushSubscription),
                });
                const json = yield response.json();
                if (!json.success) {
                    throw Error("Failed to register in Push Server");
                }
            }
            catch (error) {
                throw Error("Failed to register in Push Server");
            }
        }));
    }
}
exports["default"] = Connector;
//# sourceMappingURL=core.js.map

/***/ }),

/***/ 48156:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.decrypt = exports.encrypt = exports.verifyHmac = exports.generateKey = void 0;
const tslib_1 = __webpack_require__(97316);
const crypto = tslib_1.__importStar(__webpack_require__(41210));
const encoding = tslib_1.__importStar(__webpack_require__(2921));
const legacy_utils_1 = __webpack_require__(10603);
function generateKey(length) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const _length = (length || 256) / 8;
        const bytes = crypto.randomBytes(_length);
        const result = legacy_utils_1.convertBufferToArrayBuffer(encoding.arrayToBuffer(bytes));
        return result;
    });
}
exports.generateKey = generateKey;
function verifyHmac(payload, key) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const cipherText = encoding.hexToArray(payload.data);
        const iv = encoding.hexToArray(payload.iv);
        const hmac = encoding.hexToArray(payload.hmac);
        const hmacHex = encoding.arrayToHex(hmac, false);
        const unsigned = encoding.concatArrays(cipherText, iv);
        const chmac = yield crypto.hmacSha256Sign(key, unsigned);
        const chmacHex = encoding.arrayToHex(chmac, false);
        if (encoding.removeHexPrefix(hmacHex) === encoding.removeHexPrefix(chmacHex)) {
            return true;
        }
        return false;
    });
}
exports.verifyHmac = verifyHmac;
function encrypt(data, key, providedIv) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const _key = encoding.bufferToArray(legacy_utils_1.convertArrayBufferToBuffer(key));
        const ivArrayBuffer = providedIv || (yield generateKey(128));
        const iv = encoding.bufferToArray(legacy_utils_1.convertArrayBufferToBuffer(ivArrayBuffer));
        const ivHex = encoding.arrayToHex(iv, false);
        const contentString = JSON.stringify(data);
        const content = encoding.utf8ToArray(contentString);
        const cipherText = yield crypto.aesCbcEncrypt(iv, _key, content);
        const cipherTextHex = encoding.arrayToHex(cipherText, false);
        const unsigned = encoding.concatArrays(cipherText, iv);
        const hmac = yield crypto.hmacSha256Sign(_key, unsigned);
        const hmacHex = encoding.arrayToHex(hmac, false);
        return {
            data: cipherTextHex,
            hmac: hmacHex,
            iv: ivHex,
        };
    });
}
exports.encrypt = encrypt;
function decrypt(payload, key) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const _key = encoding.bufferToArray(legacy_utils_1.convertArrayBufferToBuffer(key));
        if (!_key) {
            throw new Error("Missing key: required for decryption");
        }
        const verified = yield verifyHmac(payload, _key);
        if (!verified) {
            return null;
        }
        const cipherText = encoding.hexToArray(payload.data);
        const iv = encoding.hexToArray(payload.iv);
        const buffer = yield crypto.aesCbcDecrypt(iv, _key, cipherText);
        const utf8 = encoding.arrayToUtf8(buffer);
        let data;
        try {
            data = JSON.parse(utf8);
        }
        catch (error) {
            return null;
        }
        return data;
    });
}
exports.decrypt = decrypt;
//# sourceMappingURL=crypto.js.map

/***/ }),

/***/ 85350:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
const legacy_utils_1 = __webpack_require__(10603);
class EventManager {
    constructor() {
        this._eventEmitters = [];
    }
    subscribe(eventEmitter) {
        this._eventEmitters.push(eventEmitter);
    }
    unsubscribe(event) {
        this._eventEmitters = this._eventEmitters.filter(x => x.event !== event);
    }
    trigger(payload) {
        let eventEmitters = [];
        let event;
        if (legacy_utils_1.isJsonRpcRequest(payload)) {
            event = payload.method;
        }
        else if (legacy_utils_1.isJsonRpcResponseSuccess(payload) || legacy_utils_1.isJsonRpcResponseError(payload)) {
            event = `response:${payload.id}`;
        }
        else if (legacy_utils_1.isInternalEvent(payload)) {
            event = payload.event;
        }
        else {
            event = "";
        }
        if (event) {
            eventEmitters = this._eventEmitters.filter((eventEmitter) => eventEmitter.event === event);
        }
        if ((!eventEmitters || !eventEmitters.length) &&
            !legacy_utils_1.isReservedEvent(event) &&
            !legacy_utils_1.isInternalEvent(event)) {
            eventEmitters = this._eventEmitters.filter((eventEmitter) => eventEmitter.event === "call_request");
        }
        eventEmitters.forEach((eventEmitter) => {
            if (legacy_utils_1.isJsonRpcResponseError(payload)) {
                const error = new Error(payload.error.message);
                eventEmitter.callback(error, null);
            }
            else {
                eventEmitter.callback(null, payload);
            }
        });
    }
}
exports["default"] = EventManager;
//# sourceMappingURL=events.js.map

/***/ }),

/***/ 42496:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __webpack_require__(97316);
const core_1 = tslib_1.__importDefault(__webpack_require__(98491));
const cryptoLib = tslib_1.__importStar(__webpack_require__(48156));
class WalletConnect extends core_1.default {
    constructor(connectorOpts, pushServerOpts) {
        super({
            cryptoLib,
            connectorOpts,
            pushServerOpts,
        });
    }
}
exports["default"] = WalletConnect;
//# sourceMappingURL=index.js.map

/***/ }),

/***/ 91083:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
class NetworkMonitor {
    constructor() {
        this._eventEmitters = [];
        if (typeof window !== "undefined" && typeof window.addEventListener !== "undefined") {
            window.addEventListener("online", () => this.trigger("online"));
            window.addEventListener("offline", () => this.trigger("offline"));
        }
    }
    on(event, callback) {
        this._eventEmitters.push({
            event,
            callback,
        });
    }
    trigger(event) {
        let eventEmitters = [];
        if (event) {
            eventEmitters = this._eventEmitters.filter((eventEmitter) => eventEmitter.event === event);
        }
        eventEmitters.forEach((eventEmitter) => {
            eventEmitter.callback();
        });
    }
}
exports["default"] = NetworkMonitor;
//# sourceMappingURL=network.js.map

/***/ }),

/***/ 55218:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __webpack_require__(97316);
const legacy_utils_1 = __webpack_require__(10603);
const network_1 = tslib_1.__importDefault(__webpack_require__(91083));
const WS = typeof global.WebSocket !== "undefined" ? global.WebSocket : __webpack_require__(26864);
class SocketTransport {
    constructor(opts) {
        this.opts = opts;
        this._queue = [];
        this._events = [];
        this._subscriptions = [];
        this._protocol = opts.protocol;
        this._version = opts.version;
        this._url = "";
        this._netMonitor = null;
        this._socket = null;
        this._nextSocket = null;
        this._subscriptions = opts.subscriptions || [];
        this._netMonitor = opts.netMonitor || new network_1.default();
        if (!opts.url || typeof opts.url !== "string") {
            throw new Error("Missing or invalid WebSocket url");
        }
        this._url = opts.url;
        this._netMonitor.on("online", () => this._socketCreate());
    }
    set readyState(value) {
    }
    get readyState() {
        return this._socket ? this._socket.readyState : -1;
    }
    set connecting(value) {
    }
    get connecting() {
        return this.readyState === 0;
    }
    set connected(value) {
    }
    get connected() {
        return this.readyState === 1;
    }
    set closing(value) {
    }
    get closing() {
        return this.readyState === 2;
    }
    set closed(value) {
    }
    get closed() {
        return this.readyState === 3;
    }
    open() {
        this._socketCreate();
    }
    close() {
        this._socketClose();
    }
    send(message, topic, silent) {
        if (!topic || typeof topic !== "string") {
            throw new Error("Missing or invalid topic field");
        }
        this._socketSend({
            topic: topic,
            type: "pub",
            payload: message,
            silent: !!silent,
        });
    }
    subscribe(topic) {
        this._socketSend({
            topic: topic,
            type: "sub",
            payload: "",
            silent: true,
        });
    }
    on(event, callback) {
        this._events.push({ event, callback });
    }
    _socketCreate() {
        if (this._nextSocket) {
            return;
        }
        const url = getWebSocketUrl(this._url, this._protocol, this._version);
        this._nextSocket = new WS(url);
        if (!this._nextSocket) {
            throw new Error("Failed to create socket");
        }
        this._nextSocket.onmessage = (event) => this._socketReceive(event);
        this._nextSocket.onopen = () => this._socketOpen();
        this._nextSocket.onerror = (event) => this._socketError(event);
        this._nextSocket.onclose = () => {
            setTimeout(() => {
                this._nextSocket = null;
                this._socketCreate();
            }, 1000);
        };
    }
    _socketOpen() {
        this._socketClose();
        this._socket = this._nextSocket;
        this._nextSocket = null;
        this._queueSubscriptions();
        this._pushQueue();
    }
    _socketClose() {
        if (this._socket) {
            this._socket.onclose = () => {
            };
            this._socket.close();
        }
    }
    _socketSend(socketMessage) {
        const message = JSON.stringify(socketMessage);
        if (this._socket && this._socket.readyState === 1) {
            this._socket.send(message);
        }
        else {
            this._setToQueue(socketMessage);
            this._socketCreate();
        }
    }
    _socketReceive(event) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            let socketMessage;
            try {
                socketMessage = JSON.parse(event.data);
            }
            catch (error) {
                return;
            }
            this._socketSend({
                topic: socketMessage.topic,
                type: "ack",
                payload: "",
                silent: true,
            });
            if (this._socket && this._socket.readyState === 1) {
                const events = this._events.filter(event => event.event === "message");
                if (events && events.length) {
                    events.forEach(event => event.callback(socketMessage));
                }
            }
        });
    }
    _socketError(e) {
        const events = this._events.filter(event => event.event === "error");
        if (events && events.length) {
            events.forEach(event => event.callback(e));
        }
    }
    _queueSubscriptions() {
        const subscriptions = this._subscriptions;
        subscriptions.forEach((topic) => this._queue.push({
            topic: topic,
            type: "sub",
            payload: "",
            silent: true,
        }));
        this._subscriptions = this.opts.subscriptions || [];
    }
    _setToQueue(socketMessage) {
        this._queue.push(socketMessage);
    }
    _pushQueue() {
        const queue = this._queue;
        queue.forEach((socketMessage) => this._socketSend(socketMessage));
        this._queue = [];
    }
}
function getWebSocketUrl(_url, protocol, version) {
    var _a, _b;
    const url = _url.startsWith("https")
        ? _url.replace("https", "wss")
        : _url.startsWith("http")
            ? _url.replace("http", "ws")
            : _url;
    const splitUrl = url.split("?");
    const params = legacy_utils_1.isBrowser()
        ? {
            protocol,
            version,
            env: "browser",
            host: ((_a = legacy_utils_1.getLocation()) === null || _a === void 0 ? void 0 : _a.host) || "",
        }
        : {
            protocol,
            version,
            env: ((_b = legacy_utils_1.detectEnv()) === null || _b === void 0 ? void 0 : _b.name) || "",
        };
    const queryString = legacy_utils_1.appendToQueryString(legacy_utils_1.getQueryString(splitUrl[1] || ""), params);
    return splitUrl[0] + "?" + queryString;
}
exports["default"] = SocketTransport;
//# sourceMappingURL=socket.js.map

/***/ }),

/***/ 14710:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
const legacy_utils_1 = __webpack_require__(10603);
class SessionStorage {
    constructor(storageId = "walletconnect") {
        this.storageId = storageId;
    }
    getSession() {
        let session = null;
        const json = legacy_utils_1.getLocal(this.storageId);
        if (json && legacy_utils_1.isWalletConnectSession(json)) {
            session = json;
        }
        return session;
    }
    setSession(session) {
        legacy_utils_1.setLocal(this.storageId, session);
        return session;
    }
    removeSession() {
        legacy_utils_1.removeLocal(this.storageId);
    }
}
exports["default"] = SessionStorage;
//# sourceMappingURL=storage.js.map

/***/ }),

/***/ 13662:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getBridgeUrl = exports.shouldSelectRandomly = exports.selectRandomBridgeUrl = exports.randomBridgeIndex = exports.extractRootDomain = exports.extractHostname = void 0;
const domain = "walletconnect.org";
const alphanumerical = "abcdefghijklmnopqrstuvwxyz0123456789";
const bridges = alphanumerical.split("").map(char => `https://${char}.bridge.walletconnect.org`);
function extractHostname(url) {
    let hostname = url.indexOf("//") > -1 ? url.split("/")[2] : url.split("/")[0];
    hostname = hostname.split(":")[0];
    hostname = hostname.split("?")[0];
    return hostname;
}
exports.extractHostname = extractHostname;
function extractRootDomain(url) {
    return extractHostname(url)
        .split(".")
        .slice(-2)
        .join(".");
}
exports.extractRootDomain = extractRootDomain;
function randomBridgeIndex() {
    return Math.floor(Math.random() * bridges.length);
}
exports.randomBridgeIndex = randomBridgeIndex;
function selectRandomBridgeUrl() {
    return bridges[randomBridgeIndex()];
}
exports.selectRandomBridgeUrl = selectRandomBridgeUrl;
function shouldSelectRandomly(url) {
    return extractRootDomain(url) === domain;
}
exports.shouldSelectRandomly = shouldSelectRandomly;
function getBridgeUrl(url) {
    if (shouldSelectRandomly(url)) {
        return selectRandomBridgeUrl();
    }
    return url;
}
exports.getBridgeUrl = getBridgeUrl;
//# sourceMappingURL=url.js.map

/***/ }),

/***/ 8569:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

function _interopDefault (ex) { return (ex && (typeof ex === 'object') && 'default' in ex) ? ex['default'] : ex; }

var legacyUtils = __webpack_require__(10603);
var QRCode = _interopDefault(__webpack_require__(43907));
var copy = _interopDefault(__webpack_require__(90343));
var React = __webpack_require__(80134);

function open(uri) {
  QRCode.toString(uri, {
    type: "terminal"
  }).then(console.log);
}

var WALLETCONNECT_STYLE_SHEET = ":root {\n  --animation-duration: 300ms;\n}\n\n@keyframes fadeIn {\n  from {\n    opacity: 0;\n  }\n  to {\n    opacity: 1;\n  }\n}\n\n@keyframes fadeOut {\n  from {\n    opacity: 1;\n  }\n  to {\n    opacity: 0;\n  }\n}\n\n.animated {\n  animation-duration: var(--animation-duration);\n  animation-fill-mode: both;\n}\n\n.fadeIn {\n  animation-name: fadeIn;\n}\n\n.fadeOut {\n  animation-name: fadeOut;\n}\n\n#walletconnect-wrapper {\n  -webkit-user-select: none;\n  align-items: center;\n  display: flex;\n  height: 100%;\n  justify-content: center;\n  left: 0;\n  pointer-events: none;\n  position: fixed;\n  top: 0;\n  user-select: none;\n  width: 100%;\n  z-index: 99999999999999;\n}\n\n.walletconnect-modal__headerLogo {\n  height: 21px;\n}\n\n.walletconnect-modal__header p {\n  color: #ffffff;\n  font-size: 20px;\n  font-weight: 600;\n  margin: 0;\n  align-items: flex-start;\n  display: flex;\n  flex: 1;\n  margin-left: 5px;\n}\n\n.walletconnect-modal__close__wrapper {\n  position: absolute;\n  top: 0px;\n  right: 0px;\n  z-index: 10000;\n  background: white;\n  border-radius: 26px;\n  padding: 6px;\n  box-sizing: border-box;\n  width: 26px;\n  height: 26px;\n  cursor: pointer;\n}\n\n.walletconnect-modal__close__icon {\n  position: relative;\n  top: 7px;\n  right: 0;\n  display: flex;\n  align-items: center;\n  justify-content: center;\n  transform: rotate(45deg);\n}\n\n.walletconnect-modal__close__line1 {\n  position: absolute;\n  width: 100%;\n  border: 1px solid rgb(48, 52, 59);\n}\n\n.walletconnect-modal__close__line2 {\n  position: absolute;\n  width: 100%;\n  border: 1px solid rgb(48, 52, 59);\n  transform: rotate(90deg);\n}\n\n.walletconnect-qrcode__base {\n  -webkit-tap-highlight-color: rgba(0, 0, 0, 0);\n  background: rgba(37, 41, 46, 0.95);\n  height: 100%;\n  left: 0;\n  pointer-events: auto;\n  position: fixed;\n  top: 0;\n  transition: 0.4s cubic-bezier(0.19, 1, 0.22, 1);\n  width: 100%;\n  will-change: opacity;\n  padding: 40px;\n  box-sizing: border-box;\n}\n\n.walletconnect-qrcode__text {\n  color: rgba(60, 66, 82, 0.6);\n  font-size: 16px;\n  font-weight: 600;\n  letter-spacing: 0;\n  line-height: 1.1875em;\n  margin: 10px 0 20px 0;\n  text-align: center;\n  width: 100%;\n}\n\n@media only screen and (max-width: 768px) {\n  .walletconnect-qrcode__text {\n    font-size: 4vw;\n  }\n}\n\n@media only screen and (max-width: 320px) {\n  .walletconnect-qrcode__text {\n    font-size: 14px;\n  }\n}\n\n.walletconnect-qrcode__image {\n  width: calc(100% - 30px);\n  box-sizing: border-box;\n  cursor: none;\n  margin: 0 auto;\n}\n\n.walletconnect-qrcode__notification {\n  position: absolute;\n  bottom: 0;\n  left: 0;\n  right: 0;\n  font-size: 16px;\n  padding: 16px 20px;\n  border-radius: 16px;\n  text-align: center;\n  transition: all 0.1s ease-in-out;\n  background: white;\n  color: black;\n  margin-bottom: -60px;\n  opacity: 0;\n}\n\n.walletconnect-qrcode__notification.notification__show {\n  opacity: 1;\n}\n\n@media only screen and (max-width: 768px) {\n  .walletconnect-modal__header {\n    height: 130px;\n  }\n  .walletconnect-modal__base {\n    overflow: auto;\n  }\n}\n\n@media only screen and (min-device-width: 415px) and (max-width: 768px) {\n  #content {\n    max-width: 768px;\n    box-sizing: border-box;\n  }\n}\n\n@media only screen and (min-width: 375px) and (max-width: 415px) {\n  #content {\n    max-width: 414px;\n    box-sizing: border-box;\n  }\n}\n\n@media only screen and (min-width: 320px) and (max-width: 375px) {\n  #content {\n    max-width: 375px;\n    box-sizing: border-box;\n  }\n}\n\n@media only screen and (max-width: 320px) {\n  #content {\n    max-width: 320px;\n    box-sizing: border-box;\n  }\n}\n\n.walletconnect-modal__base {\n  -webkit-font-smoothing: antialiased;\n  background: #ffffff;\n  border-radius: 24px;\n  box-shadow: 0 10px 50px 5px rgba(0, 0, 0, 0.4);\n  font-family: ui-rounded, \"SF Pro Rounded\", \"SF Pro Text\", medium-content-sans-serif-font,\n    -apple-system, BlinkMacSystemFont, ui-sans-serif, \"Segoe UI\", Roboto, Oxygen, Ubuntu, Cantarell,\n    \"Open Sans\", \"Helvetica Neue\", sans-serif;\n  margin-top: 41px;\n  padding: 24px 24px 22px;\n  pointer-events: auto;\n  position: relative;\n  text-align: center;\n  transition: 0.4s cubic-bezier(0.19, 1, 0.22, 1);\n  will-change: transform;\n  overflow: visible;\n  transform: translateY(-50%);\n  top: 50%;\n  max-width: 500px;\n  margin: auto;\n}\n\n@media only screen and (max-width: 320px) {\n  .walletconnect-modal__base {\n    padding: 24px 12px;\n  }\n}\n\n.walletconnect-modal__base .hidden {\n  transform: translateY(150%);\n  transition: 0.125s cubic-bezier(0.4, 0, 1, 1);\n}\n\n.walletconnect-modal__header {\n  align-items: center;\n  display: flex;\n  height: 26px;\n  left: 0;\n  justify-content: space-between;\n  position: absolute;\n  top: -42px;\n  width: 100%;\n}\n\n.walletconnect-modal__base .wc-logo {\n  align-items: center;\n  display: flex;\n  height: 26px;\n  margin-top: 15px;\n  padding-bottom: 15px;\n  pointer-events: auto;\n}\n\n.walletconnect-modal__base .wc-logo div {\n  background-color: #3399ff;\n  height: 21px;\n  margin-right: 5px;\n  mask-image: url(\"images/wc-logo.svg\") center no-repeat;\n  width: 32px;\n}\n\n.walletconnect-modal__base .wc-logo p {\n  color: #ffffff;\n  font-size: 20px;\n  font-weight: 600;\n  margin: 0;\n}\n\n.walletconnect-modal__base h2 {\n  color: rgba(60, 66, 82, 0.6);\n  font-size: 16px;\n  font-weight: 600;\n  letter-spacing: 0;\n  line-height: 1.1875em;\n  margin: 0 0 19px 0;\n  text-align: center;\n  width: 100%;\n}\n\n.walletconnect-modal__base__row {\n  -webkit-tap-highlight-color: rgba(0, 0, 0, 0);\n  align-items: center;\n  border-radius: 20px;\n  cursor: pointer;\n  display: flex;\n  height: 56px;\n  justify-content: space-between;\n  padding: 0 15px;\n  position: relative;\n  margin: 0px 0px 8px;\n  text-align: left;\n  transition: 0.15s cubic-bezier(0.25, 0.46, 0.45, 0.94);\n  will-change: transform;\n  text-decoration: none;\n}\n\n.walletconnect-modal__base__row:hover {\n  background: rgba(60, 66, 82, 0.06);\n}\n\n.walletconnect-modal__base__row:active {\n  background: rgba(60, 66, 82, 0.06);\n  transform: scale(0.975);\n  transition: 0.1s cubic-bezier(0.25, 0.46, 0.45, 0.94);\n}\n\n.walletconnect-modal__base__row__h3 {\n  color: #25292e;\n  font-size: 20px;\n  font-weight: 700;\n  margin: 0;\n  padding-bottom: 3px;\n}\n\n.walletconnect-modal__base__row__right {\n  align-items: center;\n  display: flex;\n  justify-content: center;\n}\n\n.walletconnect-modal__base__row__right__app-icon {\n  border-radius: 8px;\n  height: 34px;\n  margin: 0 11px 2px 0;\n  width: 34px;\n  background-size: 100%;\n  box-shadow: 0 4px 12px 0 rgba(37, 41, 46, 0.25);\n}\n\n.walletconnect-modal__base__row__right__caret {\n  height: 18px;\n  opacity: 0.3;\n  transition: 0.1s cubic-bezier(0.25, 0.46, 0.45, 0.94);\n  width: 8px;\n  will-change: opacity;\n}\n\n.walletconnect-modal__base__row:hover .caret,\n.walletconnect-modal__base__row:active .caret {\n  opacity: 0.6;\n}\n\n.walletconnect-modal__mobile__toggle {\n  width: 80%;\n  display: flex;\n  margin: 0 auto;\n  position: relative;\n  overflow: hidden;\n  border-radius: 8px;\n  margin-bottom: 18px;\n  background: #d4d5d9;\n}\n\n.walletconnect-modal__single_wallet {\n  display: flex;\n  justify-content: center;\n  margin-top: 7px;\n  margin-bottom: 18px;\n}\n\n.walletconnect-modal__single_wallet a {\n  cursor: pointer;\n  color: rgb(64, 153, 255);\n  font-size: 21px;\n  font-weight: 800;\n  text-decoration: none !important;\n  margin: 0 auto;\n}\n\n.walletconnect-modal__mobile__toggle_selector {\n  width: calc(50% - 8px);\n  background: white;\n  position: absolute;\n  border-radius: 5px;\n  height: calc(100% - 8px);\n  top: 4px;\n  transition: all 0.2s ease-in-out;\n  transform: translate3d(4px, 0, 0);\n}\n\n.walletconnect-modal__mobile__toggle.right__selected .walletconnect-modal__mobile__toggle_selector {\n  transform: translate3d(calc(100% + 12px), 0, 0);\n}\n\n.walletconnect-modal__mobile__toggle a {\n  font-size: 12px;\n  width: 50%;\n  text-align: center;\n  padding: 8px;\n  margin: 0;\n  font-weight: 600;\n  z-index: 1;\n}\n\n.walletconnect-modal__footer {\n  display: flex;\n  justify-content: center;\n  margin-top: 20px;\n}\n\n@media only screen and (max-width: 768px) {\n  .walletconnect-modal__footer {\n    margin-top: 5vw;\n  }\n}\n\n.walletconnect-modal__footer a {\n  cursor: pointer;\n  color: #898d97;\n  font-size: 15px;\n  margin: 0 auto;\n}\n\n@media only screen and (max-width: 320px) {\n  .walletconnect-modal__footer a {\n    font-size: 14px;\n  }\n}\n\n.walletconnect-connect__buttons__wrapper {\n  max-height: 44vh;\n}\n\n.walletconnect-connect__buttons__wrapper__android {\n  margin: 50% 0;\n}\n\n.walletconnect-connect__buttons__wrapper__wrap {\n  display: grid;\n  grid-template-columns: repeat(4, 1fr);\n  margin: 10px 0;\n}\n\n@media only screen and (min-width: 768px) {\n  .walletconnect-connect__buttons__wrapper__wrap {\n    margin-top: 40px;\n  }\n}\n\n.walletconnect-connect__button {\n  background-color: rgb(64, 153, 255);\n  padding: 12px;\n  border-radius: 8px;\n  text-decoration: none;\n  color: rgb(255, 255, 255);\n  font-weight: 500;\n}\n\n.walletconnect-connect__button__icon_anchor {\n  cursor: pointer;\n  display: flex;\n  justify-content: flex-start;\n  align-items: center;\n  margin: 8px;\n  width: 42px;\n  justify-self: center;\n  flex-direction: column;\n  text-decoration: none !important;\n}\n\n@media only screen and (max-width: 320px) {\n  .walletconnect-connect__button__icon_anchor {\n    margin: 4px;\n  }\n}\n\n.walletconnect-connect__button__icon {\n  border-radius: 10px;\n  height: 42px;\n  margin: 0;\n  width: 42px;\n  background-size: cover !important;\n  box-shadow: 0 4px 12px 0 rgba(37, 41, 46, 0.25);\n}\n\n.walletconnect-connect__button__text {\n  color: #424952;\n  font-size: 2.7vw;\n  text-decoration: none !important;\n  padding: 0;\n  margin-top: 1.8vw;\n  font-weight: 600;\n}\n\n@media only screen and (min-width: 768px) {\n  .walletconnect-connect__button__text {\n    font-size: 16px;\n    margin-top: 12px;\n  }\n}\n\n.walletconnect-search__input {\n  border: none;\n  background: #d4d5d9;\n  border-style: none;\n  padding: 8px 16px;\n  outline: none;\n  font-style: normal;\n  font-stretch: normal;\n  font-size: 16px;\n  font-style: normal;\n  font-stretch: normal;\n  line-height: normal;\n  letter-spacing: normal;\n  text-align: left;\n  border-radius: 8px;\n  width: calc(100% - 16px);\n  margin: 0;\n  margin-bottom: 8px;\n}\n";

// A type of promise-like that resolves synchronously and supports only one observer
var _iteratorSymbol = /*#__PURE__*/typeof Symbol !== "undefined" ? Symbol.iterator || (Symbol.iterator = Symbol("Symbol.iterator")) : "@@iterator";
var _asyncIteratorSymbol = /*#__PURE__*/typeof Symbol !== "undefined" ? Symbol.asyncIterator || (Symbol.asyncIterator = Symbol("Symbol.asyncIterator")) : "@@asyncIterator";

// Asynchronously call a function and send errors to recovery continuation
function _catch(body, recover) {
  try {
    var result = body();
  } catch (e) {
    return recover(e);
  }
  if (result && result.then) {
    return result.then(void 0, recover);
  }
  return result;
}

var WALLETCONNECT_LOGO_SVG_URL = "data:image/svg+xml,%3C?xml version='1.0' encoding='UTF-8'?%3E %3Csvg width='300px' height='185px' viewBox='0 0 300 185' version='1.1' xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink'%3E %3C!-- Generator: Sketch 49.3 (51167) - http://www.bohemiancoding.com/sketch --%3E %3Ctitle%3EWalletConnect%3C/title%3E %3Cdesc%3ECreated with Sketch.%3C/desc%3E %3Cdefs%3E%3C/defs%3E %3Cg id='Page-1' stroke='none' stroke-width='1' fill='none' fill-rule='evenodd'%3E %3Cg id='walletconnect-logo-alt' fill='%233B99FC' fill-rule='nonzero'%3E %3Cpath d='M61.4385429,36.2562612 C110.349767,-11.6319051 189.65053,-11.6319051 238.561752,36.2562612 L244.448297,42.0196786 C246.893858,44.4140867 246.893858,48.2961898 244.448297,50.690599 L224.311602,70.406102 C223.088821,71.6033071 221.106302,71.6033071 219.883521,70.406102 L211.782937,62.4749541 C177.661245,29.0669724 122.339051,29.0669724 88.2173582,62.4749541 L79.542302,70.9685592 C78.3195204,72.1657633 76.337001,72.1657633 75.1142214,70.9685592 L54.9775265,51.2530561 C52.5319653,48.8586469 52.5319653,44.9765439 54.9775265,42.5821357 L61.4385429,36.2562612 Z M280.206339,77.0300061 L298.128036,94.5769031 C300.573585,96.9713 300.573599,100.85338 298.128067,103.247793 L217.317896,182.368927 C214.872352,184.763353 210.907314,184.76338 208.461736,182.368989 C208.461726,182.368979 208.461714,182.368967 208.461704,182.368957 L151.107561,126.214385 C150.496171,125.615783 149.504911,125.615783 148.893521,126.214385 C148.893517,126.214389 148.893514,126.214393 148.89351,126.214396 L91.5405888,182.368927 C89.095052,184.763359 85.1300133,184.763399 82.6844276,182.369014 C82.6844133,182.369 82.684398,182.368986 82.6843827,182.36897 L1.87196327,103.246785 C-0.573596939,100.852377 -0.573596939,96.9702735 1.87196327,94.5758653 L19.7936929,77.028998 C22.2392531,74.6345898 26.2042918,74.6345898 28.6498531,77.028998 L86.0048306,133.184355 C86.6162214,133.782957 87.6074796,133.782957 88.2188704,133.184355 C88.2188796,133.184346 88.2188878,133.184338 88.2188969,133.184331 L145.571,77.028998 C148.016505,74.6345347 151.981544,74.6344449 154.427161,77.028798 C154.427195,77.0288316 154.427229,77.0288653 154.427262,77.028899 L211.782164,133.184331 C212.393554,133.782932 213.384814,133.782932 213.996204,133.184331 L271.350179,77.0300061 C273.79574,74.6355969 277.760778,74.6355969 280.206339,77.0300061 Z' id='WalletConnect'%3E%3C/path%3E %3C/g%3E %3C/g%3E %3C/svg%3E";

var WALLETCONNECT_HEADER_TEXT = "WalletConnect";
var ANIMATION_DURATION = 300;
var DEFAULT_BUTTON_COLOR = "rgb(64, 153, 255)";
var WALLETCONNECT_WRAPPER_ID = "walletconnect-wrapper";
var WALLETCONNECT_STYLE_ID = "walletconnect-style-sheet";
var WALLETCONNECT_MODAL_ID = "walletconnect-qrcode-modal";
var WALLETCONNECT_CLOSE_BUTTON_ID = "walletconnect-qrcode-close";
var WALLETCONNECT_CTA_TEXT_ID = "walletconnect-qrcode-text";
var WALLETCONNECT_CONNECT_BUTTON_ID = "walletconnect-connect-button";

function Header(props) {
  return React.createElement("div", {
    className: "walletconnect-modal__header"
  }, React.createElement("img", {
    src: WALLETCONNECT_LOGO_SVG_URL,
    className: "walletconnect-modal__headerLogo"
  }), React.createElement("p", null, WALLETCONNECT_HEADER_TEXT), React.createElement("div", {
    className: "walletconnect-modal__close__wrapper",
    onClick: props.onClose
  }, React.createElement("div", {
    id: WALLETCONNECT_CLOSE_BUTTON_ID,
    className: "walletconnect-modal__close__icon"
  }, React.createElement("div", {
    className: "walletconnect-modal__close__line1"
  }), React.createElement("div", {
    className: "walletconnect-modal__close__line2"
  }))));
}

function ConnectButton(props) {
  return React.createElement("a", {
    className: "walletconnect-connect__button",
    href: props.href,
    id: (WALLETCONNECT_CONNECT_BUTTON_ID + "-" + (props.name)),
    onClick: props.onClick,
    rel: "noopener noreferrer",
    style: {
      backgroundColor: props.color
    },
    target: "_blank"
  }, props.name);
}

var CARET_SVG_URL = "data:image/svg+xml,%3Csvg width='8' height='18' viewBox='0 0 8 18' fill='none' xmlns='http://www.w3.org/2000/svg'%3E %3Cpath fill-rule='evenodd' clip-rule='evenodd' d='M0.586301 0.213898C0.150354 0.552968 0.0718197 1.18124 0.41089 1.61719L5.2892 7.88931C5.57007 8.25042 5.57007 8.75608 5.2892 9.11719L0.410889 15.3893C0.071819 15.8253 0.150353 16.4535 0.586301 16.7926C1.02225 17.1317 1.65052 17.0531 1.98959 16.6172L6.86791 10.3451C7.7105 9.26174 7.7105 7.74476 6.86791 6.66143L1.98959 0.38931C1.65052 -0.0466374 1.02225 -0.125172 0.586301 0.213898Z' fill='%233C4252'/%3E %3C/svg%3E";

function WalletButton(props) {
  var color = props.color;
  var href = props.href;
  var name = props.name;
  var logo = props.logo;
  var onClick = props.onClick;
  return React.createElement("a", {
    className: "walletconnect-modal__base__row",
    href: href,
    onClick: onClick,
    rel: "noopener noreferrer",
    target: "_blank"
  }, React.createElement("h3", {
    className: "walletconnect-modal__base__row__h3"
  }, name), React.createElement("div", {
    className: "walletconnect-modal__base__row__right"
  }, React.createElement("div", {
    className: "walletconnect-modal__base__row__right__app-icon",
    style: {
      background: ("url('" + logo + "') " + color),
      backgroundSize: "100%"
    }
  }), React.createElement("img", {
    src: CARET_SVG_URL,
    className: "walletconnect-modal__base__row__right__caret"
  })));
}

function WalletIcon(props) {
  var color = props.color;
  var href = props.href;
  var name = props.name;
  var logo = props.logo;
  var onClick = props.onClick;
  var fontSize = window.innerWidth < 768 ? ((name.length > 8 ? 2.5 : 2.7) + "vw") : "inherit";
  return React.createElement("a", {
    className: "walletconnect-connect__button__icon_anchor",
    href: href,
    onClick: onClick,
    rel: "noopener noreferrer",
    target: "_blank"
  }, React.createElement("div", {
    className: "walletconnect-connect__button__icon",
    style: {
      background: ("url('" + logo + "') " + color),
      backgroundSize: "100%"
    }
  }), React.createElement("div", {
    style: {
      fontSize: fontSize
    },
    className: "walletconnect-connect__button__text"
  }, name));
}

var GRID_MIN_COUNT = 5;
var LINKS_PER_PAGE = 12;
function LinkDisplay(props) {
  var android = legacyUtils.isAndroid();
  var ref = React.useState("");
  var input = ref[0];
  var setInput = ref[1];
  var ref$1 = React.useState("");
  var filter = ref$1[0];
  var setFilter = ref$1[1];
  var ref$2 = React.useState(1);
  var page = ref$2[0];
  var setPage = ref$2[1];
  var links = filter ? props.links.filter(function (link) { return link.name.toLowerCase().includes(filter.toLowerCase()); }) : props.links;
  var errorMessage = props.errorMessage;
  var grid = filter || links.length > GRID_MIN_COUNT;
  var pages = Math.ceil(links.length / LINKS_PER_PAGE);
  var range = [(page - 1) * LINKS_PER_PAGE + 1, page * LINKS_PER_PAGE];
  var pageLinks = links.length ? links.filter(function (_, index) { return index + 1 >= range[0] && index + 1 <= range[1]; }) : [];
  var hasPaging = !!(!android && pages > 1);
  var filterTimeout = undefined;
  function handleInput(e) {
    setInput(e.target.value);
    clearTimeout(filterTimeout);
    if (e.target.value) {
      filterTimeout = setTimeout(function () {
        setFilter(e.target.value);
        setPage(1);
      }, 1000);
    } else {
      setInput("");
      setFilter("");
      setPage(1);
    }
  }
  return React.createElement("div", null, React.createElement("p", {
    id: WALLETCONNECT_CTA_TEXT_ID,
    className: "walletconnect-qrcode__text"
  }, android ? props.text.connect_mobile_wallet : props.text.choose_preferred_wallet), !android && React.createElement("input", {
    className: "walletconnect-search__input",
    placeholder: "Search",
    value: input,
    onChange: handleInput
  }), React.createElement("div", {
    className: ("walletconnect-connect__buttons__wrapper" + (android ? "__android" : grid && links.length ? "__wrap" : ""))
  }, !android ? pageLinks.length ? pageLinks.map(function (entry) {
    var color = entry.color;
    var name = entry.name;
    var shortName = entry.shortName;
    var logo = entry.logo;
    var href = legacyUtils.formatIOSMobile(props.uri, entry);
    var handleClickIOS = React.useCallback(function () {
      legacyUtils.saveMobileLinkInfo({
        name: name,
        href: href
      });
    }, [pageLinks]);
    return !grid ? React.createElement(WalletButton, {
      color: color,
      href: href,
      name: name,
      logo: logo,
      onClick: handleClickIOS
    }) : React.createElement(WalletIcon, {
      color: color,
      href: href,
      name: shortName || name,
      logo: logo,
      onClick: handleClickIOS
    });
  }) : React.createElement(React.Fragment, null, React.createElement("p", null, errorMessage.length ? props.errorMessage : !!props.links.length && !links.length ? props.text.no_wallets_found : props.text.loading)) : React.createElement(ConnectButton, {
    name: props.text.connect,
    color: DEFAULT_BUTTON_COLOR,
    href: props.uri,
    onClick: React.useCallback(function () {
      legacyUtils.saveMobileLinkInfo({
        name: "Unknown",
        href: props.uri
      });
    }, [])
  })), hasPaging && React.createElement("div", {
    className: "walletconnect-modal__footer"
  }, Array(pages).fill(0).map(function (_, index) {
    var pageNumber = index + 1;
    var selected = page === pageNumber;
    return React.createElement("a", {
      style: {
        margin: "auto 10px",
        fontWeight: selected ? "bold" : "normal"
      },
      onClick: function () { return setPage(pageNumber); }
    }, pageNumber);
  })));
}

function Notification(props) {
  var show = !!props.message.trim();
  return React.createElement("div", {
    className: ("walletconnect-qrcode__notification" + (show ? " notification__show" : ""))
  }, props.message);
}

var formatQRCodeImage = function (data) {
  try {
    var result = "";
    return Promise.resolve(QRCode.toString(data, {
      margin: 0,
      type: "svg"
    })).then(function (dataString) {
      if (typeof dataString === "string") {
        result = dataString.replace("<svg", "<svg class=\"walletconnect-qrcode__image\"");
      }
      return result;
    });
  } catch (e) {
    return Promise.reject(e);
  }
};
function QRCodeDisplay(props) {
  var ref = React.useState("");
  var notification = ref[0];
  var setNotification = ref[1];
  var ref$1 = React.useState("");
  var svg = ref$1[0];
  var setSvg = ref$1[1];
  React.useEffect(function () {
    try {
      return Promise.resolve(formatQRCodeImage(props.uri)).then(function (_formatQRCodeImage) {
        setSvg(_formatQRCodeImage);
      });
    } catch (e) {
      Promise.reject(e);
    }
  }, []);
  var copyToClipboard = function () {
    var success = copy(props.uri);
    if (success) {
      setNotification(props.text.copied_to_clipboard);
      setInterval(function () { return setNotification(""); }, 1200);
    } else {
      setNotification("Error");
      setInterval(function () { return setNotification(""); }, 1200);
    }
  };
  return React.createElement("div", null, React.createElement("p", {
    id: WALLETCONNECT_CTA_TEXT_ID,
    className: "walletconnect-qrcode__text"
  }, props.text.scan_qrcode_with_wallet), React.createElement("div", {
    dangerouslySetInnerHTML: {
      __html: svg
    }
  }), React.createElement("div", {
    className: "walletconnect-modal__footer"
  }, React.createElement("a", {
    onClick: copyToClipboard
  }, props.text.copy_to_clipboard)), React.createElement(Notification, {
    message: notification
  }));
}

function Modal(props) {
  var android = legacyUtils.isAndroid();
  var mobile = legacyUtils.isMobile();
  var whitelist = mobile ? props.qrcodeModalOptions && props.qrcodeModalOptions.mobileLinks ? props.qrcodeModalOptions.mobileLinks : undefined : props.qrcodeModalOptions && props.qrcodeModalOptions.desktopLinks ? props.qrcodeModalOptions.desktopLinks : undefined;
  var ref = React.useState(false);
  var loading = ref[0];
  var setLoading = ref[1];
  var ref$1 = React.useState(false);
  var fetched = ref$1[0];
  var setFetched = ref$1[1];
  var ref$2 = React.useState(!mobile);
  var displayQRCode = ref$2[0];
  var setDisplayQRCode = ref$2[1];
  var displayProps = {
    mobile: mobile,
    text: props.text,
    uri: props.uri,
    qrcodeModalOptions: props.qrcodeModalOptions
  };
  var ref$3 = React.useState("");
  var singleLinkHref = ref$3[0];
  var setSingleLinkHref = ref$3[1];
  var ref$4 = React.useState(false);
  var hasSingleLink = ref$4[0];
  var setHasSingleLink = ref$4[1];
  var ref$5 = React.useState([]);
  var links = ref$5[0];
  var setLinks = ref$5[1];
  var ref$6 = React.useState("");
  var errorMessage = ref$6[0];
  var setErrorMessage = ref$6[1];
  var getLinksIfNeeded = function () {
    if (fetched || loading || whitelist && !whitelist.length || links.length > 0) {
      return;
    }
    React.useEffect(function () {
      var initLinks = function () {
        try {
          if (android) { return Promise.resolve(); }
          setLoading(true);
          var _temp = _catch(function () {
            var url = props.qrcodeModalOptions && props.qrcodeModalOptions.registryUrl ? props.qrcodeModalOptions.registryUrl : legacyUtils.getWalletRegistryUrl();
            return Promise.resolve(fetch(url)).then(function (registryResponse) {
              return Promise.resolve(registryResponse.json()).then(function (_registryResponse$jso) {
                var registry = _registryResponse$jso.listings;
                var platform = mobile ? "mobile" : "desktop";
                var _links = legacyUtils.getMobileLinkRegistry(legacyUtils.formatMobileRegistry(registry, platform), whitelist);
                setLoading(false);
                setFetched(true);
                setErrorMessage(!_links.length ? props.text.no_supported_wallets : "");
                setLinks(_links);
                var hasSingleLink = _links.length === 1;
                if (hasSingleLink) {
                  setSingleLinkHref(legacyUtils.formatIOSMobile(props.uri, _links[0]));
                  setDisplayQRCode(true);
                }
                setHasSingleLink(hasSingleLink);
              });
            });
          }, function (e) {
            setLoading(false);
            setFetched(true);
            setErrorMessage(props.text.something_went_wrong);
            console.error(e);
          });
          return Promise.resolve(_temp && _temp.then ? _temp.then(function () {}) : void 0);
        } catch (e) {
          return Promise.reject(e);
        }
      };
      initLinks();
    });
  };
  getLinksIfNeeded();
  var rightSelected = mobile ? displayQRCode : !displayQRCode;
  return React.createElement("div", {
    id: WALLETCONNECT_MODAL_ID,
    className: "walletconnect-qrcode__base animated fadeIn"
  }, React.createElement("div", {
    className: "walletconnect-modal__base"
  }, React.createElement(Header, {
    onClose: props.onClose
  }), hasSingleLink && displayQRCode ? React.createElement("div", {
    className: "walletconnect-modal__single_wallet"
  }, React.createElement("a", {
    onClick: function () { return legacyUtils.saveMobileLinkInfo({
      name: links[0].name,
      href: singleLinkHref
    }); },
    href: singleLinkHref,
    rel: "noopener noreferrer",
    target: "_blank"
  }, props.text.connect_with + " " + (hasSingleLink ? links[0].name : "") + " ›")) : android || loading || !loading && links.length ? React.createElement("div", {
    className: ("walletconnect-modal__mobile__toggle" + (rightSelected ? " right__selected" : ""))
  }, React.createElement("div", {
    className: "walletconnect-modal__mobile__toggle_selector"
  }), mobile ? React.createElement(React.Fragment, null, React.createElement("a", {
    onClick: function () { return (setDisplayQRCode(false), getLinksIfNeeded()); }
  }, props.text.mobile), React.createElement("a", {
    onClick: function () { return setDisplayQRCode(true); }
  }, props.text.qrcode)) : React.createElement(React.Fragment, null, React.createElement("a", {
    onClick: function () { return setDisplayQRCode(true); }
  }, props.text.qrcode), React.createElement("a", {
    onClick: function () { return (setDisplayQRCode(false), getLinksIfNeeded()); }
  }, props.text.desktop))) : null, React.createElement("div", null, displayQRCode || !android && !loading && !links.length ? React.createElement(QRCodeDisplay, Object.assign({}, displayProps)) : React.createElement(LinkDisplay, Object.assign({}, displayProps, {
    links: links,
    errorMessage: errorMessage
  })))));
}

var de = {
  choose_preferred_wallet: "Wähle bevorzugte Wallet",
  connect_mobile_wallet: "Verbinde mit Mobile Wallet",
  scan_qrcode_with_wallet: "Scanne den QR-code mit einer WalletConnect kompatiblen Wallet",
  connect: "Verbinden",
  qrcode: "QR-Code",
  mobile: "Mobile",
  desktop: "Desktop",
  copy_to_clipboard: "In die Zwischenablage kopieren",
  copied_to_clipboard: "In die Zwischenablage kopiert!",
  connect_with: "Verbinden mit Hilfe von",
  loading: "Laden...",
  something_went_wrong: "Etwas ist schief gelaufen",
  no_supported_wallets: "Es gibt noch keine unterstützten Wallet",
  no_wallets_found: "keine Wallet gefunden"
};

var en = {
  choose_preferred_wallet: "Choose your preferred wallet",
  connect_mobile_wallet: "Connect to Mobile Wallet",
  scan_qrcode_with_wallet: "Scan QR code with a WalletConnect-compatible wallet",
  connect: "Connect",
  qrcode: "QR Code",
  mobile: "Mobile",
  desktop: "Desktop",
  copy_to_clipboard: "Copy to clipboard",
  copied_to_clipboard: "Copied to clipboard!",
  connect_with: "Connect with",
  loading: "Loading...",
  something_went_wrong: "Something went wrong",
  no_supported_wallets: "There are no supported wallets yet",
  no_wallets_found: "No wallets found"
};

var es = {
  choose_preferred_wallet: "Elige tu billetera preferida",
  connect_mobile_wallet: "Conectar a billetera móvil",
  scan_qrcode_with_wallet: "Escanea el código QR con una billetera compatible con WalletConnect",
  connect: "Conectar",
  qrcode: "Código QR",
  mobile: "Móvil",
  desktop: "Desktop",
  copy_to_clipboard: "Copiar",
  copied_to_clipboard: "Copiado!",
  connect_with: "Conectar mediante",
  loading: "Cargando...",
  something_went_wrong: "Algo salió mal",
  no_supported_wallets: "Todavía no hay billeteras compatibles",
  no_wallets_found: "No se encontraron billeteras"
};

var fr = {
  choose_preferred_wallet: "Choisissez votre portefeuille préféré",
  connect_mobile_wallet: "Se connecter au portefeuille mobile",
  scan_qrcode_with_wallet: "Scannez le QR code avec un portefeuille compatible WalletConnect",
  connect: "Se connecter",
  qrcode: "QR Code",
  mobile: "Mobile",
  desktop: "Desktop",
  copy_to_clipboard: "Copier",
  copied_to_clipboard: "Copié!",
  connect_with: "Connectez-vous à l'aide de",
  loading: "Chargement...",
  something_went_wrong: "Quelque chose a mal tourné",
  no_supported_wallets: "Il n'y a pas encore de portefeuilles pris en charge",
  no_wallets_found: "Aucun portefeuille trouvé"
};

var ko = {
  choose_preferred_wallet: "원하는 지갑을 선택하세요",
  connect_mobile_wallet: "모바일 지갑과 연결",
  scan_qrcode_with_wallet: "WalletConnect 지원 지갑에서 QR코드를 스캔하세요",
  connect: "연결",
  qrcode: "QR 코드",
  mobile: "모바일",
  desktop: "데스크탑",
  copy_to_clipboard: "클립보드에 복사",
  copied_to_clipboard: "클립보드에 복사되었습니다!",
  connect_with: "와 연결하다",
  loading: "로드 중...",
  something_went_wrong: "문제가 발생했습니다.",
  no_supported_wallets: "아직 지원되는 지갑이 없습니다",
  no_wallets_found: "지갑을 찾을 수 없습니다"
};

var pt = {
  choose_preferred_wallet: "Escolha sua carteira preferida",
  connect_mobile_wallet: "Conectar-se à carteira móvel",
  scan_qrcode_with_wallet: "Ler o código QR com uma carteira compatível com WalletConnect",
  connect: "Conectar",
  qrcode: "Código QR",
  mobile: "Móvel",
  desktop: "Desktop",
  copy_to_clipboard: "Copiar",
  copied_to_clipboard: "Copiado!",
  connect_with: "Ligar por meio de",
  loading: "Carregamento...",
  something_went_wrong: "Algo correu mal",
  no_supported_wallets: "Ainda não há carteiras suportadas",
  no_wallets_found: "Nenhuma carteira encontrada"
};

var zh = {
  choose_preferred_wallet: "选择你的钱包",
  connect_mobile_wallet: "连接至移动端钱包",
  scan_qrcode_with_wallet: "使用兼容 WalletConnect 的钱包扫描二维码",
  connect: "连接",
  qrcode: "二维码",
  mobile: "移动",
  desktop: "桌面",
  copy_to_clipboard: "复制到剪贴板",
  copied_to_clipboard: "复制到剪贴板成功！",
  connect_with: "通过以下方式连接",
  loading: "正在加载...",
  something_went_wrong: "出了问题",
  no_supported_wallets: "目前还没有支持的钱包",
  no_wallets_found: "没有找到钱包"
};

var fa = {
  choose_preferred_wallet: "کیف پول مورد نظر خود را انتخاب کنید",
  connect_mobile_wallet: "به کیف پول موبایل وصل شوید",
  scan_qrcode_with_wallet: "کد QR را با یک کیف پول سازگار با WalletConnect اسکن کنید",
  connect: "اتصال",
  qrcode: "کد QR",
  mobile: "سیار",
  desktop: "دسکتاپ",
  copy_to_clipboard: "کپی به کلیپ بورد",
  copied_to_clipboard: "در کلیپ بورد کپی شد!",
  connect_with: "ارتباط با",
  loading: "...بارگذاری",
  something_went_wrong: "مشکلی پیش آمد",
  no_supported_wallets: "هنوز هیچ کیف پول پشتیبانی شده ای وجود ندارد",
  no_wallets_found: "هیچ کیف پولی پیدا نشد"
};

var languages = {
  de: de,
  en: en,
  es: es,
  fr: fr,
  ko: ko,
  pt: pt,
  zh: zh,
  fa: fa
};

function injectStyleSheet() {
  var doc = legacyUtils.getDocumentOrThrow();
  var prev = doc.getElementById(WALLETCONNECT_STYLE_ID);
  if (prev) {
    doc.head.removeChild(prev);
  }
  var style = doc.createElement("style");
  style.setAttribute("id", WALLETCONNECT_STYLE_ID);
  style.innerText = WALLETCONNECT_STYLE_SHEET;
  doc.head.appendChild(style);
}
function renderWrapper() {
  var doc = legacyUtils.getDocumentOrThrow();
  var wrapper = doc.createElement("div");
  wrapper.setAttribute("id", WALLETCONNECT_WRAPPER_ID);
  doc.body.appendChild(wrapper);
  return wrapper;
}
function triggerCloseAnimation() {
  var doc = legacyUtils.getDocumentOrThrow();
  var modal = doc.getElementById(WALLETCONNECT_MODAL_ID);
  if (modal) {
    modal.className = modal.className.replace("fadeIn", "fadeOut");
    setTimeout(function () {
      var wrapper = doc.getElementById(WALLETCONNECT_WRAPPER_ID);
      if (wrapper) {
        doc.body.removeChild(wrapper);
      }
    }, ANIMATION_DURATION);
  }
}
function getWrappedCallback(cb) {
  return function () {
    triggerCloseAnimation();
    if (cb) {
      cb();
    }
  };
}
function getText() {
  var lang = legacyUtils.getNavigatorOrThrow().language.split("-")[0] || "en";
  return languages[lang] || languages["en"];
}
function open$1(uri, cb, qrcodeModalOptions) {
  injectStyleSheet();
  var wrapper = renderWrapper();
  React.render(React.createElement(Modal, {
    text: getText(),
    uri: uri,
    onClose: getWrappedCallback(cb),
    qrcodeModalOptions: qrcodeModalOptions
  }), wrapper);
}
function close$1() {
  triggerCloseAnimation();
}

var isNode = function () { return typeof process !== "undefined" && typeof process.versions !== "undefined" && typeof process.versions.node !== "undefined"; };
function open$2(uri, cb, qrcodeModalOptions) {
  console.log(uri);
  if (isNode()) {
    open(uri);
  } else {
    open$1(uri, cb, qrcodeModalOptions);
  }
}
function close$2() {
  if (isNode()) ; else {
    close$1();
  }
}
var index = {
  open: open$2,
  close: close$2
};

module.exports = index;
//# sourceMappingURL=index.js.map


/***/ }),

/***/ 95232:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __webpack_require__(97316);
const events_1 = tslib_1.__importDefault(__webpack_require__(82361));
const jsonrpc_provider_1 = __webpack_require__(32207);
const jsonrpc_http_connection_1 = __webpack_require__(65286);
const legacy_types_1 = __webpack_require__(97117);
const legacy_utils_1 = __webpack_require__(10603);
const signer_1 = __webpack_require__(9619);
class WalletConnectProvider {
    constructor(opts) {
        this.events = new events_1.default();
        this.rpc = { infuraId: opts === null || opts === void 0 ? void 0 : opts.infuraId, custom: opts === null || opts === void 0 ? void 0 : opts.rpc };
        this.signer = new jsonrpc_provider_1.JsonRpcProvider(new signer_1.SignerConnection(opts));
        const chainId = this.signer.connection.chainId || (opts === null || opts === void 0 ? void 0 : opts.chainId) || 1;
        this.http = this.setHttpProvider(chainId);
        this.registerEventListeners();
    }
    get connected() {
        return this.signer.connection.connected;
    }
    get connector() {
        return this.signer.connection.connector;
    }
    get accounts() {
        return this.signer.connection.accounts;
    }
    get chainId() {
        return this.signer.connection.chainId;
    }
    get rpcUrl() {
        var _a;
        return ((_a = this.http) === null || _a === void 0 ? void 0 : _a.connection).url || "";
    }
    request(args) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            switch (args.method) {
                case "eth_requestAccounts":
                    yield this.connect();
                    return this.signer.connection.accounts;
                case "eth_accounts":
                    return this.signer.connection.accounts;
                case "eth_chainId":
                    return this.signer.connection.chainId;
                default:
                    break;
            }
            if (legacy_types_1.SIGNING_METHODS.includes(args.method)) {
                return this.signer.request(args);
            }
            if (typeof this.http === "undefined") {
                throw new Error(`Cannot request JSON-RPC method (${args.method}) without provided rpc url`);
            }
            return this.http.request(args);
        });
    }
    sendAsync(args, callback) {
        this.request(args)
            .then(response => callback(null, response))
            .catch(error => callback(error, undefined));
    }
    enable() {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const accounts = yield this.request({ method: "eth_requestAccounts" });
            return accounts;
        });
    }
    connect() {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (!this.signer.connection.connected) {
                yield this.signer.connect();
            }
        });
    }
    disconnect() {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (this.signer.connection.connected) {
                yield this.signer.disconnect();
            }
        });
    }
    on(event, listener) {
        this.events.on(event, listener);
    }
    once(event, listener) {
        this.events.once(event, listener);
    }
    removeListener(event, listener) {
        this.events.removeListener(event, listener);
    }
    off(event, listener) {
        this.events.off(event, listener);
    }
    get isWalletConnect() {
        return true;
    }
    registerEventListeners() {
        this.signer.connection.on("accountsChanged", accounts => {
            this.events.emit("accountsChanged", accounts);
        });
        this.signer.connection.on("chainChanged", chainId => {
            this.http = this.setHttpProvider(chainId);
            this.events.emit("chainChanged", chainId);
        });
        this.signer.on("disconnect", () => {
            this.events.emit("disconnect");
        });
    }
    setHttpProvider(chainId) {
        const rpcUrl = legacy_utils_1.getRpcUrl(chainId, this.rpc);
        if (typeof rpcUrl === "undefined")
            return undefined;
        const http = new jsonrpc_provider_1.JsonRpcProvider(new jsonrpc_http_connection_1.HttpConnection(rpcUrl));
        return http;
    }
}
exports["default"] = WalletConnectProvider;
//# sourceMappingURL=index.js.map

/***/ }),

/***/ 9619:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.SignerConnection = void 0;
const tslib_1 = __webpack_require__(97316);
const events_1 = tslib_1.__importDefault(__webpack_require__(82361));
const legacy_client_1 = tslib_1.__importDefault(__webpack_require__(42496));
const legacy_modal_1 = tslib_1.__importDefault(__webpack_require__(8569));
const jsonrpc_types_1 = __webpack_require__(7057);
const jsonrpc_utils_1 = __webpack_require__(25815);
class SignerConnection extends jsonrpc_types_1.IJsonRpcConnection {
    constructor(opts) {
        super();
        this.events = new events_1.default();
        this.accounts = [];
        this.chainId = 1;
        this.pending = false;
        this.bridge = "https://bridge.walletconnect.org";
        this.qrcode = true;
        this.qrcodeModalOptions = undefined;
        this.opts = opts;
        this.chainId = (opts === null || opts === void 0 ? void 0 : opts.chainId) || this.chainId;
        this.wc = this.register(opts);
    }
    get connected() {
        return typeof this.wc !== "undefined" && this.wc.connected;
    }
    get connecting() {
        return this.pending;
    }
    get connector() {
        this.wc = this.register(this.opts);
        return this.wc;
    }
    on(event, listener) {
        this.events.on(event, listener);
    }
    once(event, listener) {
        this.events.once(event, listener);
    }
    off(event, listener) {
        this.events.off(event, listener);
    }
    removeListener(event, listener) {
        this.events.removeListener(event, listener);
    }
    open(chainId) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (this.connected) {
                this.onOpen();
                return;
            }
            return new Promise((resolve, reject) => {
                this.on("error", err => {
                    reject(err);
                });
                this.on("open", () => {
                    resolve();
                });
                this.create(chainId);
            });
        });
    }
    close() {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (typeof this.wc === "undefined")
                return;
            if (this.wc.connected) {
                this.wc.killSession();
            }
            this.onClose();
        });
    }
    send(payload) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            this.wc = this.register(this.opts);
            if (!this.connected)
                yield this.open();
            this.sendPayload(payload)
                .then((res) => this.events.emit("payload", res))
                .catch(e => this.events.emit("payload", jsonrpc_utils_1.formatJsonRpcError(payload.id, e.message)));
        });
    }
    register(opts) {
        if (this.wc)
            return this.wc;
        this.opts = opts || this.opts;
        this.bridge = (opts === null || opts === void 0 ? void 0 : opts.connector) ? opts.connector.bridge
            : (opts === null || opts === void 0 ? void 0 : opts.bridge) || "https://bridge.walletconnect.org";
        this.qrcode = typeof (opts === null || opts === void 0 ? void 0 : opts.qrcode) === "undefined" || opts.qrcode !== false;
        this.chainId = typeof (opts === null || opts === void 0 ? void 0 : opts.chainId) !== "undefined" ? opts.chainId : this.chainId;
        this.qrcodeModalOptions = opts === null || opts === void 0 ? void 0 : opts.qrcodeModalOptions;
        const connectorOpts = {
            bridge: this.bridge,
            qrcodeModal: this.qrcode ? legacy_modal_1.default : undefined,
            qrcodeModalOptions: this.qrcodeModalOptions,
            storageId: opts === null || opts === void 0 ? void 0 : opts.storageId,
            signingMethods: opts === null || opts === void 0 ? void 0 : opts.signingMethods,
            clientMeta: opts === null || opts === void 0 ? void 0 : opts.clientMeta,
        };
        this.wc =
            typeof (opts === null || opts === void 0 ? void 0 : opts.connector) !== "undefined" ? opts.connector : new legacy_client_1.default(connectorOpts);
        if (typeof this.wc === "undefined") {
            throw new Error("Failed to register WalletConnect connector");
        }
        if (this.wc.accounts.length) {
            this.accounts = this.wc.accounts;
        }
        if (this.wc.chainId) {
            this.chainId = this.wc.chainId;
        }
        this.registerConnectorEvents();
        return this.wc;
    }
    onOpen(wc) {
        this.pending = false;
        if (wc) {
            this.wc = wc;
        }
        this.events.emit("open");
    }
    onClose() {
        this.pending = false;
        if (this.wc) {
            this.wc = undefined;
        }
        this.events.emit("close");
    }
    onError(payload, message = "Failed or Rejected Request", code = -32000) {
        const errorPayload = {
            id: payload.id,
            jsonrpc: payload.jsonrpc,
            error: { code, message },
        };
        this.events.emit("payload", errorPayload);
        return errorPayload;
    }
    create(chainId) {
        this.wc = this.register(this.opts);
        this.chainId = chainId || this.chainId;
        if (this.connected || this.pending)
            return;
        this.pending = true;
        this.registerConnectorEvents();
        this.wc
            .createSession({ chainId: this.chainId })
            .then(() => this.events.emit("created"))
            .catch((e) => this.events.emit("error", e));
    }
    registerConnectorEvents() {
        this.wc = this.register(this.opts);
        this.wc.on("connect", (err) => {
            var _a, _b;
            if (err) {
                this.events.emit("error", err);
                return;
            }
            this.accounts = ((_a = this.wc) === null || _a === void 0 ? void 0 : _a.accounts) || [];
            this.chainId = ((_b = this.wc) === null || _b === void 0 ? void 0 : _b.chainId) || this.chainId;
            this.onOpen();
        });
        this.wc.on("disconnect", (err) => {
            if (err) {
                this.events.emit("error", err);
                return;
            }
            this.onClose();
        });
        this.wc.on("modal_closed", () => {
            this.events.emit("error", new Error("User closed modal"));
        });
        this.wc.on("session_update", (error, payload) => {
            const { accounts, chainId } = payload.params[0];
            if (!this.accounts || (accounts && this.accounts !== accounts)) {
                this.accounts = accounts;
                this.events.emit("accountsChanged", accounts);
            }
            if (!this.chainId || (chainId && this.chainId !== chainId)) {
                this.chainId = chainId;
                this.events.emit("chainChanged", chainId);
            }
        });
    }
    sendPayload(payload) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            this.wc = this.register(this.opts);
            try {
                const response = yield this.wc.unsafeSend(payload);
                return this.sanitizeResponse(response);
            }
            catch (error) {
                return this.onError(payload, error.message);
            }
        });
    }
    sanitizeResponse(response) {
        return typeof response.error !== "undefined" &&
            typeof response.error.code === "undefined"
            ? jsonrpc_utils_1.formatJsonRpcError(response.id, response.error.message, response.error.data)
            : response;
    }
}
exports.SignerConnection = SignerConnection;
exports["default"] = SignerConnection;
//# sourceMappingURL=signer.js.map

/***/ }),

/***/ 68688:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ERROR_QRCODE_MODAL_USER_CLOSED = exports.ERROR_QRCODE_MODAL_NOT_PROVIDED = exports.ERROR_INVALID_URI = exports.ERROR_INVALID_RESPONSE = exports.ERROR_MISSING_REQUIRED = exports.ERROR_MISSING_ID = exports.ERROR_MISSING_METHOD = exports.ERROR_MISSING_ERROR = exports.ERROR_MISSING_RESULT = exports.ERROR_MISSING_JSON_RPC = exports.ERROR_SESSION_REJECTED = exports.ERROR_SESSION_DISCONNECTED = exports.ERROR_SESSION_CONNECTED = void 0;
exports.ERROR_SESSION_CONNECTED = "Session currently connected";
exports.ERROR_SESSION_DISCONNECTED = "Session currently disconnected";
exports.ERROR_SESSION_REJECTED = "Session Rejected";
exports.ERROR_MISSING_JSON_RPC = "Missing JSON RPC response";
exports.ERROR_MISSING_RESULT = `JSON-RPC success response must include "result" field`;
exports.ERROR_MISSING_ERROR = `JSON-RPC error response must include "error" field`;
exports.ERROR_MISSING_METHOD = `JSON RPC request must have valid "method" value`;
exports.ERROR_MISSING_ID = `JSON RPC request must have valid "id" value`;
exports.ERROR_MISSING_REQUIRED = "Missing one of the required parameters: bridge / uri / session";
exports.ERROR_INVALID_RESPONSE = "JSON RPC response format is invalid";
exports.ERROR_INVALID_URI = "URI format is invalid";
exports.ERROR_QRCODE_MODAL_NOT_PROVIDED = "QRCode Modal not provided";
exports.ERROR_QRCODE_MODAL_USER_CLOSED = "User close QRCode Modal";
//# sourceMappingURL=errors.js.map

/***/ }),

/***/ 56668:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.reservedEvents = exports.RESERVED_EVENTS = void 0;
exports.RESERVED_EVENTS = [
    "session_request",
    "session_update",
    "exchange_key",
    "connect",
    "disconnect",
    "display_uri",
    "modal_closed",
    "transport_open",
    "transport_close",
    "transport_error",
];
exports.reservedEvents = exports.RESERVED_EVENTS;
//# sourceMappingURL=events.js.map

/***/ }),

/***/ 29125:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __webpack_require__(97316);
tslib_1.__exportStar(__webpack_require__(68688), exports);
tslib_1.__exportStar(__webpack_require__(56668), exports);
tslib_1.__exportStar(__webpack_require__(70379), exports);
tslib_1.__exportStar(__webpack_require__(75967), exports);
tslib_1.__exportStar(__webpack_require__(98269), exports);
//# sourceMappingURL=index.js.map

/***/ }),

/***/ 70379:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.stateMethods = exports.signingMethods = exports.STATE_METHODS = exports.SIGNING_METHODS = exports.WALLET_METHODS = void 0;
exports.WALLET_METHODS = [
    "wallet_addEthereumChain",
    "wallet_switchEthereumChain",
    "wallet_getPermissions",
    "wallet_requestPermissions",
    "wallet_registerOnboarding",
    "wallet_watchAsset",
    "wallet_scanQRCode",
];
exports.SIGNING_METHODS = [
    "eth_sendTransaction",
    "eth_signTransaction",
    "eth_sign",
    "eth_signTypedData",
    "eth_signTypedData_v1",
    "eth_signTypedData_v2",
    "eth_signTypedData_v3",
    "eth_signTypedData_v4",
    "personal_sign",
    ...exports.WALLET_METHODS,
];
exports.STATE_METHODS = ["eth_accounts", "eth_chainId", "net_version"];
exports.signingMethods = exports.SIGNING_METHODS;
exports.stateMethods = exports.STATE_METHODS;
//# sourceMappingURL=jsonrpc.js.map

/***/ }),

/***/ 75967:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.mobileLinkChoiceKey = exports.MOBILE_LINK_CHOICE_KEY = void 0;
exports.MOBILE_LINK_CHOICE_KEY = "WALLETCONNECT_DEEPLINK_CHOICE";
exports.mobileLinkChoiceKey = exports.MOBILE_LINK_CHOICE_KEY;
//# sourceMappingURL=mobile.js.map

/***/ }),

/***/ 98269:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.infuraNetworks = exports.INFURA_NETWORKS = void 0;
exports.INFURA_NETWORKS = {
    1: "mainnet",
    3: "ropsten",
    4: "rinkeby",
    5: "goerli",
    42: "kovan",
};
exports.infuraNetworks = exports.INFURA_NETWORKS;
//# sourceMappingURL=networks.js.map

/***/ }),

/***/ 43665:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
//# sourceMappingURL=crypto.js.map

/***/ }),

/***/ 72220:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
//# sourceMappingURL=ethereum.js.map

/***/ }),

/***/ 76732:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.IEvents = void 0;
class IEvents {
}
exports.IEvents = IEvents;
//# sourceMappingURL=events.js.map

/***/ }),

/***/ 97117:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __webpack_require__(97316);
tslib_1.__exportStar(__webpack_require__(43665), exports);
tslib_1.__exportStar(__webpack_require__(29125), exports);
tslib_1.__exportStar(__webpack_require__(72220), exports);
tslib_1.__exportStar(__webpack_require__(76732), exports);
tslib_1.__exportStar(__webpack_require__(93126), exports);
tslib_1.__exportStar(__webpack_require__(2768), exports);
tslib_1.__exportStar(__webpack_require__(1280), exports);
tslib_1.__exportStar(__webpack_require__(60774), exports);
tslib_1.__exportStar(__webpack_require__(27425), exports);
tslib_1.__exportStar(__webpack_require__(13554), exports);
tslib_1.__exportStar(__webpack_require__(78841), exports);
//# sourceMappingURL=index.js.map

/***/ }),

/***/ 93126:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
//# sourceMappingURL=jsonrpc.js.map

/***/ }),

/***/ 2768:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
//# sourceMappingURL=network.js.map

/***/ }),

/***/ 1280:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
//# sourceMappingURL=protocol.js.map

/***/ }),

/***/ 60774:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
//# sourceMappingURL=qrcode.js.map

/***/ }),

/***/ 27425:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
//# sourceMappingURL=registry.js.map

/***/ }),

/***/ 13554:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
//# sourceMappingURL=socket.js.map

/***/ }),

/***/ 78841:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
//# sourceMappingURL=storage.js.map

/***/ }),

/***/ 21129:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.convertNumberToHex = exports.convertNumberToUtf8 = exports.convertNumberToArrayBuffer = exports.convertNumberToBuffer = exports.convertHexToNumber = exports.convertHexToUtf8 = exports.convertHexToArrayBuffer = exports.convertHexToBuffer = exports.convertUtf8ToNumber = exports.convertUtf8ToHex = exports.convertUtf8ToBuffer = exports.convertUtf8ToArrayBuffer = exports.concatBuffers = exports.convertBufferToNumber = exports.convertBufferToHex = exports.convertBufferToUtf8 = exports.convertBufferToArrayBuffer = exports.concatArrayBuffers = exports.convertArrayBufferToNumber = exports.convertArrayBufferToHex = exports.convertArrayBufferToUtf8 = exports.convertArrayBufferToBuffer = void 0;
const tslib_1 = __webpack_require__(97316);
const encoding = tslib_1.__importStar(__webpack_require__(2921));
function convertArrayBufferToBuffer(arrBuf) {
    return encoding.arrayToBuffer(new Uint8Array(arrBuf));
}
exports.convertArrayBufferToBuffer = convertArrayBufferToBuffer;
function convertArrayBufferToUtf8(arrBuf) {
    return encoding.arrayToUtf8(new Uint8Array(arrBuf));
}
exports.convertArrayBufferToUtf8 = convertArrayBufferToUtf8;
function convertArrayBufferToHex(arrBuf, noPrefix) {
    return encoding.arrayToHex(new Uint8Array(arrBuf), !noPrefix);
}
exports.convertArrayBufferToHex = convertArrayBufferToHex;
function convertArrayBufferToNumber(arrBuf) {
    return encoding.arrayToNumber(new Uint8Array(arrBuf));
}
exports.convertArrayBufferToNumber = convertArrayBufferToNumber;
function concatArrayBuffers(...args) {
    return encoding.hexToArray(args.map(b => encoding.arrayToHex(new Uint8Array(b))).join("")).buffer;
}
exports.concatArrayBuffers = concatArrayBuffers;
function convertBufferToArrayBuffer(buf) {
    return encoding.bufferToArray(buf).buffer;
}
exports.convertBufferToArrayBuffer = convertBufferToArrayBuffer;
function convertBufferToUtf8(buf) {
    return encoding.bufferToUtf8(buf);
}
exports.convertBufferToUtf8 = convertBufferToUtf8;
function convertBufferToHex(buf, noPrefix) {
    return encoding.bufferToHex(buf, !noPrefix);
}
exports.convertBufferToHex = convertBufferToHex;
function convertBufferToNumber(buf) {
    return encoding.bufferToNumber(buf);
}
exports.convertBufferToNumber = convertBufferToNumber;
function concatBuffers(...args) {
    return encoding.concatBuffers(...args);
}
exports.concatBuffers = concatBuffers;
function convertUtf8ToArrayBuffer(utf8) {
    return encoding.utf8ToArray(utf8).buffer;
}
exports.convertUtf8ToArrayBuffer = convertUtf8ToArrayBuffer;
function convertUtf8ToBuffer(utf8) {
    return encoding.utf8ToBuffer(utf8);
}
exports.convertUtf8ToBuffer = convertUtf8ToBuffer;
function convertUtf8ToHex(utf8, noPrefix) {
    return encoding.utf8ToHex(utf8, !noPrefix);
}
exports.convertUtf8ToHex = convertUtf8ToHex;
function convertUtf8ToNumber(utf8) {
    return encoding.utf8ToNumber(utf8);
}
exports.convertUtf8ToNumber = convertUtf8ToNumber;
function convertHexToBuffer(hex) {
    return encoding.hexToBuffer(hex);
}
exports.convertHexToBuffer = convertHexToBuffer;
function convertHexToArrayBuffer(hex) {
    return encoding.hexToArray(hex).buffer;
}
exports.convertHexToArrayBuffer = convertHexToArrayBuffer;
function convertHexToUtf8(hex) {
    return encoding.hexToUtf8(hex);
}
exports.convertHexToUtf8 = convertHexToUtf8;
function convertHexToNumber(hex) {
    return encoding.hexToNumber(hex);
}
exports.convertHexToNumber = convertHexToNumber;
function convertNumberToBuffer(num) {
    return encoding.numberToBuffer(num);
}
exports.convertNumberToBuffer = convertNumberToBuffer;
function convertNumberToArrayBuffer(num) {
    return encoding.numberToArray(num).buffer;
}
exports.convertNumberToArrayBuffer = convertNumberToArrayBuffer;
function convertNumberToUtf8(num) {
    return encoding.numberToUtf8(num);
}
exports.convertNumberToUtf8 = convertNumberToUtf8;
function convertNumberToHex(num, noPrefix) {
    return encoding.numberToHex(Number(num), !noPrefix);
}
exports.convertNumberToHex = convertNumberToHex;
//# sourceMappingURL=encoding.js.map

/***/ }),

/***/ 11222:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.isBrowser = exports.isNode = exports.isMobile = exports.isIOS = exports.isAndroid = exports.detectOS = exports.detectEnv = void 0;
const detect_browser_1 = __webpack_require__(70573);
const window_1 = __webpack_require__(9110);
function detectEnv(userAgent) {
    return detect_browser_1.detect(userAgent);
}
exports.detectEnv = detectEnv;
function detectOS() {
    const env = detectEnv();
    return env && env.os ? env.os : undefined;
}
exports.detectOS = detectOS;
function isAndroid() {
    const os = detectOS();
    return os ? os.toLowerCase().includes("android") : false;
}
exports.isAndroid = isAndroid;
function isIOS() {
    const os = detectOS();
    return os
        ? os.toLowerCase().includes("ios") ||
            (os.toLowerCase().includes("mac") && navigator.maxTouchPoints > 1)
        : false;
}
exports.isIOS = isIOS;
function isMobile() {
    const os = detectOS();
    return os ? isAndroid() || isIOS() : false;
}
exports.isMobile = isMobile;
function isNode() {
    const env = detectEnv();
    const result = env && env.name ? env.name.toLowerCase() === "node" : false;
    return result;
}
exports.isNode = isNode;
function isBrowser() {
    const result = !isNode() && !!window_1.getNavigator();
    return result;
}
exports.isBrowser = isBrowser;
//# sourceMappingURL=env.js.map

/***/ }),

/***/ 10603:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __webpack_require__(97316);
tslib_1.__exportStar(__webpack_require__(21129), exports);
tslib_1.__exportStar(__webpack_require__(11222), exports);
tslib_1.__exportStar(__webpack_require__(99741), exports);
tslib_1.__exportStar(__webpack_require__(64560), exports);
tslib_1.__exportStar(__webpack_require__(97783), exports);
tslib_1.__exportStar(__webpack_require__(39012), exports);
tslib_1.__exportStar(__webpack_require__(15235), exports);
tslib_1.__exportStar(__webpack_require__(84019), exports);
tslib_1.__exportStar(__webpack_require__(19582), exports);
tslib_1.__exportStar(__webpack_require__(71612), exports);
tslib_1.__exportStar(__webpack_require__(44290), exports);
tslib_1.__exportStar(__webpack_require__(4967), exports);
tslib_1.__exportStar(__webpack_require__(9110), exports);
//# sourceMappingURL=index.js.map

/***/ }),

/***/ 99741:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.safeJsonStringify = exports.safeJsonParse = void 0;
const tslib_1 = __webpack_require__(97316);
const safeJson = tslib_1.__importStar(__webpack_require__(51738));
exports.safeJsonParse = safeJson.safeJsonParse;
exports.safeJsonStringify = safeJson.safeJsonStringify;
//# sourceMappingURL=json.js.map

/***/ }),

/***/ 64560:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.removeLocal = exports.getLocal = exports.setLocal = void 0;
const json_1 = __webpack_require__(99741);
const window_1 = __webpack_require__(9110);
function setLocal(key, data) {
    const raw = json_1.safeJsonStringify(data);
    const local = window_1.getLocalStorage();
    if (local) {
        local.setItem(key, raw);
    }
}
exports.setLocal = setLocal;
function getLocal(key) {
    let data = null;
    let raw = null;
    const local = window_1.getLocalStorage();
    if (local) {
        raw = local.getItem(key);
    }
    data = raw ? json_1.safeJsonParse(raw) : raw;
    return data;
}
exports.getLocal = getLocal;
function removeLocal(key) {
    const local = window_1.getLocalStorage();
    if (local) {
        local.removeItem(key);
    }
}
exports.removeLocal = removeLocal;
//# sourceMappingURL=local.js.map

/***/ }),

/***/ 97783:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getClientMeta = void 0;
const tslib_1 = __webpack_require__(97316);
const windowMetadata = tslib_1.__importStar(__webpack_require__(18478));
function getClientMeta() {
    return windowMetadata.getWindowMetadata();
}
exports.getClientMeta = getClientMeta;
//# sourceMappingURL=meta.js.map

/***/ }),

/***/ 39012:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getRpcUrl = exports.getInfuraRpcUrl = exports.logDeprecationWarning = exports.uuid = exports.payloadId = exports.removeHexLeadingZeros = exports.removeHexPrefix = exports.addHexPrefix = exports.sanitizeHex = void 0;
const tslib_1 = __webpack_require__(97316);
const encoding = tslib_1.__importStar(__webpack_require__(2921));
const jsonRpcUtils = tslib_1.__importStar(__webpack_require__(25815));
const legacy_types_1 = __webpack_require__(97117);
function sanitizeHex(hex) {
    return encoding.sanitizeHex(hex);
}
exports.sanitizeHex = sanitizeHex;
function addHexPrefix(hex) {
    return encoding.addHexPrefix(hex);
}
exports.addHexPrefix = addHexPrefix;
function removeHexPrefix(hex) {
    return encoding.removeHexPrefix(hex);
}
exports.removeHexPrefix = removeHexPrefix;
function removeHexLeadingZeros(hex) {
    return encoding.removeHexLeadingZeros(encoding.addHexPrefix(hex));
}
exports.removeHexLeadingZeros = removeHexLeadingZeros;
exports.payloadId = jsonRpcUtils.payloadId;
function uuid() {
    const result = ((a, b) => {
        for (b = a = ""; a++ < 36; b += (a * 51) & 52 ? (a ^ 15 ? 8 ^ (Math.random() * (a ^ 20 ? 16 : 4)) : 4).toString(16) : "-") {
        }
        return b;
    })();
    return result;
}
exports.uuid = uuid;
function logDeprecationWarning() {
    console.warn("DEPRECATION WARNING: This WalletConnect client library will be deprecated in favor of @walletconnect/client. Please check docs.walletconnect.org to learn more about this migration!");
}
exports.logDeprecationWarning = logDeprecationWarning;
function getInfuraRpcUrl(chainId, infuraId) {
    let rpcUrl;
    const network = legacy_types_1.INFURA_NETWORKS[chainId];
    if (network) {
        rpcUrl = `https://${network}.infura.io/v3/${infuraId}`;
    }
    return rpcUrl;
}
exports.getInfuraRpcUrl = getInfuraRpcUrl;
function getRpcUrl(chainId, rpc) {
    let rpcUrl;
    const infuraUrl = getInfuraRpcUrl(chainId, rpc.infuraId);
    if (rpc.custom && rpc.custom[chainId]) {
        rpcUrl = rpc.custom[chainId];
    }
    else if (infuraUrl) {
        rpcUrl = infuraUrl;
    }
    return rpcUrl;
}
exports.getRpcUrl = getRpcUrl;
//# sourceMappingURL=misc.js.map

/***/ }),

/***/ 15235:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getMobileLinkRegistry = exports.getMobileRegistryEntry = exports.saveMobileLinkInfo = exports.formatIOSMobile = void 0;
const legacy_types_1 = __webpack_require__(97117);
const local_1 = __webpack_require__(64560);
function formatIOSMobile(uri, entry) {
    const encodedUri = encodeURIComponent(uri);
    return entry.universalLink
        ? `${entry.universalLink}/wc?uri=${encodedUri}`
        : entry.deepLink
            ? `${entry.deepLink}${entry.deepLink.endsWith(":") ? "//" : "/"}wc?uri=${encodedUri}`
            : "";
}
exports.formatIOSMobile = formatIOSMobile;
function saveMobileLinkInfo(data) {
    const focusUri = data.href.split("?")[0];
    local_1.setLocal(legacy_types_1.MOBILE_LINK_CHOICE_KEY, Object.assign(Object.assign({}, data), { href: focusUri }));
}
exports.saveMobileLinkInfo = saveMobileLinkInfo;
function getMobileRegistryEntry(registry, name) {
    return registry.filter((entry) => entry.name.toLowerCase().includes(name.toLowerCase()))[0];
}
exports.getMobileRegistryEntry = getMobileRegistryEntry;
function getMobileLinkRegistry(registry, whitelist) {
    let links = registry;
    if (whitelist) {
        links = whitelist.map((name) => getMobileRegistryEntry(registry, name)).filter(Boolean);
    }
    return links;
}
exports.getMobileLinkRegistry = getMobileLinkRegistry;
//# sourceMappingURL=mobile.js.map

/***/ }),

/***/ 84019:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.formatRpcError = exports.promisify = void 0;
const tslib_1 = __webpack_require__(97316);
function promisify(originalFn, thisArg) {
    const promisifiedFunction = (...callArgs) => tslib_1.__awaiter(this, void 0, void 0, function* () {
        return new Promise((resolve, reject) => {
            const callback = (err, data) => {
                if (err === null || typeof err === "undefined") {
                    reject(err);
                }
                resolve(data);
            };
            originalFn.apply(thisArg, [...callArgs, callback]);
        });
    });
    return promisifiedFunction;
}
exports.promisify = promisify;
function formatRpcError(error) {
    const message = error.message || "Failed or Rejected Request";
    let code = -32000;
    if (error && !error.code) {
        switch (message) {
            case "Parse error":
                code = -32700;
                break;
            case "Invalid request":
                code = -32600;
                break;
            case "Method not found":
                code = -32601;
                break;
            case "Invalid params":
                code = -32602;
                break;
            case "Internal error":
                code = -32603;
                break;
            default:
                code = -32000;
                break;
        }
    }
    const result = {
        code,
        message,
    };
    if (error.data) {
        result.data = error.data;
    }
    return result;
}
exports.formatRpcError = formatRpcError;
//# sourceMappingURL=payload.js.map

/***/ }),

/***/ 19582:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.formatMobileRegistry = exports.formatMobileRegistryEntry = exports.getDappRegistryUrl = exports.getWalletRegistryUrl = void 0;
const API_URL = "https://registry.walletconnect.com";
function getWalletRegistryUrl() {
    return API_URL + "/api/v2/wallets";
}
exports.getWalletRegistryUrl = getWalletRegistryUrl;
function getDappRegistryUrl() {
    return API_URL + "/api/v2/dapps";
}
exports.getDappRegistryUrl = getDappRegistryUrl;
function formatMobileRegistryEntry(entry, platform = "mobile") {
    var _a;
    return {
        name: entry.name || "",
        shortName: entry.metadata.shortName || "",
        color: entry.metadata.colors.primary || "",
        logo: (_a = entry.image_url.sm) !== null && _a !== void 0 ? _a : "",
        universalLink: entry[platform].universal || "",
        deepLink: entry[platform].native || "",
    };
}
exports.formatMobileRegistryEntry = formatMobileRegistryEntry;
function formatMobileRegistry(registry, platform = "mobile") {
    return Object.values(registry)
        .filter(entry => !!entry[platform].universal || !!entry[platform].native)
        .map(entry => formatMobileRegistryEntry(entry, platform));
}
exports.formatMobileRegistry = formatMobileRegistry;
//# sourceMappingURL=registry.js.map

/***/ }),

/***/ 71612:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.parseWalletConnectUri = exports.isWalletConnectSession = void 0;
const url_1 = __webpack_require__(44290);
function isWalletConnectSession(object) {
    return typeof object.bridge !== "undefined";
}
exports.isWalletConnectSession = isWalletConnectSession;
function parseWalletConnectUri(str) {
    const pathStart = str.indexOf(":");
    const pathEnd = str.indexOf("?") !== -1 ? str.indexOf("?") : undefined;
    const protocol = str.substring(0, pathStart);
    const path = str.substring(pathStart + 1, pathEnd);
    function parseRequiredParams(path) {
        const separator = "@";
        const values = path.split(separator);
        const requiredParams = {
            handshakeTopic: values[0],
            version: parseInt(values[1], 10),
        };
        return requiredParams;
    }
    const requiredParams = parseRequiredParams(path);
    const queryString = typeof pathEnd !== "undefined" ? str.substr(pathEnd) : "";
    function parseQueryParams(queryString) {
        const result = url_1.parseQueryString(queryString);
        const parameters = {
            key: result.key || "",
            bridge: result.bridge || "",
        };
        return parameters;
    }
    const queryParams = parseQueryParams(queryString);
    const result = Object.assign(Object.assign({ protocol }, requiredParams), queryParams);
    return result;
}
exports.parseWalletConnectUri = parseWalletConnectUri;
//# sourceMappingURL=session.js.map

/***/ }),

/***/ 44290:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.formatQueryString = exports.parseQueryString = exports.appendToQueryString = exports.getQueryString = void 0;
const tslib_1 = __webpack_require__(97316);
const queryStringUtils = tslib_1.__importStar(__webpack_require__(97305));
function getQueryString(url) {
    const pathEnd = url.indexOf("?") !== -1 ? url.indexOf("?") : undefined;
    const queryString = typeof pathEnd !== "undefined" ? url.substr(pathEnd) : "";
    return queryString;
}
exports.getQueryString = getQueryString;
function appendToQueryString(queryString, newQueryParams) {
    let queryParams = parseQueryString(queryString);
    queryParams = Object.assign(Object.assign({}, queryParams), newQueryParams);
    queryString = formatQueryString(queryParams);
    return queryString;
}
exports.appendToQueryString = appendToQueryString;
function parseQueryString(queryString) {
    return queryStringUtils.parse(queryString);
}
exports.parseQueryString = parseQueryString;
function formatQueryString(queryParams) {
    return queryStringUtils.stringify(queryParams);
}
exports.formatQueryString = formatQueryString;
//# sourceMappingURL=url.js.map

/***/ }),

/***/ 4967:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.isSilentPayload = exports.isReservedEvent = exports.isInternalEvent = exports.isJsonRpcResponseError = exports.isJsonRpcResponseSuccess = exports.isJsonRpcRequest = exports.isJsonRpcSubscription = exports.isHexString = exports.getEncoding = exports.getType = exports.isArrayBuffer = exports.isTypedArray = exports.isBuffer = exports.isEmptyArray = exports.isEmptyString = void 0;
const tslib_1 = __webpack_require__(97316);
const encoding = tslib_1.__importStar(__webpack_require__(2921));
const legacy_types_1 = __webpack_require__(97117);
function isEmptyString(value) {
    return value === "" || (typeof value === "string" && value.trim() === "");
}
exports.isEmptyString = isEmptyString;
function isEmptyArray(array) {
    return !(array && array.length);
}
exports.isEmptyArray = isEmptyArray;
function isBuffer(val) {
    return encoding.isBuffer(val);
}
exports.isBuffer = isBuffer;
function isTypedArray(val) {
    return encoding.isTypedArray(val);
}
exports.isTypedArray = isTypedArray;
function isArrayBuffer(val) {
    return encoding.isArrayBuffer(val);
}
exports.isArrayBuffer = isArrayBuffer;
function getType(val) {
    return encoding.getType(val);
}
exports.getType = getType;
function getEncoding(val) {
    return encoding.getEncoding(val);
}
exports.getEncoding = getEncoding;
function isHexString(value, length) {
    return encoding.isHexString(value, length);
}
exports.isHexString = isHexString;
function isJsonRpcSubscription(object) {
    return typeof object.params === "object";
}
exports.isJsonRpcSubscription = isJsonRpcSubscription;
function isJsonRpcRequest(object) {
    return typeof object.method !== "undefined";
}
exports.isJsonRpcRequest = isJsonRpcRequest;
function isJsonRpcResponseSuccess(object) {
    return typeof object.result !== "undefined";
}
exports.isJsonRpcResponseSuccess = isJsonRpcResponseSuccess;
function isJsonRpcResponseError(object) {
    return typeof object.error !== "undefined";
}
exports.isJsonRpcResponseError = isJsonRpcResponseError;
function isInternalEvent(object) {
    return typeof object.event !== "undefined";
}
exports.isInternalEvent = isInternalEvent;
function isReservedEvent(event) {
    return legacy_types_1.RESERVED_EVENTS.includes(event) || event.startsWith("wc_");
}
exports.isReservedEvent = isReservedEvent;
function isSilentPayload(request) {
    if (request.method.startsWith("wc_")) {
        return true;
    }
    if (legacy_types_1.SIGNING_METHODS.includes(request.method)) {
        return false;
    }
    return true;
}
exports.isSilentPayload = isSilentPayload;
//# sourceMappingURL=validators.js.map

/***/ }),

/***/ 9110:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getLocalStorage = exports.getLocalStorageOrThrow = exports.getCrypto = exports.getCryptoOrThrow = exports.getLocation = exports.getLocationOrThrow = exports.getNavigator = exports.getNavigatorOrThrow = exports.getDocument = exports.getDocumentOrThrow = exports.getFromWindowOrThrow = exports.getFromWindow = void 0;
const tslib_1 = __webpack_require__(97316);
const windowGetters = tslib_1.__importStar(__webpack_require__(57351));
exports.getFromWindow = windowGetters.getFromWindow;
exports.getFromWindowOrThrow = windowGetters.getFromWindowOrThrow;
exports.getDocumentOrThrow = windowGetters.getDocumentOrThrow;
exports.getDocument = windowGetters.getDocument;
exports.getNavigatorOrThrow = windowGetters.getNavigatorOrThrow;
exports.getNavigator = windowGetters.getNavigator;
exports.getLocationOrThrow = windowGetters.getLocationOrThrow;
exports.getLocation = windowGetters.getLocation;
exports.getCryptoOrThrow = windowGetters.getCryptoOrThrow;
exports.getCrypto = windowGetters.getCrypto;
exports.getLocalStorageOrThrow = windowGetters.getLocalStorageOrThrow;
exports.getLocalStorage = windowGetters.getLocalStorage;
//# sourceMappingURL=window.js.map

/***/ }),

/***/ 10651:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.randomBytes = void 0;
const tslib_1 = __webpack_require__(97316);
const crypto_1 = tslib_1.__importDefault(__webpack_require__(6113));
const encoding_1 = __webpack_require__(2921);
function randomBytes(length) {
    const buf = crypto_1.default.randomBytes(length);
    return encoding_1.bufferToArray(buf);
}
exports.randomBytes = randomBytes;
//# sourceMappingURL=index.js.map

/***/ }),

/***/ 90343:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

"use strict";


var deselectCurrent = __webpack_require__(80664);

var clipboardToIE11Formatting = {
  "text/plain": "Text",
  "text/html": "Url",
  "default": "Text"
}

var defaultMessage = "Copy to clipboard: #{key}, Enter";

function format(message) {
  var copyKey = (/mac os x/i.test(navigator.userAgent) ? "⌘" : "Ctrl") + "+C";
  return message.replace(/#{\s*key\s*}/g, copyKey);
}

function copy(text, options) {
  var debug,
    message,
    reselectPrevious,
    range,
    selection,
    mark,
    success = false;
  if (!options) {
    options = {};
  }
  debug = options.debug || false;
  try {
    reselectPrevious = deselectCurrent();

    range = document.createRange();
    selection = document.getSelection();

    mark = document.createElement("span");
    mark.textContent = text;
    // avoid screen readers from reading out loud the text
    mark.ariaHidden = "true"
    // reset user styles for span element
    mark.style.all = "unset";
    // prevents scrolling to the end of the page
    mark.style.position = "fixed";
    mark.style.top = 0;
    mark.style.clip = "rect(0, 0, 0, 0)";
    // used to preserve spaces and line breaks
    mark.style.whiteSpace = "pre";
    // do not inherit user-select (it may be `none`)
    mark.style.webkitUserSelect = "text";
    mark.style.MozUserSelect = "text";
    mark.style.msUserSelect = "text";
    mark.style.userSelect = "text";
    mark.addEventListener("copy", function(e) {
      e.stopPropagation();
      if (options.format) {
        e.preventDefault();
        if (typeof e.clipboardData === "undefined") { // IE 11
          debug && console.warn("unable to use e.clipboardData");
          debug && console.warn("trying IE specific stuff");
          window.clipboardData.clearData();
          var format = clipboardToIE11Formatting[options.format] || clipboardToIE11Formatting["default"]
          window.clipboardData.setData(format, text);
        } else { // all other browsers
          e.clipboardData.clearData();
          e.clipboardData.setData(options.format, text);
        }
      }
      if (options.onCopy) {
        e.preventDefault();
        options.onCopy(e.clipboardData);
      }
    });

    document.body.appendChild(mark);

    range.selectNodeContents(mark);
    selection.addRange(range);

    var successful = document.execCommand("copy");
    if (!successful) {
      throw new Error("copy command was unsuccessful");
    }
    success = true;
  } catch (err) {
    debug && console.error("unable to copy using execCommand: ", err);
    debug && console.warn("trying IE specific stuff");
    try {
      window.clipboardData.setData(options.format || "text", text);
      options.onCopy && options.onCopy(window.clipboardData);
      success = true;
    } catch (err) {
      debug && console.error("unable to copy using clipboardData: ", err);
      debug && console.error("falling back to prompt");
      message = format("message" in options ? options.message : defaultMessage);
      window.prompt(message, text);
    }
  } finally {
    if (selection) {
      if (typeof selection.removeRange == "function") {
        selection.removeRange(range);
      } else {
        selection.removeAllRanges();
      }
    }

    if (mark) {
      document.body.removeChild(mark);
    }
    reselectPrevious();
  }

  return success;
}

module.exports = copy;


/***/ }),

/***/ 38943:
/***/ ((module) => {

module.exports      = isTypedArray
isTypedArray.strict = isStrictTypedArray
isTypedArray.loose  = isLooseTypedArray

var toString = Object.prototype.toString
var names = {
    '[object Int8Array]': true
  , '[object Int16Array]': true
  , '[object Int32Array]': true
  , '[object Uint8Array]': true
  , '[object Uint8ClampedArray]': true
  , '[object Uint16Array]': true
  , '[object Uint32Array]': true
  , '[object Float32Array]': true
  , '[object Float64Array]': true
}

function isTypedArray(arr) {
  return (
       isStrictTypedArray(arr)
    || isLooseTypedArray(arr)
  )
}

function isStrictTypedArray(arr) {
  return (
       arr instanceof Int8Array
    || arr instanceof Int16Array
    || arr instanceof Int32Array
    || arr instanceof Uint8Array
    || arr instanceof Uint8ClampedArray
    || arr instanceof Uint16Array
    || arr instanceof Uint32Array
    || arr instanceof Float32Array
    || arr instanceof Float64Array
  )
}

function isLooseTypedArray(arr) {
  return names[toString.call(arr)]
}


/***/ }),

/***/ 80134:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

var n=__webpack_require__(28076),t=__webpack_require__(74609);function e(n,t){for(var e in t)n[e]=t[e];return n}function r(n,t){for(var e in n)if("__source"!==e&&!(e in t))return!0;for(var r in t)if("__source"!==r&&n[r]!==t[r])return!0;return!1}function u(n,t){return n===t&&(0!==n||1/n==1/t)||n!=n&&t!=t}function o(n){this.props=n}function i(t,e){function u(n){var t=this.props.ref,u=t==n.ref;return!u&&t&&(t.call?t(null):t.current=null),e?!e(this.props,n)||!u:r(this.props,n)}function o(e){return this.shouldComponentUpdate=u,n.createElement(t,e)}return o.displayName="Memo("+(t.displayName||t.name)+")",o.prototype.isReactComponent=!0,o.__f=!0,o}(o.prototype=new n.Component).isPureReactComponent=!0,o.prototype.shouldComponentUpdate=function(n,t){return r(this.props,n)||r(this.state,t)};var c=n.options.__b;n.options.__b=function(n){n.type&&n.type.__f&&n.ref&&(n.props.ref=n.ref,n.ref=null),c&&c(n)};var l="undefined"!=typeof Symbol&&Symbol.for&&Symbol.for("react.forward_ref")||3911;function f(n){function t(t){var r=e({},t);return delete r.ref,n(r,t.ref||null)}return t.$$typeof=l,t.render=t,t.prototype.isReactComponent=t.__f=!0,t.displayName="ForwardRef("+(n.displayName||n.name)+")",t}var a=function(t,e){return null==t?null:n.toChildArray(n.toChildArray(t).map(e))},s={map:a,forEach:a,count:function(t){return t?n.toChildArray(t).length:0},only:function(t){var e=n.toChildArray(t);if(1!==e.length)throw"Children.only";return e[0]},toArray:n.toChildArray},p=n.options.__e;n.options.__e=function(n,t,e,r){if(n.then)for(var u,o=t;o=o.__;)if((u=o.__c)&&u.__c)return null==t.__e&&(t.__e=e.__e,t.__k=e.__k),u.__c(n,t);p(n,t,e,r)};var h=n.options.unmount;function v(n,t,r){return n&&(n.__c&&n.__c.__H&&(n.__c.__H.__.forEach(function(n){"function"==typeof n.__c&&n.__c()}),n.__c.__H=null),null!=(n=e({},n)).__c&&(n.__c.__P===r&&(n.__c.__P=t),n.__c=null),n.__k=n.__k&&n.__k.map(function(n){return v(n,t,r)})),n}function d(n,t,e){return n&&(n.__v=null,n.__k=n.__k&&n.__k.map(function(n){return d(n,t,e)}),n.__c&&n.__c.__P===t&&(n.__e&&e.insertBefore(n.__e,n.__d),n.__c.__e=!0,n.__c.__P=e)),n}function m(){this.__u=0,this.t=null,this.__b=null}function x(n){var t=n.__.__c;return t&&t.__a&&t.__a(n)}function b(t){var e,r,u;function o(o){if(e||(e=t()).then(function(n){r=n.default||n},function(n){u=n}),u)throw u;if(!r)throw e;return n.createElement(r,o)}return o.displayName="Lazy",o.__f=!0,o}function _(){this.u=null,this.o=null}n.options.unmount=function(n){var t=n.__c;t&&t.__R&&t.__R(),t&&!0===n.__h&&(n.type=null),h&&h(n)},(m.prototype=new n.Component).__c=function(n,t){var e=t.__c,r=this;null==r.t&&(r.t=[]),r.t.push(e);var u=x(r.__v),o=!1,i=function(){o||(o=!0,e.__R=null,u?u(c):c())};e.__R=i;var c=function(){if(!--r.__u){if(r.state.__a){var n=r.state.__a;r.__v.__k[0]=d(n,n.__c.__P,n.__c.__O)}var t;for(r.setState({__a:r.__b=null});t=r.t.pop();)t.forceUpdate()}},l=!0===t.__h;r.__u++||l||r.setState({__a:r.__b=r.__v.__k[0]}),n.then(i,i)},m.prototype.componentWillUnmount=function(){this.t=[]},m.prototype.render=function(t,e){if(this.__b){if(this.__v.__k){var r=document.createElement("div"),u=this.__v.__k[0].__c;this.__v.__k[0]=v(this.__b,r,u.__O=u.__P)}this.__b=null}var o=e.__a&&n.createElement(n.Fragment,null,t.fallback);return o&&(o.__h=null),[n.createElement(n.Fragment,null,e.__a?null:t.children),o]};var y=function(n,t,e){if(++e[1]===e[0]&&n.o.delete(t),n.props.revealOrder&&("t"!==n.props.revealOrder[0]||!n.o.size))for(e=n.u;e;){for(;e.length>3;)e.pop()();if(e[1]<e[0])break;n.u=e=e[2]}};function g(n){return this.getChildContext=function(){return n.context},n.children}function S(t){var e=this,r=t.i;e.componentWillUnmount=function(){n.render(null,e.l),e.l=null,e.i=null},e.i&&e.i!==r&&e.componentWillUnmount(),e.l||(e.i=r,e.l={nodeType:1,parentNode:r,childNodes:[],appendChild:function(n){this.childNodes.push(n),e.i.appendChild(n)},insertBefore:function(n,t){this.childNodes.push(n),e.i.appendChild(n)},removeChild:function(n){this.childNodes.splice(this.childNodes.indexOf(n)>>>1,1),e.i.removeChild(n)}}),n.render(n.createElement(g,{context:e.context},t.__v),e.l)}function C(t,e){var r=n.createElement(S,{__v:t,i:e});return r.containerInfo=e,r}(_.prototype=new n.Component).__a=function(n){var t=this,e=x(t.__v),r=t.o.get(n);return r[0]++,function(u){var o=function(){t.props.revealOrder?(r.push(u),y(t,n,r)):u()};e?e(o):o()}},_.prototype.render=function(t){this.u=null,this.o=new Map;var e=n.toChildArray(t.children);t.revealOrder&&"b"===t.revealOrder[0]&&e.reverse();for(var r=e.length;r--;)this.o.set(e[r],this.u=[1,0,this.u]);return t.children},_.prototype.componentDidUpdate=_.prototype.componentDidMount=function(){var n=this;this.o.forEach(function(t,e){y(n,e,t)})};var E="undefined"!=typeof Symbol&&Symbol.for&&Symbol.for("react.element")||60103,O=/^(?:accent|alignment|arabic|baseline|cap|clip(?!PathU)|color|dominant|fill|flood|font|glyph(?!R)|horiz|image(!S)|letter|lighting|marker(?!H|W|U)|overline|paint|pointer|shape|stop|strikethrough|stroke|text(?!L)|transform|underline|unicode|units|v|vector|vert|word|writing|x(?!C))[A-Z]/,w=/^on(Ani|Tra|Tou|BeforeInp|Compo)/,R=/[A-Z0-9]/g,j="undefined"!=typeof document,N=function(n){return("undefined"!=typeof Symbol&&"symbol"==typeof Symbol()?/fil|che|rad/:/fil|che|ra/).test(n)};function k(t,e,r){return null==e.__k&&(e.textContent=""),n.render(t,e),"function"==typeof r&&r(),t?t.__c:null}function A(t,e,r){return n.hydrate(t,e),"function"==typeof r&&r(),t?t.__c:null}n.Component.prototype.isReactComponent={},["componentWillMount","componentWillReceiveProps","componentWillUpdate"].forEach(function(t){Object.defineProperty(n.Component.prototype,t,{configurable:!0,get:function(){return this["UNSAFE_"+t]},set:function(n){Object.defineProperty(this,t,{configurable:!0,writable:!0,value:n})}})});var T=n.options.event;function F(){}function I(){return this.cancelBubble}function L(){return this.defaultPrevented}n.options.event=function(n){return T&&(n=T(n)),n.persist=F,n.isPropagationStopped=I,n.isDefaultPrevented=L,n.nativeEvent=n};var U,D={enumerable:!1,configurable:!0,get:function(){return this.class}},M=n.options.vnode;n.options.vnode=function(t){"string"==typeof t.type&&function(t){var e=t.props,r=t.type,u={};for(var o in e){var i=e[o];if(!("value"===o&&"defaultValue"in e&&null==i||j&&"children"===o&&"noscript"===r||"class"===o||"className"===o)){var c=o.toLowerCase();"defaultValue"===o&&"value"in e&&null==e.value?o="value":"download"===o&&!0===i?i="":"ondoubleclick"===c?o="ondblclick":"onchange"!==c||"input"!==r&&"textarea"!==r||N(e.type)?"onfocus"===c?o="onfocusin":"onblur"===c?o="onfocusout":w.test(o)?o=c:-1===r.indexOf("-")&&O.test(o)?o=o.replace(R,"-$&").toLowerCase():null===i&&(i=void 0):c=o="oninput","oninput"===c&&u[o=c]&&(o="oninputCapture"),u[o]=i}}"select"==r&&u.multiple&&Array.isArray(u.value)&&(u.value=n.toChildArray(e.children).forEach(function(n){n.props.selected=-1!=u.value.indexOf(n.props.value)})),"select"==r&&null!=u.defaultValue&&(u.value=n.toChildArray(e.children).forEach(function(n){n.props.selected=u.multiple?-1!=u.defaultValue.indexOf(n.props.value):u.defaultValue==n.props.value})),e.class&&!e.className?(u.class=e.class,Object.defineProperty(u,"className",D)):(e.className&&!e.class||e.class&&e.className)&&(u.class=u.className=e.className),t.props=u}(t),t.$$typeof=E,M&&M(t)};var V=n.options.__r;n.options.__r=function(n){V&&V(n),U=n.__c};var W=n.options.diffed;n.options.diffed=function(n){W&&W(n);var t=n.props,e=n.__e;null!=e&&"textarea"===n.type&&"value"in t&&t.value!==e.value&&(e.value=null==t.value?"":t.value),U=null};var P={ReactCurrentDispatcher:{current:{readContext:function(n){return U.__n[n.__c].props.value}}}};function z(t){return n.createElement.bind(null,t)}function B(n){return!!n&&n.$$typeof===E}function q(t){return B(t)&&t.type===n.Fragment}function H(t){return B(t)?n.cloneElement.apply(null,arguments):t}function Z(t){return!!t.__k&&(n.render(null,t),!0)}function Y(n){return n&&(n.base||1===n.nodeType&&n)||null}var $=function(n,t){return n(t)},G=function(n,t){return n(t)},J=n.Fragment;function K(n){n()}function Q(n){return n}function X(){return[!1,K]}var nn=t.useLayoutEffect,tn=B;function en(n,e){var r=e(),o=t.useState({p:{__:r,h:e}}),i=o[0].p,c=o[1];return t.useLayoutEffect(function(){i.__=r,i.h=e,u(i.__,e())||c({p:i})},[n,r,e]),t.useEffect(function(){return u(i.__,i.h())||c({p:i}),n(function(){u(i.__,i.h())||c({p:i})})},[n]),r}var rn={useState:t.useState,useId:t.useId,useReducer:t.useReducer,useEffect:t.useEffect,useLayoutEffect:t.useLayoutEffect,useInsertionEffect:nn,useTransition:X,useDeferredValue:Q,useSyncExternalStore:en,startTransition:K,useRef:t.useRef,useImperativeHandle:t.useImperativeHandle,useMemo:t.useMemo,useCallback:t.useCallback,useContext:t.useContext,useDebugValue:t.useDebugValue,version:"17.0.2",Children:s,render:k,hydrate:A,unmountComponentAtNode:Z,createPortal:C,createElement:n.createElement,createContext:n.createContext,createFactory:z,cloneElement:H,createRef:n.createRef,Fragment:n.Fragment,isValidElement:B,isElement:tn,isFragment:q,findDOMNode:Y,Component:n.Component,PureComponent:o,memo:i,forwardRef:f,flushSync:G,unstable_batchedUpdates:$,StrictMode:J,Suspense:m,SuspenseList:_,lazy:b,__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED:P};Object.defineProperty(exports, "Component", ({enumerable:!0,get:function(){return n.Component}})),Object.defineProperty(exports, "Fragment", ({enumerable:!0,get:function(){return n.Fragment}})),Object.defineProperty(exports, "createContext", ({enumerable:!0,get:function(){return n.createContext}})),Object.defineProperty(exports, "createElement", ({enumerable:!0,get:function(){return n.createElement}})),Object.defineProperty(exports, "createRef", ({enumerable:!0,get:function(){return n.createRef}})),exports.Children=s,exports.PureComponent=o,exports.StrictMode=J,exports.Suspense=m,exports.SuspenseList=_,exports.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED=P,exports.cloneElement=H,exports.createFactory=z,exports.createPortal=C,exports["default"]=rn,exports.findDOMNode=Y,exports.flushSync=G,exports.forwardRef=f,exports.hydrate=A,exports.isElement=tn,exports.isFragment=q,exports.isValidElement=B,exports.lazy=b,exports.memo=i,exports.render=k,exports.startTransition=K,exports.unmountComponentAtNode=Z,exports.unstable_batchedUpdates=$,exports.useDeferredValue=Q,exports.useInsertionEffect=nn,exports.useSyncExternalStore=en,exports.useTransition=X,exports.version="17.0.2",Object.keys(t).forEach(function(n){"default"===n||exports.hasOwnProperty(n)||Object.defineProperty(exports,n,{enumerable:!0,get:function(){return t[n]}})});
//# sourceMappingURL=compat.js.map


/***/ }),

/***/ 97305:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

const strictUriEncode = __webpack_require__(65485);
const decodeComponent = __webpack_require__(4613);
const splitOnFirst = __webpack_require__(6785);
const filterObject = __webpack_require__(28881);

const isNullOrUndefined = value => value === null || value === undefined;

function encoderForArrayFormat(options) {
	switch (options.arrayFormat) {
		case 'index':
			return key => (result, value) => {
				const index = result.length;

				if (
					value === undefined ||
					(options.skipNull && value === null) ||
					(options.skipEmptyString && value === '')
				) {
					return result;
				}

				if (value === null) {
					return [...result, [encode(key, options), '[', index, ']'].join('')];
				}

				return [
					...result,
					[encode(key, options), '[', encode(index, options), ']=', encode(value, options)].join('')
				];
			};

		case 'bracket':
			return key => (result, value) => {
				if (
					value === undefined ||
					(options.skipNull && value === null) ||
					(options.skipEmptyString && value === '')
				) {
					return result;
				}

				if (value === null) {
					return [...result, [encode(key, options), '[]'].join('')];
				}

				return [...result, [encode(key, options), '[]=', encode(value, options)].join('')];
			};

		case 'comma':
		case 'separator':
			return key => (result, value) => {
				if (value === null || value === undefined || value.length === 0) {
					return result;
				}

				if (result.length === 0) {
					return [[encode(key, options), '=', encode(value, options)].join('')];
				}

				return [[result, encode(value, options)].join(options.arrayFormatSeparator)];
			};

		default:
			return key => (result, value) => {
				if (
					value === undefined ||
					(options.skipNull && value === null) ||
					(options.skipEmptyString && value === '')
				) {
					return result;
				}

				if (value === null) {
					return [...result, encode(key, options)];
				}

				return [...result, [encode(key, options), '=', encode(value, options)].join('')];
			};
	}
}

function parserForArrayFormat(options) {
	let result;

	switch (options.arrayFormat) {
		case 'index':
			return (key, value, accumulator) => {
				result = /\[(\d*)\]$/.exec(key);

				key = key.replace(/\[\d*\]$/, '');

				if (!result) {
					accumulator[key] = value;
					return;
				}

				if (accumulator[key] === undefined) {
					accumulator[key] = {};
				}

				accumulator[key][result[1]] = value;
			};

		case 'bracket':
			return (key, value, accumulator) => {
				result = /(\[\])$/.exec(key);
				key = key.replace(/\[\]$/, '');

				if (!result) {
					accumulator[key] = value;
					return;
				}

				if (accumulator[key] === undefined) {
					accumulator[key] = [value];
					return;
				}

				accumulator[key] = [].concat(accumulator[key], value);
			};

		case 'comma':
		case 'separator':
			return (key, value, accumulator) => {
				const isArray = typeof value === 'string' && value.includes(options.arrayFormatSeparator);
				const isEncodedArray = (typeof value === 'string' && !isArray && decode(value, options).includes(options.arrayFormatSeparator));
				value = isEncodedArray ? decode(value, options) : value;
				const newValue = isArray || isEncodedArray ? value.split(options.arrayFormatSeparator).map(item => decode(item, options)) : value === null ? value : decode(value, options);
				accumulator[key] = newValue;
			};

		default:
			return (key, value, accumulator) => {
				if (accumulator[key] === undefined) {
					accumulator[key] = value;
					return;
				}

				accumulator[key] = [].concat(accumulator[key], value);
			};
	}
}

function validateArrayFormatSeparator(value) {
	if (typeof value !== 'string' || value.length !== 1) {
		throw new TypeError('arrayFormatSeparator must be single character string');
	}
}

function encode(value, options) {
	if (options.encode) {
		return options.strict ? strictUriEncode(value) : encodeURIComponent(value);
	}

	return value;
}

function decode(value, options) {
	if (options.decode) {
		return decodeComponent(value);
	}

	return value;
}

function keysSorter(input) {
	if (Array.isArray(input)) {
		return input.sort();
	}

	if (typeof input === 'object') {
		return keysSorter(Object.keys(input))
			.sort((a, b) => Number(a) - Number(b))
			.map(key => input[key]);
	}

	return input;
}

function removeHash(input) {
	const hashStart = input.indexOf('#');
	if (hashStart !== -1) {
		input = input.slice(0, hashStart);
	}

	return input;
}

function getHash(url) {
	let hash = '';
	const hashStart = url.indexOf('#');
	if (hashStart !== -1) {
		hash = url.slice(hashStart);
	}

	return hash;
}

function extract(input) {
	input = removeHash(input);
	const queryStart = input.indexOf('?');
	if (queryStart === -1) {
		return '';
	}

	return input.slice(queryStart + 1);
}

function parseValue(value, options) {
	if (options.parseNumbers && !Number.isNaN(Number(value)) && (typeof value === 'string' && value.trim() !== '')) {
		value = Number(value);
	} else if (options.parseBooleans && value !== null && (value.toLowerCase() === 'true' || value.toLowerCase() === 'false')) {
		value = value.toLowerCase() === 'true';
	}

	return value;
}

function parse(query, options) {
	options = Object.assign({
		decode: true,
		sort: true,
		arrayFormat: 'none',
		arrayFormatSeparator: ',',
		parseNumbers: false,
		parseBooleans: false
	}, options);

	validateArrayFormatSeparator(options.arrayFormatSeparator);

	const formatter = parserForArrayFormat(options);

	// Create an object with no prototype
	const ret = Object.create(null);

	if (typeof query !== 'string') {
		return ret;
	}

	query = query.trim().replace(/^[?#&]/, '');

	if (!query) {
		return ret;
	}

	for (const param of query.split('&')) {
		if (param === '') {
			continue;
		}

		let [key, value] = splitOnFirst(options.decode ? param.replace(/\+/g, ' ') : param, '=');

		// Missing `=` should be `null`:
		// http://w3.org/TR/2012/WD-url-20120524/#collect-url-parameters
		value = value === undefined ? null : ['comma', 'separator'].includes(options.arrayFormat) ? value : decode(value, options);
		formatter(decode(key, options), value, ret);
	}

	for (const key of Object.keys(ret)) {
		const value = ret[key];
		if (typeof value === 'object' && value !== null) {
			for (const k of Object.keys(value)) {
				value[k] = parseValue(value[k], options);
			}
		} else {
			ret[key] = parseValue(value, options);
		}
	}

	if (options.sort === false) {
		return ret;
	}

	return (options.sort === true ? Object.keys(ret).sort() : Object.keys(ret).sort(options.sort)).reduce((result, key) => {
		const value = ret[key];
		if (Boolean(value) && typeof value === 'object' && !Array.isArray(value)) {
			// Sort object keys, not values
			result[key] = keysSorter(value);
		} else {
			result[key] = value;
		}

		return result;
	}, Object.create(null));
}

exports.extract = extract;
exports.parse = parse;

exports.stringify = (object, options) => {
	if (!object) {
		return '';
	}

	options = Object.assign({
		encode: true,
		strict: true,
		arrayFormat: 'none',
		arrayFormatSeparator: ','
	}, options);

	validateArrayFormatSeparator(options.arrayFormatSeparator);

	const shouldFilter = key => (
		(options.skipNull && isNullOrUndefined(object[key])) ||
		(options.skipEmptyString && object[key] === '')
	);

	const formatter = encoderForArrayFormat(options);

	const objectCopy = {};

	for (const key of Object.keys(object)) {
		if (!shouldFilter(key)) {
			objectCopy[key] = object[key];
		}
	}

	const keys = Object.keys(objectCopy);

	if (options.sort !== false) {
		keys.sort(options.sort);
	}

	return keys.map(key => {
		const value = object[key];

		if (value === undefined) {
			return '';
		}

		if (value === null) {
			return encode(key, options);
		}

		if (Array.isArray(value)) {
			return value
				.reduce(formatter(key), [])
				.join('&');
		}

		return encode(key, options) + '=' + encode(value, options);
	}).filter(x => x.length > 0).join('&');
};

exports.parseUrl = (url, options) => {
	options = Object.assign({
		decode: true
	}, options);

	const [url_, hash] = splitOnFirst(url, '#');

	return Object.assign(
		{
			url: url_.split('?')[0] || '',
			query: parse(extract(url), options)
		},
		options && options.parseFragmentIdentifier && hash ? {fragmentIdentifier: decode(hash, options)} : {}
	);
};

exports.stringifyUrl = (object, options) => {
	options = Object.assign({
		encode: true,
		strict: true
	}, options);

	const url = removeHash(object.url).split('?')[0] || '';
	const queryFromUrl = exports.extract(object.url);
	const parsedQueryFromUrl = exports.parse(queryFromUrl, {sort: false});

	const query = Object.assign(parsedQueryFromUrl, object.query);
	let queryString = exports.stringify(query, options);
	if (queryString) {
		queryString = `?${queryString}`;
	}

	let hash = getHash(object.url);
	if (object.fragmentIdentifier) {
		hash = `#${encode(object.fragmentIdentifier, options)}`;
	}

	return `${url}${queryString}${hash}`;
};

exports.pick = (input, filter, options) => {
	options = Object.assign({
		parseFragmentIdentifier: true
	}, options);

	const {url, query, fragmentIdentifier} = exports.parseUrl(input, options);
	return exports.stringifyUrl({
		url,
		query: filterObject(query, filter),
		fragmentIdentifier
	}, options);
};

exports.exclude = (input, filter, options) => {
	const exclusionFilter = Array.isArray(filter) ? key => !filter.includes(key) : (key, value) => !filter(key, value);

	return exports.pick(input, exclusionFilter, options);
};


/***/ }),

/***/ 80664:
/***/ ((module) => {


module.exports = function () {
  var selection = document.getSelection();
  if (!selection.rangeCount) {
    return function () {};
  }
  var active = document.activeElement;

  var ranges = [];
  for (var i = 0; i < selection.rangeCount; i++) {
    ranges.push(selection.getRangeAt(i));
  }

  switch (active.tagName.toUpperCase()) { // .toUpperCase handles XHTML
    case 'INPUT':
    case 'TEXTAREA':
      active.blur();
      break;

    default:
      active = null;
      break;
  }

  selection.removeAllRanges();
  return function () {
    selection.type === 'Caret' &&
    selection.removeAllRanges();

    if (!selection.rangeCount) {
      ranges.forEach(function(range) {
        selection.addRange(range);
      });
    }

    active &&
    active.focus();
  };
};


/***/ }),

/***/ 56144:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

/**
 * Convert a typed array to a Buffer without a copy
 *
 * Author:   Feross Aboukhadijeh <https://feross.org>
 * License:  MIT
 *
 * `npm install typedarray-to-buffer`
 */

var isTypedArray = (__webpack_require__(38943).strict)

module.exports = function typedarrayToBuffer (arr) {
  if (isTypedArray(arr)) {
    // To avoid a copy, use the typed array's underlying ArrayBuffer to back new Buffer
    var buf = Buffer.from(arr.buffer)
    if (arr.byteLength !== arr.buffer.byteLength) {
      // Respect the "view", i.e. byteOffset and byteLength, without doing a copy
      buf = buf.slice(arr.byteOffset, arr.byteOffset + arr.byteLength)
    }
    return buf
  } else {
    // Pass through all other types to `Buffer.from`
    return Buffer.from(arr)
  }
}


/***/ })

};
;
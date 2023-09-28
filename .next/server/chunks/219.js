exports.id = 219;
exports.ids = [219];
exports.modules = {

/***/ 28332:
/***/ ((__unused_webpack_module, exports) => {

"use strict";


// Runtime header offsets
const ID_OFFSET = -8;
const SIZE_OFFSET = -4;

// Runtime ids
const ARRAYBUFFER_ID = 0;
const STRING_ID = 1;
const ARRAYBUFFERVIEW_ID = 2;

// Runtime type information
const ARRAYBUFFERVIEW = 1 << 0;
const ARRAY = 1 << 1;
const SET = (/* unused pure expression or super */ null && (1 << 2));
const MAP = (/* unused pure expression or super */ null && (1 << 3));
const VAL_ALIGN_OFFSET = 5;
const VAL_ALIGN = 1 << VAL_ALIGN_OFFSET;
const VAL_SIGNED = 1 << 10;
const VAL_FLOAT = 1 << 11;
const VAL_NULLABLE = (/* unused pure expression or super */ null && (1 << 12));
const VAL_MANAGED = 1 << 13;
const KEY_ALIGN_OFFSET = 14;
const KEY_ALIGN = 1 << KEY_ALIGN_OFFSET;
const KEY_SIGNED = (/* unused pure expression or super */ null && (1 << 19));
const KEY_FLOAT = (/* unused pure expression or super */ null && (1 << 20));
const KEY_NULLABLE = (/* unused pure expression or super */ null && (1 << 21));
const KEY_MANAGED = (/* unused pure expression or super */ null && (1 << 22));

// Array(BufferView) layout
const ARRAYBUFFERVIEW_BUFFER_OFFSET = 0;
const ARRAYBUFFERVIEW_DATASTART_OFFSET = 4;
const ARRAYBUFFERVIEW_DATALENGTH_OFFSET = 8;
const ARRAYBUFFERVIEW_SIZE = 12;
const ARRAY_LENGTH_OFFSET = 12;
const ARRAY_SIZE = 16;

const BIGINT = typeof BigUint64Array !== "undefined";
const THIS = Symbol();
const CHUNKSIZE = 1024;

/** Gets a string from an U32 and an U16 view on a memory. */
function getStringImpl(buffer, ptr) {
  const U32 = new Uint32Array(buffer);
  const U16 = new Uint16Array(buffer);
  var length = U32[(ptr + SIZE_OFFSET) >>> 2] >>> 1;
  var offset = ptr >>> 1;
  if (length <= CHUNKSIZE) return String.fromCharCode.apply(String, U16.subarray(offset, offset + length));
  const parts = [];
  do {
    const last = U16[offset + CHUNKSIZE - 1];
    const size = last >= 0xD800 && last < 0xDC00 ? CHUNKSIZE - 1 : CHUNKSIZE;
    parts.push(String.fromCharCode.apply(String, U16.subarray(offset, offset += size)));
    length -= size;
  } while (length > CHUNKSIZE);
  return parts.join("") + String.fromCharCode.apply(String, U16.subarray(offset, offset + length));
}

/** Prepares the base module prior to instantiation. */
function preInstantiate(imports) {
  const baseModule = {};

  function getString(memory, ptr) {
    if (!memory) return "<yet unknown>";
    return getStringImpl(memory.buffer, ptr);
  }

  // add common imports used by stdlib for convenience
  const env = (imports.env = imports.env || {});
  env.abort = env.abort || function abort(mesg, file, line, colm) {
    const memory = baseModule.memory || env.memory; // prefer exported, otherwise try imported
    throw Error("abort: " + getString(memory, mesg) + " at " + getString(memory, file) + ":" + line + ":" + colm);
  }
  env.trace = env.trace || function trace(mesg, n) {
    const memory = baseModule.memory || env.memory;
    console.log("trace: " + getString(memory, mesg) + (n ? " " : "") + Array.prototype.slice.call(arguments, 2, 2 + n).join(", "));
  }
  imports.Math = imports.Math || Math;
  imports.Date = imports.Date || Date;

  return baseModule;
}

/** Prepares the final module once instantiation is complete. */
function postInstantiate(baseModule, instance) {
  const rawExports = instance.exports;
  const memory = rawExports.memory;
  const table = rawExports.table;
  const alloc = rawExports["__alloc"];
  const retain = rawExports["__retain"];
  const rttiBase = rawExports["__rtti_base"] || ~0; // oob if not present

  /** Gets the runtime type info for the given id. */
  function getInfo(id) {
    const U32 = new Uint32Array(memory.buffer);
    const count = U32[rttiBase >>> 2];
    if ((id >>>= 0) >= count) throw Error("invalid id: " + id);
    return U32[(rttiBase + 4 >>> 2) + id * 2];
  }

  /** Gets the runtime base id for the given id. */
  function getBase(id) {
    const U32 = new Uint32Array(memory.buffer);
    const count = U32[rttiBase >>> 2];
    if ((id >>>= 0) >= count) throw Error("invalid id: " + id);
    return U32[(rttiBase + 4 >>> 2) + id * 2 + 1];
  }

  /** Gets the runtime alignment of a collection's values. */
  function getValueAlign(info) {
    return 31 - Math.clz32((info >>> VAL_ALIGN_OFFSET) & 31); // -1 if none
  }

  /** Gets the runtime alignment of a collection's keys. */
  function getKeyAlign(info) {
    return 31 - Math.clz32((info >>> KEY_ALIGN_OFFSET) & 31); // -1 if none
  }

  /** Allocates a new string in the module's memory and returns its retained pointer. */
  function __allocString(str) {
    const length = str.length;
    const ptr = alloc(length << 1, STRING_ID);
    const U16 = new Uint16Array(memory.buffer);
    for (var i = 0, p = ptr >>> 1; i < length; ++i) U16[p + i] = str.charCodeAt(i);
    return ptr;
  }

  baseModule.__allocString = __allocString;

  /** Reads a string from the module's memory by its pointer. */
  function __getString(ptr) {
    const buffer = memory.buffer;
    const id = new Uint32Array(buffer)[ptr + ID_OFFSET >>> 2];
    if (id !== STRING_ID) throw Error("not a string: " + ptr);
    return getStringImpl(buffer, ptr);
  }

  baseModule.__getString = __getString;

  /** Gets the view matching the specified alignment, signedness and floatness. */
  function getView(alignLog2, signed, float) {
    const buffer = memory.buffer;
    if (float) {
      switch (alignLog2) {
        case 2: return new Float32Array(buffer);
        case 3: return new Float64Array(buffer);
      }
    } else {
      switch (alignLog2) {
        case 0: return new (signed ? Int8Array : Uint8Array)(buffer);
        case 1: return new (signed ? Int16Array : Uint16Array)(buffer);
        case 2: return new (signed ? Int32Array : Uint32Array)(buffer);
        case 3: return new (signed ? BigInt64Array : BigUint64Array)(buffer);
      }
    }
    throw Error("unsupported align: " + alignLog2);
  }

  /** Allocates a new array in the module's memory and returns its retained pointer. */
  function __allocArray(id, values) {
    const info = getInfo(id);
    if (!(info & (ARRAYBUFFERVIEW | ARRAY))) throw Error("not an array: " + id + " @ " + info);
    const align = getValueAlign(info);
    const length = values.length;
    const buf = alloc(length << align, ARRAYBUFFER_ID);
    const arr = alloc(info & ARRAY ? ARRAY_SIZE : ARRAYBUFFERVIEW_SIZE, id);
    const U32 = new Uint32Array(memory.buffer);
    U32[arr + ARRAYBUFFERVIEW_BUFFER_OFFSET >>> 2] = retain(buf);
    U32[arr + ARRAYBUFFERVIEW_DATASTART_OFFSET >>> 2] = buf;
    U32[arr + ARRAYBUFFERVIEW_DATALENGTH_OFFSET >>> 2] = length << align;
    if (info & ARRAY) U32[arr + ARRAY_LENGTH_OFFSET >>> 2] = length;
    const view = getView(align, info & VAL_SIGNED, info & VAL_FLOAT);
    if (info & VAL_MANAGED) {
      for (let i = 0; i < length; ++i) view[(buf >>> align) + i] = retain(values[i]);
    } else {
      view.set(values, buf >>> align);
    }
    return arr;
  }

  baseModule.__allocArray = __allocArray;

  /** Gets a live view on an array's values in the module's memory. Infers the array type from RTTI. */
  function __getArrayView(arr) {
    const U32 = new Uint32Array(memory.buffer);
    const id = U32[arr + ID_OFFSET >>> 2];
    const info = getInfo(id);
    if (!(info & ARRAYBUFFERVIEW)) throw Error("not an array: " + id);
    const align = getValueAlign(info);
    var buf = U32[arr + ARRAYBUFFERVIEW_DATASTART_OFFSET >>> 2];
    const length = info & ARRAY
      ? U32[arr + ARRAY_LENGTH_OFFSET >>> 2]
      : U32[buf + SIZE_OFFSET >>> 2] >>> align;
    return getView(align, info & VAL_SIGNED, info & VAL_FLOAT)
          .subarray(buf >>>= align, buf + length);
  }

  baseModule.__getArrayView = __getArrayView;

  /** Copies an array's values from the module's memory. Infers the array type from RTTI. */
  function __getArray(arr) {
    const input = __getArrayView(arr);
    const len = input.length;
    const out = new Array(len);
    for (let i = 0; i < len; i++) out[i] = input[i];
    return out;
  }

  baseModule.__getArray = __getArray;

  /** Copies an ArrayBuffer's value from the module's memory. */
  function __getArrayBuffer(ptr) {
    const buffer = memory.buffer;
    const length = new Uint32Array(buffer)[ptr + SIZE_OFFSET >>> 2];
    return buffer.slice(ptr, ptr + length);
  }

  baseModule.__getArrayBuffer = __getArrayBuffer;

  /** Copies a typed array's values from the module's memory. */
  function getTypedArray(Type, alignLog2, ptr) {
    return new Type(getTypedArrayView(Type, alignLog2, ptr));
  }

  /** Gets a live view on a typed array's values in the module's memory. */
  function getTypedArrayView(Type, alignLog2, ptr) {
    const buffer = memory.buffer;
    const U32 = new Uint32Array(buffer);
    const bufPtr = U32[ptr + ARRAYBUFFERVIEW_DATASTART_OFFSET >>> 2];
    return new Type(buffer, bufPtr, U32[bufPtr + SIZE_OFFSET >>> 2] >>> alignLog2);
  }

  baseModule.__getInt8Array = getTypedArray.bind(null, Int8Array, 0);
  baseModule.__getInt8ArrayView = getTypedArrayView.bind(null, Int8Array, 0);
  baseModule.__getUint8Array = getTypedArray.bind(null, Uint8Array, 0);
  baseModule.__getUint8ArrayView = getTypedArrayView.bind(null, Uint8Array, 0);
  baseModule.__getUint8ClampedArray = getTypedArray.bind(null, Uint8ClampedArray, 0);
  baseModule.__getUint8ClampedArrayView = getTypedArrayView.bind(null, Uint8ClampedArray, 0);
  baseModule.__getInt16Array = getTypedArray.bind(null, Int16Array, 1);
  baseModule.__getInt16ArrayView = getTypedArrayView.bind(null, Int16Array, 1);
  baseModule.__getUint16Array = getTypedArray.bind(null, Uint16Array, 1);
  baseModule.__getUint16ArrayView = getTypedArrayView.bind(null, Uint16Array, 1);
  baseModule.__getInt32Array = getTypedArray.bind(null, Int32Array, 2);
  baseModule.__getInt32ArrayView = getTypedArrayView.bind(null, Int32Array, 2);
  baseModule.__getUint32Array = getTypedArray.bind(null, Uint32Array, 2);
  baseModule.__getUint32ArrayView = getTypedArrayView.bind(null, Uint32Array, 2);
  if (BIGINT) {
    baseModule.__getInt64Array = getTypedArray.bind(null, BigInt64Array, 3);
    baseModule.__getInt64ArrayView = getTypedArrayView.bind(null, BigInt64Array, 3);
    baseModule.__getUint64Array = getTypedArray.bind(null, BigUint64Array, 3);
    baseModule.__getUint64ArrayView = getTypedArrayView.bind(null, BigUint64Array, 3);
  }
  baseModule.__getFloat32Array = getTypedArray.bind(null, Float32Array, 2);
  baseModule.__getFloat32ArrayView = getTypedArrayView.bind(null, Float32Array, 2);
  baseModule.__getFloat64Array = getTypedArray.bind(null, Float64Array, 3);
  baseModule.__getFloat64ArrayView = getTypedArrayView.bind(null, Float64Array, 3);

  /** Tests whether an object is an instance of the class represented by the specified base id. */
  function __instanceof(ptr, baseId) {
    const U32 = new Uint32Array(memory.buffer);
    var id = U32[(ptr + ID_OFFSET) >>> 2];
    if (id <= U32[rttiBase >>> 2]) {
      do if (id == baseId) return true;
      while (id = getBase(id));
    }
    return false;
  }

  baseModule.__instanceof = __instanceof;

  // Pull basic exports to baseModule so code in preInstantiate can use them
  baseModule.memory = baseModule.memory || memory;
  baseModule.table  = baseModule.table  || table;

  // Demangle exports and provide the usual utility on the prototype
  return demangle(rawExports, baseModule);
}

function isResponse(o) {
  return typeof Response !== "undefined" && o instanceof Response;
}

/** Asynchronously instantiates an AssemblyScript module from anything that can be instantiated. */
async function instantiate(source, imports) {
  if (isResponse(source = await source)) return instantiateStreaming(source, imports);
  return postInstantiate(
    preInstantiate(imports || (imports = {})),
    await WebAssembly.instantiate(
      source instanceof WebAssembly.Module
        ? source
        : await WebAssembly.compile(source),
      imports
    )
  );
}

exports.instantiate = instantiate;

/** Synchronously instantiates an AssemblyScript module from a WebAssembly.Module or binary buffer. */
function instantiateSync(source, imports) {
  return postInstantiate(
    preInstantiate(imports || (imports = {})),
    new WebAssembly.Instance(
      source instanceof WebAssembly.Module
        ? source
        : new WebAssembly.Module(source),
      imports
    )
  )
}

exports.instantiateSync = instantiateSync;

/** Asynchronously instantiates an AssemblyScript module from a response, i.e. as obtained by `fetch`. */
async function instantiateStreaming(source, imports) {
  if (!WebAssembly.instantiateStreaming) {
    return instantiate(
      isResponse(source = await source)
        ? source.arrayBuffer()
        : source,
      imports
    );
  }
  return postInstantiate(
    preInstantiate(imports || (imports = {})),
    (await WebAssembly.instantiateStreaming(source, imports)).instance
  );
}

exports.instantiateStreaming = instantiateStreaming;

/** Demangles an AssemblyScript module's exports to a friendly object structure. */
function demangle(exports, baseModule) {
  var module = baseModule ? Object.create(baseModule) : {};
  var setArgumentsLength = exports["__argumentsLength"]
    ? function(length) { exports["__argumentsLength"].value = length; }
    : exports["__setArgumentsLength"] || exports["__setargc"] || function() {};
  for (let internalName in exports) {
    if (!Object.prototype.hasOwnProperty.call(exports, internalName)) continue;
    const elem = exports[internalName];
    let parts = internalName.split(".");
    let curr = module;
    while (parts.length > 1) {
      let part = parts.shift();
      if (!Object.prototype.hasOwnProperty.call(curr, part)) curr[part] = {};
      curr = curr[part];
    }
    let name = parts[0];
    let hash = name.indexOf("#");
    if (hash >= 0) {
      let className = name.substring(0, hash);
      let classElem = curr[className];
      if (typeof classElem === "undefined" || !classElem.prototype) {
        let ctor = function(...args) {
          return ctor.wrap(ctor.prototype.constructor(0, ...args));
        };
        ctor.prototype = {
          valueOf: function valueOf() {
            return this[THIS];
          }
        };
        ctor.wrap = function(thisValue) {
          return Object.create(ctor.prototype, { [THIS]: { value: thisValue, writable: false } });
        };
        if (classElem) Object.getOwnPropertyNames(classElem).forEach(name =>
          Object.defineProperty(ctor, name, Object.getOwnPropertyDescriptor(classElem, name))
        );
        curr[className] = ctor;
      }
      name = name.substring(hash + 1);
      curr = curr[className].prototype;
      if (/^(get|set):/.test(name)) {
        if (!Object.prototype.hasOwnProperty.call(curr, name = name.substring(4))) {
          let getter = exports[internalName.replace("set:", "get:")];
          let setter = exports[internalName.replace("get:", "set:")];
          Object.defineProperty(curr, name, {
            get: function() { return getter(this[THIS]); },
            set: function(value) { setter(this[THIS], value); },
            enumerable: true
          });
        }
      } else {
        if (name === 'constructor') {
          (curr[name] = (...args) => {
            setArgumentsLength(args.length);
            return elem(...args);
          }).original = elem;
        } else { // instance method
          (curr[name] = function(...args) { // !
            setArgumentsLength(args.length);
            return elem(this[THIS], ...args);
          }).original = elem;
        }
      }
    } else {
      if (/^(get|set):/.test(name)) {
        if (!Object.prototype.hasOwnProperty.call(curr, name = name.substring(4))) {
          Object.defineProperty(curr, name, {
            get: exports[internalName.replace("set:", "get:")],
            set: exports[internalName.replace("get:", "set:")],
            enumerable: true
          });
        }
      } else if (typeof elem === "function" && elem !== setArgumentsLength) {
        (curr[name] = (...args) => {
          setArgumentsLength(args.length);
          return elem(...args);
        }).original = elem;
      } else {
        curr[name] = elem;
      }
    }
  }
  return module;
}

exports.demangle = demangle;


/***/ }),

/***/ 18670:
/***/ ((module) => {

"use strict";

module.exports = asPromise;

/**
 * Callback as used by {@link util.asPromise}.
 * @typedef asPromiseCallback
 * @type {function}
 * @param {Error|null} error Error, if any
 * @param {...*} params Additional arguments
 * @returns {undefined}
 */

/**
 * Returns a promise from a node-style callback function.
 * @memberof util
 * @param {asPromiseCallback} fn Function to call
 * @param {*} ctx Function context
 * @param {...*} params Function arguments
 * @returns {Promise<*>} Promisified function
 */
function asPromise(fn, ctx/*, varargs */) {
    var params  = new Array(arguments.length - 1),
        offset  = 0,
        index   = 2,
        pending = true;
    while (index < arguments.length)
        params[offset++] = arguments[index++];
    return new Promise(function executor(resolve, reject) {
        params[offset] = function callback(err/*, varargs */) {
            if (pending) {
                pending = false;
                if (err)
                    reject(err);
                else {
                    var params = new Array(arguments.length - 1),
                        offset = 0;
                    while (offset < params.length)
                        params[offset++] = arguments[offset];
                    resolve.apply(null, params);
                }
            }
        };
        try {
            fn.apply(ctx || null, params);
        } catch (err) {
            if (pending) {
                pending = false;
                reject(err);
            }
        }
    });
}


/***/ }),

/***/ 36009:
/***/ ((__unused_webpack_module, exports) => {

"use strict";


/**
 * A minimal base64 implementation for number arrays.
 * @memberof util
 * @namespace
 */
var base64 = exports;

/**
 * Calculates the byte length of a base64 encoded string.
 * @param {string} string Base64 encoded string
 * @returns {number} Byte length
 */
base64.length = function length(string) {
    var p = string.length;
    if (!p)
        return 0;
    var n = 0;
    while (--p % 4 > 1 && string.charAt(p) === "=")
        ++n;
    return Math.ceil(string.length * 3) / 4 - n;
};

// Base64 encoding table
var b64 = new Array(64);

// Base64 decoding table
var s64 = new Array(123);

// 65..90, 97..122, 48..57, 43, 47
for (var i = 0; i < 64;)
    s64[b64[i] = i < 26 ? i + 65 : i < 52 ? i + 71 : i < 62 ? i - 4 : i - 59 | 43] = i++;

/**
 * Encodes a buffer to a base64 encoded string.
 * @param {Uint8Array} buffer Source buffer
 * @param {number} start Source start
 * @param {number} end Source end
 * @returns {string} Base64 encoded string
 */
base64.encode = function encode(buffer, start, end) {
    var parts = null,
        chunk = [];
    var i = 0, // output index
        j = 0, // goto index
        t;     // temporary
    while (start < end) {
        var b = buffer[start++];
        switch (j) {
            case 0:
                chunk[i++] = b64[b >> 2];
                t = (b & 3) << 4;
                j = 1;
                break;
            case 1:
                chunk[i++] = b64[t | b >> 4];
                t = (b & 15) << 2;
                j = 2;
                break;
            case 2:
                chunk[i++] = b64[t | b >> 6];
                chunk[i++] = b64[b & 63];
                j = 0;
                break;
        }
        if (i > 8191) {
            (parts || (parts = [])).push(String.fromCharCode.apply(String, chunk));
            i = 0;
        }
    }
    if (j) {
        chunk[i++] = b64[t];
        chunk[i++] = 61;
        if (j === 1)
            chunk[i++] = 61;
    }
    if (parts) {
        if (i)
            parts.push(String.fromCharCode.apply(String, chunk.slice(0, i)));
        return parts.join("");
    }
    return String.fromCharCode.apply(String, chunk.slice(0, i));
};

var invalidEncoding = "invalid encoding";

/**
 * Decodes a base64 encoded string to a buffer.
 * @param {string} string Source string
 * @param {Uint8Array} buffer Destination buffer
 * @param {number} offset Destination offset
 * @returns {number} Number of bytes written
 * @throws {Error} If encoding is invalid
 */
base64.decode = function decode(string, buffer, offset) {
    var start = offset;
    var j = 0, // goto index
        t;     // temporary
    for (var i = 0; i < string.length;) {
        var c = string.charCodeAt(i++);
        if (c === 61 && j > 1)
            break;
        if ((c = s64[c]) === undefined)
            throw Error(invalidEncoding);
        switch (j) {
            case 0:
                t = c;
                j = 1;
                break;
            case 1:
                buffer[offset++] = t << 2 | (c & 48) >> 4;
                t = c;
                j = 2;
                break;
            case 2:
                buffer[offset++] = (t & 15) << 4 | (c & 60) >> 2;
                t = c;
                j = 3;
                break;
            case 3:
                buffer[offset++] = (t & 3) << 6 | c;
                j = 0;
                break;
        }
    }
    if (j === 1)
        throw Error(invalidEncoding);
    return offset - start;
};

/**
 * Tests if the specified string appears to be base64 encoded.
 * @param {string} string String to test
 * @returns {boolean} `true` if probably base64 encoded, otherwise false
 */
base64.test = function test(string) {
    return /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(string);
};


/***/ }),

/***/ 50107:
/***/ ((module) => {

"use strict";

module.exports = EventEmitter;

/**
 * Constructs a new event emitter instance.
 * @classdesc A minimal event emitter.
 * @memberof util
 * @constructor
 */
function EventEmitter() {

    /**
     * Registered listeners.
     * @type {Object.<string,*>}
     * @private
     */
    this._listeners = {};
}

/**
 * Registers an event listener.
 * @param {string} evt Event name
 * @param {function} fn Listener
 * @param {*} [ctx] Listener context
 * @returns {util.EventEmitter} `this`
 */
EventEmitter.prototype.on = function on(evt, fn, ctx) {
    (this._listeners[evt] || (this._listeners[evt] = [])).push({
        fn  : fn,
        ctx : ctx || this
    });
    return this;
};

/**
 * Removes an event listener or any matching listeners if arguments are omitted.
 * @param {string} [evt] Event name. Removes all listeners if omitted.
 * @param {function} [fn] Listener to remove. Removes all listeners of `evt` if omitted.
 * @returns {util.EventEmitter} `this`
 */
EventEmitter.prototype.off = function off(evt, fn) {
    if (evt === undefined)
        this._listeners = {};
    else {
        if (fn === undefined)
            this._listeners[evt] = [];
        else {
            var listeners = this._listeners[evt];
            for (var i = 0; i < listeners.length;)
                if (listeners[i].fn === fn)
                    listeners.splice(i, 1);
                else
                    ++i;
        }
    }
    return this;
};

/**
 * Emits an event by calling its listeners with the specified arguments.
 * @param {string} evt Event name
 * @param {...*} args Arguments
 * @returns {util.EventEmitter} `this`
 */
EventEmitter.prototype.emit = function emit(evt) {
    var listeners = this._listeners[evt];
    if (listeners) {
        var args = [],
            i = 1;
        for (; i < arguments.length;)
            args.push(arguments[i++]);
        for (i = 0; i < listeners.length;)
            listeners[i].fn.apply(listeners[i++].ctx, args);
    }
    return this;
};


/***/ }),

/***/ 71188:
/***/ ((module) => {

"use strict";


module.exports = factory(factory);

/**
 * Reads / writes floats / doubles from / to buffers.
 * @name util.float
 * @namespace
 */

/**
 * Writes a 32 bit float to a buffer using little endian byte order.
 * @name util.float.writeFloatLE
 * @function
 * @param {number} val Value to write
 * @param {Uint8Array} buf Target buffer
 * @param {number} pos Target buffer offset
 * @returns {undefined}
 */

/**
 * Writes a 32 bit float to a buffer using big endian byte order.
 * @name util.float.writeFloatBE
 * @function
 * @param {number} val Value to write
 * @param {Uint8Array} buf Target buffer
 * @param {number} pos Target buffer offset
 * @returns {undefined}
 */

/**
 * Reads a 32 bit float from a buffer using little endian byte order.
 * @name util.float.readFloatLE
 * @function
 * @param {Uint8Array} buf Source buffer
 * @param {number} pos Source buffer offset
 * @returns {number} Value read
 */

/**
 * Reads a 32 bit float from a buffer using big endian byte order.
 * @name util.float.readFloatBE
 * @function
 * @param {Uint8Array} buf Source buffer
 * @param {number} pos Source buffer offset
 * @returns {number} Value read
 */

/**
 * Writes a 64 bit double to a buffer using little endian byte order.
 * @name util.float.writeDoubleLE
 * @function
 * @param {number} val Value to write
 * @param {Uint8Array} buf Target buffer
 * @param {number} pos Target buffer offset
 * @returns {undefined}
 */

/**
 * Writes a 64 bit double to a buffer using big endian byte order.
 * @name util.float.writeDoubleBE
 * @function
 * @param {number} val Value to write
 * @param {Uint8Array} buf Target buffer
 * @param {number} pos Target buffer offset
 * @returns {undefined}
 */

/**
 * Reads a 64 bit double from a buffer using little endian byte order.
 * @name util.float.readDoubleLE
 * @function
 * @param {Uint8Array} buf Source buffer
 * @param {number} pos Source buffer offset
 * @returns {number} Value read
 */

/**
 * Reads a 64 bit double from a buffer using big endian byte order.
 * @name util.float.readDoubleBE
 * @function
 * @param {Uint8Array} buf Source buffer
 * @param {number} pos Source buffer offset
 * @returns {number} Value read
 */

// Factory function for the purpose of node-based testing in modified global environments
function factory(exports) {

    // float: typed array
    if (typeof Float32Array !== "undefined") (function() {

        var f32 = new Float32Array([ -0 ]),
            f8b = new Uint8Array(f32.buffer),
            le  = f8b[3] === 128;

        function writeFloat_f32_cpy(val, buf, pos) {
            f32[0] = val;
            buf[pos    ] = f8b[0];
            buf[pos + 1] = f8b[1];
            buf[pos + 2] = f8b[2];
            buf[pos + 3] = f8b[3];
        }

        function writeFloat_f32_rev(val, buf, pos) {
            f32[0] = val;
            buf[pos    ] = f8b[3];
            buf[pos + 1] = f8b[2];
            buf[pos + 2] = f8b[1];
            buf[pos + 3] = f8b[0];
        }

        /* istanbul ignore next */
        exports.writeFloatLE = le ? writeFloat_f32_cpy : writeFloat_f32_rev;
        /* istanbul ignore next */
        exports.writeFloatBE = le ? writeFloat_f32_rev : writeFloat_f32_cpy;

        function readFloat_f32_cpy(buf, pos) {
            f8b[0] = buf[pos    ];
            f8b[1] = buf[pos + 1];
            f8b[2] = buf[pos + 2];
            f8b[3] = buf[pos + 3];
            return f32[0];
        }

        function readFloat_f32_rev(buf, pos) {
            f8b[3] = buf[pos    ];
            f8b[2] = buf[pos + 1];
            f8b[1] = buf[pos + 2];
            f8b[0] = buf[pos + 3];
            return f32[0];
        }

        /* istanbul ignore next */
        exports.readFloatLE = le ? readFloat_f32_cpy : readFloat_f32_rev;
        /* istanbul ignore next */
        exports.readFloatBE = le ? readFloat_f32_rev : readFloat_f32_cpy;

    // float: ieee754
    })(); else (function() {

        function writeFloat_ieee754(writeUint, val, buf, pos) {
            var sign = val < 0 ? 1 : 0;
            if (sign)
                val = -val;
            if (val === 0)
                writeUint(1 / val > 0 ? /* positive */ 0 : /* negative 0 */ 2147483648, buf, pos);
            else if (isNaN(val))
                writeUint(2143289344, buf, pos);
            else if (val > 3.4028234663852886e+38) // +-Infinity
                writeUint((sign << 31 | 2139095040) >>> 0, buf, pos);
            else if (val < 1.1754943508222875e-38) // denormal
                writeUint((sign << 31 | Math.round(val / 1.401298464324817e-45)) >>> 0, buf, pos);
            else {
                var exponent = Math.floor(Math.log(val) / Math.LN2),
                    mantissa = Math.round(val * Math.pow(2, -exponent) * 8388608) & 8388607;
                writeUint((sign << 31 | exponent + 127 << 23 | mantissa) >>> 0, buf, pos);
            }
        }

        exports.writeFloatLE = writeFloat_ieee754.bind(null, writeUintLE);
        exports.writeFloatBE = writeFloat_ieee754.bind(null, writeUintBE);

        function readFloat_ieee754(readUint, buf, pos) {
            var uint = readUint(buf, pos),
                sign = (uint >> 31) * 2 + 1,
                exponent = uint >>> 23 & 255,
                mantissa = uint & 8388607;
            return exponent === 255
                ? mantissa
                ? NaN
                : sign * Infinity
                : exponent === 0 // denormal
                ? sign * 1.401298464324817e-45 * mantissa
                : sign * Math.pow(2, exponent - 150) * (mantissa + 8388608);
        }

        exports.readFloatLE = readFloat_ieee754.bind(null, readUintLE);
        exports.readFloatBE = readFloat_ieee754.bind(null, readUintBE);

    })();

    // double: typed array
    if (typeof Float64Array !== "undefined") (function() {

        var f64 = new Float64Array([-0]),
            f8b = new Uint8Array(f64.buffer),
            le  = f8b[7] === 128;

        function writeDouble_f64_cpy(val, buf, pos) {
            f64[0] = val;
            buf[pos    ] = f8b[0];
            buf[pos + 1] = f8b[1];
            buf[pos + 2] = f8b[2];
            buf[pos + 3] = f8b[3];
            buf[pos + 4] = f8b[4];
            buf[pos + 5] = f8b[5];
            buf[pos + 6] = f8b[6];
            buf[pos + 7] = f8b[7];
        }

        function writeDouble_f64_rev(val, buf, pos) {
            f64[0] = val;
            buf[pos    ] = f8b[7];
            buf[pos + 1] = f8b[6];
            buf[pos + 2] = f8b[5];
            buf[pos + 3] = f8b[4];
            buf[pos + 4] = f8b[3];
            buf[pos + 5] = f8b[2];
            buf[pos + 6] = f8b[1];
            buf[pos + 7] = f8b[0];
        }

        /* istanbul ignore next */
        exports.writeDoubleLE = le ? writeDouble_f64_cpy : writeDouble_f64_rev;
        /* istanbul ignore next */
        exports.writeDoubleBE = le ? writeDouble_f64_rev : writeDouble_f64_cpy;

        function readDouble_f64_cpy(buf, pos) {
            f8b[0] = buf[pos    ];
            f8b[1] = buf[pos + 1];
            f8b[2] = buf[pos + 2];
            f8b[3] = buf[pos + 3];
            f8b[4] = buf[pos + 4];
            f8b[5] = buf[pos + 5];
            f8b[6] = buf[pos + 6];
            f8b[7] = buf[pos + 7];
            return f64[0];
        }

        function readDouble_f64_rev(buf, pos) {
            f8b[7] = buf[pos    ];
            f8b[6] = buf[pos + 1];
            f8b[5] = buf[pos + 2];
            f8b[4] = buf[pos + 3];
            f8b[3] = buf[pos + 4];
            f8b[2] = buf[pos + 5];
            f8b[1] = buf[pos + 6];
            f8b[0] = buf[pos + 7];
            return f64[0];
        }

        /* istanbul ignore next */
        exports.readDoubleLE = le ? readDouble_f64_cpy : readDouble_f64_rev;
        /* istanbul ignore next */
        exports.readDoubleBE = le ? readDouble_f64_rev : readDouble_f64_cpy;

    // double: ieee754
    })(); else (function() {

        function writeDouble_ieee754(writeUint, off0, off1, val, buf, pos) {
            var sign = val < 0 ? 1 : 0;
            if (sign)
                val = -val;
            if (val === 0) {
                writeUint(0, buf, pos + off0);
                writeUint(1 / val > 0 ? /* positive */ 0 : /* negative 0 */ 2147483648, buf, pos + off1);
            } else if (isNaN(val)) {
                writeUint(0, buf, pos + off0);
                writeUint(2146959360, buf, pos + off1);
            } else if (val > 1.7976931348623157e+308) { // +-Infinity
                writeUint(0, buf, pos + off0);
                writeUint((sign << 31 | 2146435072) >>> 0, buf, pos + off1);
            } else {
                var mantissa;
                if (val < 2.2250738585072014e-308) { // denormal
                    mantissa = val / 5e-324;
                    writeUint(mantissa >>> 0, buf, pos + off0);
                    writeUint((sign << 31 | mantissa / 4294967296) >>> 0, buf, pos + off1);
                } else {
                    var exponent = Math.floor(Math.log(val) / Math.LN2);
                    if (exponent === 1024)
                        exponent = 1023;
                    mantissa = val * Math.pow(2, -exponent);
                    writeUint(mantissa * 4503599627370496 >>> 0, buf, pos + off0);
                    writeUint((sign << 31 | exponent + 1023 << 20 | mantissa * 1048576 & 1048575) >>> 0, buf, pos + off1);
                }
            }
        }

        exports.writeDoubleLE = writeDouble_ieee754.bind(null, writeUintLE, 0, 4);
        exports.writeDoubleBE = writeDouble_ieee754.bind(null, writeUintBE, 4, 0);

        function readDouble_ieee754(readUint, off0, off1, buf, pos) {
            var lo = readUint(buf, pos + off0),
                hi = readUint(buf, pos + off1);
            var sign = (hi >> 31) * 2 + 1,
                exponent = hi >>> 20 & 2047,
                mantissa = 4294967296 * (hi & 1048575) + lo;
            return exponent === 2047
                ? mantissa
                ? NaN
                : sign * Infinity
                : exponent === 0 // denormal
                ? sign * 5e-324 * mantissa
                : sign * Math.pow(2, exponent - 1075) * (mantissa + 4503599627370496);
        }

        exports.readDoubleLE = readDouble_ieee754.bind(null, readUintLE, 0, 4);
        exports.readDoubleBE = readDouble_ieee754.bind(null, readUintBE, 4, 0);

    })();

    return exports;
}

// uint helpers

function writeUintLE(val, buf, pos) {
    buf[pos    ] =  val        & 255;
    buf[pos + 1] =  val >>> 8  & 255;
    buf[pos + 2] =  val >>> 16 & 255;
    buf[pos + 3] =  val >>> 24;
}

function writeUintBE(val, buf, pos) {
    buf[pos    ] =  val >>> 24;
    buf[pos + 1] =  val >>> 16 & 255;
    buf[pos + 2] =  val >>> 8  & 255;
    buf[pos + 3] =  val        & 255;
}

function readUintLE(buf, pos) {
    return (buf[pos    ]
          | buf[pos + 1] << 8
          | buf[pos + 2] << 16
          | buf[pos + 3] << 24) >>> 0;
}

function readUintBE(buf, pos) {
    return (buf[pos    ] << 24
          | buf[pos + 1] << 16
          | buf[pos + 2] << 8
          | buf[pos + 3]) >>> 0;
}


/***/ }),

/***/ 28031:
/***/ ((module) => {

"use strict";

module.exports = inquire;

/**
 * Requires a module only if available.
 * @memberof util
 * @param {string} moduleName Module to require
 * @returns {?Object} Required module if available and not empty, otherwise `null`
 */
function inquire(moduleName) {
    try {
        var mod = eval("quire".replace(/^/,"re"))(moduleName); // eslint-disable-line no-eval
        if (mod && (mod.length || Object.keys(mod).length))
            return mod;
    } catch (e) {} // eslint-disable-line no-empty
    return null;
}


/***/ }),

/***/ 14314:
/***/ ((module) => {

"use strict";

module.exports = pool;

/**
 * An allocator as used by {@link util.pool}.
 * @typedef PoolAllocator
 * @type {function}
 * @param {number} size Buffer size
 * @returns {Uint8Array} Buffer
 */

/**
 * A slicer as used by {@link util.pool}.
 * @typedef PoolSlicer
 * @type {function}
 * @param {number} start Start offset
 * @param {number} end End offset
 * @returns {Uint8Array} Buffer slice
 * @this {Uint8Array}
 */

/**
 * A general purpose buffer pool.
 * @memberof util
 * @function
 * @param {PoolAllocator} alloc Allocator
 * @param {PoolSlicer} slice Slicer
 * @param {number} [size=8192] Slab size
 * @returns {PoolAllocator} Pooled allocator
 */
function pool(alloc, slice, size) {
    var SIZE   = size || 8192;
    var MAX    = SIZE >>> 1;
    var slab   = null;
    var offset = SIZE;
    return function pool_alloc(size) {
        if (size < 1 || size > MAX)
            return alloc(size);
        if (offset + size > SIZE) {
            slab = alloc(SIZE);
            offset = 0;
        }
        var buf = slice.call(slab, offset, offset += size);
        if (offset & 7) // align to 32 bit
            offset = (offset | 7) + 1;
        return buf;
    };
}


/***/ }),

/***/ 67148:
/***/ ((__unused_webpack_module, exports) => {

"use strict";


/**
 * A minimal UTF8 implementation for number arrays.
 * @memberof util
 * @namespace
 */
var utf8 = exports;

/**
 * Calculates the UTF8 byte length of a string.
 * @param {string} string String
 * @returns {number} Byte length
 */
utf8.length = function utf8_length(string) {
    var len = 0,
        c = 0;
    for (var i = 0; i < string.length; ++i) {
        c = string.charCodeAt(i);
        if (c < 128)
            len += 1;
        else if (c < 2048)
            len += 2;
        else if ((c & 0xFC00) === 0xD800 && (string.charCodeAt(i + 1) & 0xFC00) === 0xDC00) {
            ++i;
            len += 4;
        } else
            len += 3;
    }
    return len;
};

/**
 * Reads UTF8 bytes as a string.
 * @param {Uint8Array} buffer Source buffer
 * @param {number} start Source start
 * @param {number} end Source end
 * @returns {string} String read
 */
utf8.read = function utf8_read(buffer, start, end) {
    var len = end - start;
    if (len < 1)
        return "";
    var parts = null,
        chunk = [],
        i = 0, // char offset
        t;     // temporary
    while (start < end) {
        t = buffer[start++];
        if (t < 128)
            chunk[i++] = t;
        else if (t > 191 && t < 224)
            chunk[i++] = (t & 31) << 6 | buffer[start++] & 63;
        else if (t > 239 && t < 365) {
            t = ((t & 7) << 18 | (buffer[start++] & 63) << 12 | (buffer[start++] & 63) << 6 | buffer[start++] & 63) - 0x10000;
            chunk[i++] = 0xD800 + (t >> 10);
            chunk[i++] = 0xDC00 + (t & 1023);
        } else
            chunk[i++] = (t & 15) << 12 | (buffer[start++] & 63) << 6 | buffer[start++] & 63;
        if (i > 8191) {
            (parts || (parts = [])).push(String.fromCharCode.apply(String, chunk));
            i = 0;
        }
    }
    if (parts) {
        if (i)
            parts.push(String.fromCharCode.apply(String, chunk.slice(0, i)));
        return parts.join("");
    }
    return String.fromCharCode.apply(String, chunk.slice(0, i));
};

/**
 * Writes a string as UTF8 bytes.
 * @param {string} string Source string
 * @param {Uint8Array} buffer Destination buffer
 * @param {number} offset Destination offset
 * @returns {number} Bytes written
 */
utf8.write = function utf8_write(string, buffer, offset) {
    var start = offset,
        c1, // character 1
        c2; // character 2
    for (var i = 0; i < string.length; ++i) {
        c1 = string.charCodeAt(i);
        if (c1 < 128) {
            buffer[offset++] = c1;
        } else if (c1 < 2048) {
            buffer[offset++] = c1 >> 6       | 192;
            buffer[offset++] = c1       & 63 | 128;
        } else if ((c1 & 0xFC00) === 0xD800 && ((c2 = string.charCodeAt(i + 1)) & 0xFC00) === 0xDC00) {
            c1 = 0x10000 + ((c1 & 0x03FF) << 10) + (c2 & 0x03FF);
            ++i;
            buffer[offset++] = c1 >> 18      | 240;
            buffer[offset++] = c1 >> 12 & 63 | 128;
            buffer[offset++] = c1 >> 6  & 63 | 128;
            buffer[offset++] = c1       & 63 | 128;
        } else {
            buffer[offset++] = c1 >> 12      | 224;
            buffer[offset++] = c1 >> 6  & 63 | 128;
            buffer[offset++] = c1       & 63 | 128;
        }
    }
    return offset - start;
};


/***/ }),

/***/ 8541:
/***/ ((module, exports, __webpack_require__) => {

"use strict";
/**
 * @author Toru Nagashima <https://github.com/mysticatea>
 * See LICENSE file in root directory for full license.
 */


Object.defineProperty(exports, "__esModule", ({ value: true }));

var eventTargetShim = __webpack_require__(40577);

/**
 * The signal class.
 * @see https://dom.spec.whatwg.org/#abortsignal
 */
class AbortSignal extends eventTargetShim.EventTarget {
    /**
     * AbortSignal cannot be constructed directly.
     */
    constructor() {
        super();
        throw new TypeError("AbortSignal cannot be constructed directly");
    }
    /**
     * Returns `true` if this `AbortSignal`'s `AbortController` has signaled to abort, and `false` otherwise.
     */
    get aborted() {
        const aborted = abortedFlags.get(this);
        if (typeof aborted !== "boolean") {
            throw new TypeError(`Expected 'this' to be an 'AbortSignal' object, but got ${this === null ? "null" : typeof this}`);
        }
        return aborted;
    }
}
eventTargetShim.defineEventAttribute(AbortSignal.prototype, "abort");
/**
 * Create an AbortSignal object.
 */
function createAbortSignal() {
    const signal = Object.create(AbortSignal.prototype);
    eventTargetShim.EventTarget.call(signal);
    abortedFlags.set(signal, false);
    return signal;
}
/**
 * Abort a given signal.
 */
function abortSignal(signal) {
    if (abortedFlags.get(signal) !== false) {
        return;
    }
    abortedFlags.set(signal, true);
    signal.dispatchEvent({ type: "abort" });
}
/**
 * Aborted flag for each instances.
 */
const abortedFlags = new WeakMap();
// Properties should be enumerable.
Object.defineProperties(AbortSignal.prototype, {
    aborted: { enumerable: true },
});
// `toString()` should return `"[object AbortSignal]"`
if (typeof Symbol === "function" && typeof Symbol.toStringTag === "symbol") {
    Object.defineProperty(AbortSignal.prototype, Symbol.toStringTag, {
        configurable: true,
        value: "AbortSignal",
    });
}

/**
 * The AbortController.
 * @see https://dom.spec.whatwg.org/#abortcontroller
 */
class AbortController {
    /**
     * Initialize this controller.
     */
    constructor() {
        signals.set(this, createAbortSignal());
    }
    /**
     * Returns the `AbortSignal` object associated with this object.
     */
    get signal() {
        return getSignal(this);
    }
    /**
     * Abort and signal to any observers that the associated activity is to be aborted.
     */
    abort() {
        abortSignal(getSignal(this));
    }
}
/**
 * Associated signals.
 */
const signals = new WeakMap();
/**
 * Get the associated signal of a given controller.
 */
function getSignal(controller) {
    const signal = signals.get(controller);
    if (signal == null) {
        throw new TypeError(`Expected 'this' to be an 'AbortController' object, but got ${controller === null ? "null" : typeof controller}`);
    }
    return signal;
}
// Properties should be enumerable.
Object.defineProperties(AbortController.prototype, {
    signal: { enumerable: true },
    abort: { enumerable: true },
});
if (typeof Symbol === "function" && typeof Symbol.toStringTag === "symbol") {
    Object.defineProperty(AbortController.prototype, Symbol.toStringTag, {
        configurable: true,
        value: "AbortController",
    });
}

exports.AbortController = AbortController;
exports.AbortSignal = AbortSignal;
exports["default"] = AbortController;

module.exports = AbortController
module.exports.AbortController = module.exports["default"] = AbortController
module.exports.AbortSignal = AbortSignal
//# sourceMappingURL=abort-controller.js.map


/***/ }),

/***/ 31967:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

"use strict";


const { Buffer } = __webpack_require__(14300)
const symbol = Symbol.for('BufferList')

function BufferList (buf) {
  if (!(this instanceof BufferList)) {
    return new BufferList(buf)
  }

  BufferList._init.call(this, buf)
}

BufferList._init = function _init (buf) {
  Object.defineProperty(this, symbol, { value: true })

  this._bufs = []
  this.length = 0

  if (buf) {
    this.append(buf)
  }
}

BufferList.prototype._new = function _new (buf) {
  return new BufferList(buf)
}

BufferList.prototype._offset = function _offset (offset) {
  if (offset === 0) {
    return [0, 0]
  }

  let tot = 0

  for (let i = 0; i < this._bufs.length; i++) {
    const _t = tot + this._bufs[i].length
    if (offset < _t || i === this._bufs.length - 1) {
      return [i, offset - tot]
    }
    tot = _t
  }
}

BufferList.prototype._reverseOffset = function (blOffset) {
  const bufferId = blOffset[0]
  let offset = blOffset[1]

  for (let i = 0; i < bufferId; i++) {
    offset += this._bufs[i].length
  }

  return offset
}

BufferList.prototype.get = function get (index) {
  if (index > this.length || index < 0) {
    return undefined
  }

  const offset = this._offset(index)

  return this._bufs[offset[0]][offset[1]]
}

BufferList.prototype.slice = function slice (start, end) {
  if (typeof start === 'number' && start < 0) {
    start += this.length
  }

  if (typeof end === 'number' && end < 0) {
    end += this.length
  }

  return this.copy(null, 0, start, end)
}

BufferList.prototype.copy = function copy (dst, dstStart, srcStart, srcEnd) {
  if (typeof srcStart !== 'number' || srcStart < 0) {
    srcStart = 0
  }

  if (typeof srcEnd !== 'number' || srcEnd > this.length) {
    srcEnd = this.length
  }

  if (srcStart >= this.length) {
    return dst || Buffer.alloc(0)
  }

  if (srcEnd <= 0) {
    return dst || Buffer.alloc(0)
  }

  const copy = !!dst
  const off = this._offset(srcStart)
  const len = srcEnd - srcStart
  let bytes = len
  let bufoff = (copy && dstStart) || 0
  let start = off[1]

  // copy/slice everything
  if (srcStart === 0 && srcEnd === this.length) {
    if (!copy) {
      // slice, but full concat if multiple buffers
      return this._bufs.length === 1
        ? this._bufs[0]
        : Buffer.concat(this._bufs, this.length)
    }

    // copy, need to copy individual buffers
    for (let i = 0; i < this._bufs.length; i++) {
      this._bufs[i].copy(dst, bufoff)
      bufoff += this._bufs[i].length
    }

    return dst
  }

  // easy, cheap case where it's a subset of one of the buffers
  if (bytes <= this._bufs[off[0]].length - start) {
    return copy
      ? this._bufs[off[0]].copy(dst, dstStart, start, start + bytes)
      : this._bufs[off[0]].slice(start, start + bytes)
  }

  if (!copy) {
    // a slice, we need something to copy in to
    dst = Buffer.allocUnsafe(len)
  }

  for (let i = off[0]; i < this._bufs.length; i++) {
    const l = this._bufs[i].length - start

    if (bytes > l) {
      this._bufs[i].copy(dst, bufoff, start)
      bufoff += l
    } else {
      this._bufs[i].copy(dst, bufoff, start, start + bytes)
      bufoff += l
      break
    }

    bytes -= l

    if (start) {
      start = 0
    }
  }

  // safeguard so that we don't return uninitialized memory
  if (dst.length > bufoff) return dst.slice(0, bufoff)

  return dst
}

BufferList.prototype.shallowSlice = function shallowSlice (start, end) {
  start = start || 0
  end = typeof end !== 'number' ? this.length : end

  if (start < 0) {
    start += this.length
  }

  if (end < 0) {
    end += this.length
  }

  if (start === end) {
    return this._new()
  }

  const startOffset = this._offset(start)
  const endOffset = this._offset(end)
  const buffers = this._bufs.slice(startOffset[0], endOffset[0] + 1)

  if (endOffset[1] === 0) {
    buffers.pop()
  } else {
    buffers[buffers.length - 1] = buffers[buffers.length - 1].slice(0, endOffset[1])
  }

  if (startOffset[1] !== 0) {
    buffers[0] = buffers[0].slice(startOffset[1])
  }

  return this._new(buffers)
}

BufferList.prototype.toString = function toString (encoding, start, end) {
  return this.slice(start, end).toString(encoding)
}

BufferList.prototype.consume = function consume (bytes) {
  // first, normalize the argument, in accordance with how Buffer does it
  bytes = Math.trunc(bytes)
  // do nothing if not a positive number
  if (Number.isNaN(bytes) || bytes <= 0) return this

  while (this._bufs.length) {
    if (bytes >= this._bufs[0].length) {
      bytes -= this._bufs[0].length
      this.length -= this._bufs[0].length
      this._bufs.shift()
    } else {
      this._bufs[0] = this._bufs[0].slice(bytes)
      this.length -= bytes
      break
    }
  }

  return this
}

BufferList.prototype.duplicate = function duplicate () {
  const copy = this._new()

  for (let i = 0; i < this._bufs.length; i++) {
    copy.append(this._bufs[i])
  }

  return copy
}

BufferList.prototype.append = function append (buf) {
  if (buf == null) {
    return this
  }

  if (buf.buffer) {
    // append a view of the underlying ArrayBuffer
    this._appendBuffer(Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength))
  } else if (Array.isArray(buf)) {
    for (let i = 0; i < buf.length; i++) {
      this.append(buf[i])
    }
  } else if (this._isBufferList(buf)) {
    // unwrap argument into individual BufferLists
    for (let i = 0; i < buf._bufs.length; i++) {
      this.append(buf._bufs[i])
    }
  } else {
    // coerce number arguments to strings, since Buffer(number) does
    // uninitialized memory allocation
    if (typeof buf === 'number') {
      buf = buf.toString()
    }

    this._appendBuffer(Buffer.from(buf))
  }

  return this
}

BufferList.prototype._appendBuffer = function appendBuffer (buf) {
  this._bufs.push(buf)
  this.length += buf.length
}

BufferList.prototype.indexOf = function (search, offset, encoding) {
  if (encoding === undefined && typeof offset === 'string') {
    encoding = offset
    offset = undefined
  }

  if (typeof search === 'function' || Array.isArray(search)) {
    throw new TypeError('The "value" argument must be one of type string, Buffer, BufferList, or Uint8Array.')
  } else if (typeof search === 'number') {
    search = Buffer.from([search])
  } else if (typeof search === 'string') {
    search = Buffer.from(search, encoding)
  } else if (this._isBufferList(search)) {
    search = search.slice()
  } else if (Array.isArray(search.buffer)) {
    search = Buffer.from(search.buffer, search.byteOffset, search.byteLength)
  } else if (!Buffer.isBuffer(search)) {
    search = Buffer.from(search)
  }

  offset = Number(offset || 0)

  if (isNaN(offset)) {
    offset = 0
  }

  if (offset < 0) {
    offset = this.length + offset
  }

  if (offset < 0) {
    offset = 0
  }

  if (search.length === 0) {
    return offset > this.length ? this.length : offset
  }

  const blOffset = this._offset(offset)
  let blIndex = blOffset[0] // index of which internal buffer we're working on
  let buffOffset = blOffset[1] // offset of the internal buffer we're working on

  // scan over each buffer
  for (; blIndex < this._bufs.length; blIndex++) {
    const buff = this._bufs[blIndex]

    while (buffOffset < buff.length) {
      const availableWindow = buff.length - buffOffset

      if (availableWindow >= search.length) {
        const nativeSearchResult = buff.indexOf(search, buffOffset)

        if (nativeSearchResult !== -1) {
          return this._reverseOffset([blIndex, nativeSearchResult])
        }

        buffOffset = buff.length - search.length + 1 // end of native search window
      } else {
        const revOffset = this._reverseOffset([blIndex, buffOffset])

        if (this._match(revOffset, search)) {
          return revOffset
        }

        buffOffset++
      }
    }

    buffOffset = 0
  }

  return -1
}

BufferList.prototype._match = function (offset, search) {
  if (this.length - offset < search.length) {
    return false
  }

  for (let searchOffset = 0; searchOffset < search.length; searchOffset++) {
    if (this.get(offset + searchOffset) !== search[searchOffset]) {
      return false
    }
  }
  return true
}

;(function () {
  const methods = {
    readDoubleBE: 8,
    readDoubleLE: 8,
    readFloatBE: 4,
    readFloatLE: 4,
    readInt32BE: 4,
    readInt32LE: 4,
    readUInt32BE: 4,
    readUInt32LE: 4,
    readInt16BE: 2,
    readInt16LE: 2,
    readUInt16BE: 2,
    readUInt16LE: 2,
    readInt8: 1,
    readUInt8: 1,
    readIntBE: null,
    readIntLE: null,
    readUIntBE: null,
    readUIntLE: null
  }

  for (const m in methods) {
    (function (m) {
      if (methods[m] === null) {
        BufferList.prototype[m] = function (offset, byteLength) {
          return this.slice(offset, offset + byteLength)[m](0, byteLength)
        }
      } else {
        BufferList.prototype[m] = function (offset = 0) {
          return this.slice(offset, offset + methods[m])[m](0)
        }
      }
    }(m))
  }
}())

// Used internally by the class and also as an indicator of this object being
// a `BufferList`. It's not possible to use `instanceof BufferList` in a browser
// environment because there could be multiple different copies of the
// BufferList class and some `BufferList`s might be `BufferList`s.
BufferList.prototype._isBufferList = function _isBufferList (b) {
  return b instanceof BufferList || BufferList.isBufferList(b)
}

BufferList.isBufferList = function isBufferList (b) {
  return b != null && b[symbol]
}

module.exports = BufferList


/***/ }),

/***/ 85146:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

"use strict";
/* eslint-env browser */



const browserReadableStreamToIt = __webpack_require__(94459)

/**
 * @param {Blob} blob
 * @returns {AsyncIterable<Uint8Array>}
 */
function blobToIt (blob) {
  if (typeof blob.stream === 'function') {
    // @ts-ignore missing some properties
    return browserReadableStreamToIt(blob.stream())
  }

  // firefox < 69 does not support blob.stream()
  // @ts-ignore - response.body is optional, but in practice it's a stream.
  return browserReadableStreamToIt(new Response(blob).body)
}

module.exports = blobToIt


/***/ }),

/***/ 94459:
/***/ ((module) => {

"use strict";


/**
 * Turns a browser readable stream into an async iterable. Async iteration over
 * returned iterable will lock give stream, preventing any other consumer from
 * acquiring a reader. The lock will be released if iteration loop is broken. To
 * prevent stream cancelling optional `{ preventCancel: true }` could be passed
 * as a second argument.
 * @template T
 * @param {ReadableStream<T>} stream
 * @param {Object} [options]
 * @param {boolean} [options.preventCancel=boolean]
 * @returns {AsyncIterable<T>}
 */
async function * browserReadableStreamToIt (stream, options = {}) {
  const reader = stream.getReader()

  try {
    while (true) {
      const result = await reader.read()

      if (result.done) {
        return
      }

      yield result.value
    }
  } finally {
    if (options.preventCancel !== true) {
      reader.cancel()
    }

    reader.releaseLock()
  }
}

module.exports = browserReadableStreamToIt


/***/ }),

/***/ 47255:
/***/ ((module) => {

"use strict";

/**
 * Returns a `Buffer` instance from the given data URI `uri`.
 *
 * @param {String} uri Data URI to turn into a Buffer instance
 * @return {Buffer} Buffer instance from Data URI
 * @api public
 */
function dataUriToBuffer(uri) {
    if (!/^data:/i.test(uri)) {
        throw new TypeError('`uri` does not appear to be a Data URI (must begin with "data:")');
    }
    // strip newlines
    uri = uri.replace(/\r?\n/g, '');
    // split the URI up into the "metadata" and the "data" portions
    const firstComma = uri.indexOf(',');
    if (firstComma === -1 || firstComma <= 4) {
        throw new TypeError('malformed data: URI');
    }
    // remove the "data:" scheme and parse the metadata
    const meta = uri.substring(5, firstComma).split(';');
    let charset = '';
    let base64 = false;
    const type = meta[0] || 'text/plain';
    let typeFull = type;
    for (let i = 1; i < meta.length; i++) {
        if (meta[i] === 'base64') {
            base64 = true;
        }
        else {
            typeFull += `;${meta[i]}`;
            if (meta[i].indexOf('charset=') === 0) {
                charset = meta[i].substring(8);
            }
        }
    }
    // defaults to US-ASCII only if type is not provided
    if (!meta[0] && !charset.length) {
        typeFull += ';charset=US-ASCII';
        charset = 'US-ASCII';
    }
    // get the encoded data portion and decode URI-encoded chars
    const encoding = base64 ? 'base64' : 'ascii';
    const data = unescape(uri.substring(firstComma + 1));
    const buffer = Buffer.from(data, encoding);
    // set `.type` and `.typeFull` properties to MIME type
    buffer.type = type;
    buffer.typeFull = typeFull;
    // set the `.charset` property
    buffer.charset = charset;
    return buffer;
}
module.exports = dataUriToBuffer;
//# sourceMappingURL=index.js.map

/***/ }),

/***/ 17058:
/***/ ((module) => {

"use strict";


/**
 * @typedef {{ [key: string]: any }} Extensions
 * @typedef {Error} Err
 * @property {string} message
 */

/**
 *
 * @param {Error} obj
 * @param {Extensions} props
 * @returns {Error & Extensions}
 */
function assign(obj, props) {
    for (const key in props) {
        Object.defineProperty(obj, key, {
            value: props[key],
            enumerable: true,
            configurable: true,
        });
    }

    return obj;
}

/**
 *
 * @param {any} err - An Error
 * @param {string|Extensions} code - A string code or props to set on the error
 * @param {Extensions} [props] - Props to set on the error
 * @returns {Error & Extensions}
 */
function createError(err, code, props) {
    if (!err || typeof err === 'string') {
        throw new TypeError('Please pass an Error to err-code');
    }

    if (!props) {
        props = {};
    }

    if (typeof code === 'object') {
        props = code;
        code = '';
    }

    if (code) {
        props.code = code;
    }

    try {
        return assign(err, props);
    } catch (_) {
        props.message = err.message;
        props.stack = err.stack;

        const ErrClass = function () {};

        ErrClass.prototype = Object.create(Object.getPrototypeOf(err));

        // @ts-ignore
        const output = assign(new ErrClass(), props);

        return output;
    }
}

module.exports = createError;


/***/ }),

/***/ 40577:
/***/ ((module, exports) => {

"use strict";
/**
 * @author Toru Nagashima <https://github.com/mysticatea>
 * @copyright 2015 Toru Nagashima. All rights reserved.
 * See LICENSE file in root directory for full license.
 */


Object.defineProperty(exports, "__esModule", ({ value: true }));

/**
 * @typedef {object} PrivateData
 * @property {EventTarget} eventTarget The event target.
 * @property {{type:string}} event The original event object.
 * @property {number} eventPhase The current event phase.
 * @property {EventTarget|null} currentTarget The current event target.
 * @property {boolean} canceled The flag to prevent default.
 * @property {boolean} stopped The flag to stop propagation.
 * @property {boolean} immediateStopped The flag to stop propagation immediately.
 * @property {Function|null} passiveListener The listener if the current listener is passive. Otherwise this is null.
 * @property {number} timeStamp The unix time.
 * @private
 */

/**
 * Private data for event wrappers.
 * @type {WeakMap<Event, PrivateData>}
 * @private
 */
const privateData = new WeakMap();

/**
 * Cache for wrapper classes.
 * @type {WeakMap<Object, Function>}
 * @private
 */
const wrappers = new WeakMap();

/**
 * Get private data.
 * @param {Event} event The event object to get private data.
 * @returns {PrivateData} The private data of the event.
 * @private
 */
function pd(event) {
    const retv = privateData.get(event);
    console.assert(
        retv != null,
        "'this' is expected an Event object, but got",
        event
    );
    return retv
}

/**
 * https://dom.spec.whatwg.org/#set-the-canceled-flag
 * @param data {PrivateData} private data.
 */
function setCancelFlag(data) {
    if (data.passiveListener != null) {
        if (
            typeof console !== "undefined" &&
            typeof console.error === "function"
        ) {
            console.error(
                "Unable to preventDefault inside passive event listener invocation.",
                data.passiveListener
            );
        }
        return
    }
    if (!data.event.cancelable) {
        return
    }

    data.canceled = true;
    if (typeof data.event.preventDefault === "function") {
        data.event.preventDefault();
    }
}

/**
 * @see https://dom.spec.whatwg.org/#interface-event
 * @private
 */
/**
 * The event wrapper.
 * @constructor
 * @param {EventTarget} eventTarget The event target of this dispatching.
 * @param {Event|{type:string}} event The original event to wrap.
 */
function Event(eventTarget, event) {
    privateData.set(this, {
        eventTarget,
        event,
        eventPhase: 2,
        currentTarget: eventTarget,
        canceled: false,
        stopped: false,
        immediateStopped: false,
        passiveListener: null,
        timeStamp: event.timeStamp || Date.now(),
    });

    // https://heycam.github.io/webidl/#Unforgeable
    Object.defineProperty(this, "isTrusted", { value: false, enumerable: true });

    // Define accessors
    const keys = Object.keys(event);
    for (let i = 0; i < keys.length; ++i) {
        const key = keys[i];
        if (!(key in this)) {
            Object.defineProperty(this, key, defineRedirectDescriptor(key));
        }
    }
}

// Should be enumerable, but class methods are not enumerable.
Event.prototype = {
    /**
     * The type of this event.
     * @type {string}
     */
    get type() {
        return pd(this).event.type
    },

    /**
     * The target of this event.
     * @type {EventTarget}
     */
    get target() {
        return pd(this).eventTarget
    },

    /**
     * The target of this event.
     * @type {EventTarget}
     */
    get currentTarget() {
        return pd(this).currentTarget
    },

    /**
     * @returns {EventTarget[]} The composed path of this event.
     */
    composedPath() {
        const currentTarget = pd(this).currentTarget;
        if (currentTarget == null) {
            return []
        }
        return [currentTarget]
    },

    /**
     * Constant of NONE.
     * @type {number}
     */
    get NONE() {
        return 0
    },

    /**
     * Constant of CAPTURING_PHASE.
     * @type {number}
     */
    get CAPTURING_PHASE() {
        return 1
    },

    /**
     * Constant of AT_TARGET.
     * @type {number}
     */
    get AT_TARGET() {
        return 2
    },

    /**
     * Constant of BUBBLING_PHASE.
     * @type {number}
     */
    get BUBBLING_PHASE() {
        return 3
    },

    /**
     * The target of this event.
     * @type {number}
     */
    get eventPhase() {
        return pd(this).eventPhase
    },

    /**
     * Stop event bubbling.
     * @returns {void}
     */
    stopPropagation() {
        const data = pd(this);

        data.stopped = true;
        if (typeof data.event.stopPropagation === "function") {
            data.event.stopPropagation();
        }
    },

    /**
     * Stop event bubbling.
     * @returns {void}
     */
    stopImmediatePropagation() {
        const data = pd(this);

        data.stopped = true;
        data.immediateStopped = true;
        if (typeof data.event.stopImmediatePropagation === "function") {
            data.event.stopImmediatePropagation();
        }
    },

    /**
     * The flag to be bubbling.
     * @type {boolean}
     */
    get bubbles() {
        return Boolean(pd(this).event.bubbles)
    },

    /**
     * The flag to be cancelable.
     * @type {boolean}
     */
    get cancelable() {
        return Boolean(pd(this).event.cancelable)
    },

    /**
     * Cancel this event.
     * @returns {void}
     */
    preventDefault() {
        setCancelFlag(pd(this));
    },

    /**
     * The flag to indicate cancellation state.
     * @type {boolean}
     */
    get defaultPrevented() {
        return pd(this).canceled
    },

    /**
     * The flag to be composed.
     * @type {boolean}
     */
    get composed() {
        return Boolean(pd(this).event.composed)
    },

    /**
     * The unix time of this event.
     * @type {number}
     */
    get timeStamp() {
        return pd(this).timeStamp
    },

    /**
     * The target of this event.
     * @type {EventTarget}
     * @deprecated
     */
    get srcElement() {
        return pd(this).eventTarget
    },

    /**
     * The flag to stop event bubbling.
     * @type {boolean}
     * @deprecated
     */
    get cancelBubble() {
        return pd(this).stopped
    },
    set cancelBubble(value) {
        if (!value) {
            return
        }
        const data = pd(this);

        data.stopped = true;
        if (typeof data.event.cancelBubble === "boolean") {
            data.event.cancelBubble = true;
        }
    },

    /**
     * The flag to indicate cancellation state.
     * @type {boolean}
     * @deprecated
     */
    get returnValue() {
        return !pd(this).canceled
    },
    set returnValue(value) {
        if (!value) {
            setCancelFlag(pd(this));
        }
    },

    /**
     * Initialize this event object. But do nothing under event dispatching.
     * @param {string} type The event type.
     * @param {boolean} [bubbles=false] The flag to be possible to bubble up.
     * @param {boolean} [cancelable=false] The flag to be possible to cancel.
     * @deprecated
     */
    initEvent() {
        // Do nothing.
    },
};

// `constructor` is not enumerable.
Object.defineProperty(Event.prototype, "constructor", {
    value: Event,
    configurable: true,
    writable: true,
});

// Ensure `event instanceof window.Event` is `true`.
if (typeof window !== "undefined" && typeof window.Event !== "undefined") {
    Object.setPrototypeOf(Event.prototype, window.Event.prototype);

    // Make association for wrappers.
    wrappers.set(window.Event.prototype, Event);
}

/**
 * Get the property descriptor to redirect a given property.
 * @param {string} key Property name to define property descriptor.
 * @returns {PropertyDescriptor} The property descriptor to redirect the property.
 * @private
 */
function defineRedirectDescriptor(key) {
    return {
        get() {
            return pd(this).event[key]
        },
        set(value) {
            pd(this).event[key] = value;
        },
        configurable: true,
        enumerable: true,
    }
}

/**
 * Get the property descriptor to call a given method property.
 * @param {string} key Property name to define property descriptor.
 * @returns {PropertyDescriptor} The property descriptor to call the method property.
 * @private
 */
function defineCallDescriptor(key) {
    return {
        value() {
            const event = pd(this).event;
            return event[key].apply(event, arguments)
        },
        configurable: true,
        enumerable: true,
    }
}

/**
 * Define new wrapper class.
 * @param {Function} BaseEvent The base wrapper class.
 * @param {Object} proto The prototype of the original event.
 * @returns {Function} The defined wrapper class.
 * @private
 */
function defineWrapper(BaseEvent, proto) {
    const keys = Object.keys(proto);
    if (keys.length === 0) {
        return BaseEvent
    }

    /** CustomEvent */
    function CustomEvent(eventTarget, event) {
        BaseEvent.call(this, eventTarget, event);
    }

    CustomEvent.prototype = Object.create(BaseEvent.prototype, {
        constructor: { value: CustomEvent, configurable: true, writable: true },
    });

    // Define accessors.
    for (let i = 0; i < keys.length; ++i) {
        const key = keys[i];
        if (!(key in BaseEvent.prototype)) {
            const descriptor = Object.getOwnPropertyDescriptor(proto, key);
            const isFunc = typeof descriptor.value === "function";
            Object.defineProperty(
                CustomEvent.prototype,
                key,
                isFunc
                    ? defineCallDescriptor(key)
                    : defineRedirectDescriptor(key)
            );
        }
    }

    return CustomEvent
}

/**
 * Get the wrapper class of a given prototype.
 * @param {Object} proto The prototype of the original event to get its wrapper.
 * @returns {Function} The wrapper class.
 * @private
 */
function getWrapper(proto) {
    if (proto == null || proto === Object.prototype) {
        return Event
    }

    let wrapper = wrappers.get(proto);
    if (wrapper == null) {
        wrapper = defineWrapper(getWrapper(Object.getPrototypeOf(proto)), proto);
        wrappers.set(proto, wrapper);
    }
    return wrapper
}

/**
 * Wrap a given event to management a dispatching.
 * @param {EventTarget} eventTarget The event target of this dispatching.
 * @param {Object} event The event to wrap.
 * @returns {Event} The wrapper instance.
 * @private
 */
function wrapEvent(eventTarget, event) {
    const Wrapper = getWrapper(Object.getPrototypeOf(event));
    return new Wrapper(eventTarget, event)
}

/**
 * Get the immediateStopped flag of a given event.
 * @param {Event} event The event to get.
 * @returns {boolean} The flag to stop propagation immediately.
 * @private
 */
function isStopped(event) {
    return pd(event).immediateStopped
}

/**
 * Set the current event phase of a given event.
 * @param {Event} event The event to set current target.
 * @param {number} eventPhase New event phase.
 * @returns {void}
 * @private
 */
function setEventPhase(event, eventPhase) {
    pd(event).eventPhase = eventPhase;
}

/**
 * Set the current target of a given event.
 * @param {Event} event The event to set current target.
 * @param {EventTarget|null} currentTarget New current target.
 * @returns {void}
 * @private
 */
function setCurrentTarget(event, currentTarget) {
    pd(event).currentTarget = currentTarget;
}

/**
 * Set a passive listener of a given event.
 * @param {Event} event The event to set current target.
 * @param {Function|null} passiveListener New passive listener.
 * @returns {void}
 * @private
 */
function setPassiveListener(event, passiveListener) {
    pd(event).passiveListener = passiveListener;
}

/**
 * @typedef {object} ListenerNode
 * @property {Function} listener
 * @property {1|2|3} listenerType
 * @property {boolean} passive
 * @property {boolean} once
 * @property {ListenerNode|null} next
 * @private
 */

/**
 * @type {WeakMap<object, Map<string, ListenerNode>>}
 * @private
 */
const listenersMap = new WeakMap();

// Listener types
const CAPTURE = 1;
const BUBBLE = 2;
const ATTRIBUTE = 3;

/**
 * Check whether a given value is an object or not.
 * @param {any} x The value to check.
 * @returns {boolean} `true` if the value is an object.
 */
function isObject(x) {
    return x !== null && typeof x === "object" //eslint-disable-line no-restricted-syntax
}

/**
 * Get listeners.
 * @param {EventTarget} eventTarget The event target to get.
 * @returns {Map<string, ListenerNode>} The listeners.
 * @private
 */
function getListeners(eventTarget) {
    const listeners = listenersMap.get(eventTarget);
    if (listeners == null) {
        throw new TypeError(
            "'this' is expected an EventTarget object, but got another value."
        )
    }
    return listeners
}

/**
 * Get the property descriptor for the event attribute of a given event.
 * @param {string} eventName The event name to get property descriptor.
 * @returns {PropertyDescriptor} The property descriptor.
 * @private
 */
function defineEventAttributeDescriptor(eventName) {
    return {
        get() {
            const listeners = getListeners(this);
            let node = listeners.get(eventName);
            while (node != null) {
                if (node.listenerType === ATTRIBUTE) {
                    return node.listener
                }
                node = node.next;
            }
            return null
        },

        set(listener) {
            if (typeof listener !== "function" && !isObject(listener)) {
                listener = null; // eslint-disable-line no-param-reassign
            }
            const listeners = getListeners(this);

            // Traverse to the tail while removing old value.
            let prev = null;
            let node = listeners.get(eventName);
            while (node != null) {
                if (node.listenerType === ATTRIBUTE) {
                    // Remove old value.
                    if (prev !== null) {
                        prev.next = node.next;
                    } else if (node.next !== null) {
                        listeners.set(eventName, node.next);
                    } else {
                        listeners.delete(eventName);
                    }
                } else {
                    prev = node;
                }

                node = node.next;
            }

            // Add new value.
            if (listener !== null) {
                const newNode = {
                    listener,
                    listenerType: ATTRIBUTE,
                    passive: false,
                    once: false,
                    next: null,
                };
                if (prev === null) {
                    listeners.set(eventName, newNode);
                } else {
                    prev.next = newNode;
                }
            }
        },
        configurable: true,
        enumerable: true,
    }
}

/**
 * Define an event attribute (e.g. `eventTarget.onclick`).
 * @param {Object} eventTargetPrototype The event target prototype to define an event attrbite.
 * @param {string} eventName The event name to define.
 * @returns {void}
 */
function defineEventAttribute(eventTargetPrototype, eventName) {
    Object.defineProperty(
        eventTargetPrototype,
        `on${eventName}`,
        defineEventAttributeDescriptor(eventName)
    );
}

/**
 * Define a custom EventTarget with event attributes.
 * @param {string[]} eventNames Event names for event attributes.
 * @returns {EventTarget} The custom EventTarget.
 * @private
 */
function defineCustomEventTarget(eventNames) {
    /** CustomEventTarget */
    function CustomEventTarget() {
        EventTarget.call(this);
    }

    CustomEventTarget.prototype = Object.create(EventTarget.prototype, {
        constructor: {
            value: CustomEventTarget,
            configurable: true,
            writable: true,
        },
    });

    for (let i = 0; i < eventNames.length; ++i) {
        defineEventAttribute(CustomEventTarget.prototype, eventNames[i]);
    }

    return CustomEventTarget
}

/**
 * EventTarget.
 *
 * - This is constructor if no arguments.
 * - This is a function which returns a CustomEventTarget constructor if there are arguments.
 *
 * For example:
 *
 *     class A extends EventTarget {}
 *     class B extends EventTarget("message") {}
 *     class C extends EventTarget("message", "error") {}
 *     class D extends EventTarget(["message", "error"]) {}
 */
function EventTarget() {
    /*eslint-disable consistent-return */
    if (this instanceof EventTarget) {
        listenersMap.set(this, new Map());
        return
    }
    if (arguments.length === 1 && Array.isArray(arguments[0])) {
        return defineCustomEventTarget(arguments[0])
    }
    if (arguments.length > 0) {
        const types = new Array(arguments.length);
        for (let i = 0; i < arguments.length; ++i) {
            types[i] = arguments[i];
        }
        return defineCustomEventTarget(types)
    }
    throw new TypeError("Cannot call a class as a function")
    /*eslint-enable consistent-return */
}

// Should be enumerable, but class methods are not enumerable.
EventTarget.prototype = {
    /**
     * Add a given listener to this event target.
     * @param {string} eventName The event name to add.
     * @param {Function} listener The listener to add.
     * @param {boolean|{capture?:boolean,passive?:boolean,once?:boolean}} [options] The options for this listener.
     * @returns {void}
     */
    addEventListener(eventName, listener, options) {
        if (listener == null) {
            return
        }
        if (typeof listener !== "function" && !isObject(listener)) {
            throw new TypeError("'listener' should be a function or an object.")
        }

        const listeners = getListeners(this);
        const optionsIsObj = isObject(options);
        const capture = optionsIsObj
            ? Boolean(options.capture)
            : Boolean(options);
        const listenerType = capture ? CAPTURE : BUBBLE;
        const newNode = {
            listener,
            listenerType,
            passive: optionsIsObj && Boolean(options.passive),
            once: optionsIsObj && Boolean(options.once),
            next: null,
        };

        // Set it as the first node if the first node is null.
        let node = listeners.get(eventName);
        if (node === undefined) {
            listeners.set(eventName, newNode);
            return
        }

        // Traverse to the tail while checking duplication..
        let prev = null;
        while (node != null) {
            if (
                node.listener === listener &&
                node.listenerType === listenerType
            ) {
                // Should ignore duplication.
                return
            }
            prev = node;
            node = node.next;
        }

        // Add it.
        prev.next = newNode;
    },

    /**
     * Remove a given listener from this event target.
     * @param {string} eventName The event name to remove.
     * @param {Function} listener The listener to remove.
     * @param {boolean|{capture?:boolean,passive?:boolean,once?:boolean}} [options] The options for this listener.
     * @returns {void}
     */
    removeEventListener(eventName, listener, options) {
        if (listener == null) {
            return
        }

        const listeners = getListeners(this);
        const capture = isObject(options)
            ? Boolean(options.capture)
            : Boolean(options);
        const listenerType = capture ? CAPTURE : BUBBLE;

        let prev = null;
        let node = listeners.get(eventName);
        while (node != null) {
            if (
                node.listener === listener &&
                node.listenerType === listenerType
            ) {
                if (prev !== null) {
                    prev.next = node.next;
                } else if (node.next !== null) {
                    listeners.set(eventName, node.next);
                } else {
                    listeners.delete(eventName);
                }
                return
            }

            prev = node;
            node = node.next;
        }
    },

    /**
     * Dispatch a given event.
     * @param {Event|{type:string}} event The event to dispatch.
     * @returns {boolean} `false` if canceled.
     */
    dispatchEvent(event) {
        if (event == null || typeof event.type !== "string") {
            throw new TypeError('"event.type" should be a string.')
        }

        // If listeners aren't registered, terminate.
        const listeners = getListeners(this);
        const eventName = event.type;
        let node = listeners.get(eventName);
        if (node == null) {
            return true
        }

        // Since we cannot rewrite several properties, so wrap object.
        const wrappedEvent = wrapEvent(this, event);

        // This doesn't process capturing phase and bubbling phase.
        // This isn't participating in a tree.
        let prev = null;
        while (node != null) {
            // Remove this listener if it's once
            if (node.once) {
                if (prev !== null) {
                    prev.next = node.next;
                } else if (node.next !== null) {
                    listeners.set(eventName, node.next);
                } else {
                    listeners.delete(eventName);
                }
            } else {
                prev = node;
            }

            // Call this listener
            setPassiveListener(
                wrappedEvent,
                node.passive ? node.listener : null
            );
            if (typeof node.listener === "function") {
                try {
                    node.listener.call(this, wrappedEvent);
                } catch (err) {
                    if (
                        typeof console !== "undefined" &&
                        typeof console.error === "function"
                    ) {
                        console.error(err);
                    }
                }
            } else if (
                node.listenerType !== ATTRIBUTE &&
                typeof node.listener.handleEvent === "function"
            ) {
                node.listener.handleEvent(wrappedEvent);
            }

            // Break if `event.stopImmediatePropagation` was called.
            if (isStopped(wrappedEvent)) {
                break
            }

            node = node.next;
        }
        setPassiveListener(wrappedEvent, null);
        setEventPhase(wrappedEvent, 0);
        setCurrentTarget(wrappedEvent, null);

        return !wrappedEvent.defaultPrevented
    },
};

// `constructor` is not enumerable.
Object.defineProperty(EventTarget.prototype, "constructor", {
    value: EventTarget,
    configurable: true,
    writable: true,
});

// Ensure `eventTarget instanceof window.EventTarget` is `true`.
if (
    typeof window !== "undefined" &&
    typeof window.EventTarget !== "undefined"
) {
    Object.setPrototypeOf(EventTarget.prototype, window.EventTarget.prototype);
}

exports.defineEventAttribute = defineEventAttribute;
exports.EventTarget = EventTarget;
exports["default"] = EventTarget;

module.exports = EventTarget
module.exports.EventTarget = module.exports["default"] = EventTarget
module.exports.defineEventAttribute = defineEventAttribute
//# sourceMappingURL=event-target-shim.js.map


/***/ }),

/***/ 59303:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

"use strict";


// @ts-ignore
const SparseArray = __webpack_require__(50334)
const { fromString: uint8ArrayFromString } = __webpack_require__(5007)

/**
 * @typedef {import('./consumable-hash').InfiniteHash} InfiniteHash
 * @typedef {import('../').UserBucketOptions} UserBucketOptions
 */

/**
 * @template V
 * @typedef {object} BucketChild<V>
 * @property {string} key
 * @property {V} value
 * @property {InfiniteHash} hash
 */

/**
 * @template B
 *
 * @typedef {object} SA<B>
 * @property {number} length
 * @property {() => B[]} compactArray
 * @property {(i: number) => B} get
 * @property {(i: number, value: B) => void} set
 * @property {<A> (fn: (acc: A, curr: B, index: number) => A, initial: A) => B} reduce
 * @property {(fn: (item: B) => boolean) => B | undefined} find
 * @property {() => number[]} bitField
 * @property {(i: number) => void} unset
 */

/**
 * @template T
 *
 * @typedef {object} BucketPosition<T>
 * @property {Bucket<T>} bucket
 * @property {number} pos
 * @property {InfiniteHash} hash
 * @property {BucketChild<T>} [existingChild]
 */

/**
 * @typedef {object} BucketOptions
 * @property {number} bits
 * @property {(value: Uint8Array | InfiniteHash) => InfiniteHash} hash
 */

/**
 * @template T
 */
class Bucket {
  /**
   * @param {BucketOptions} options
   * @param {Bucket<T>} [parent]
   * @param {number} [posAtParent=0]
   */
  constructor (options, parent, posAtParent = 0) {
    this._options = options
    this._popCount = 0
    this._parent = parent
    this._posAtParent = posAtParent

    /** @type {SA<Bucket<T> | BucketChild<T>>} */
    this._children = new SparseArray()

    /** @type {string | null} */
    this.key = null
  }

  /**
   * @param {string} key
   * @param {T} value
   */
  async put (key, value) {
    const place = await this._findNewBucketAndPos(key)

    await place.bucket._putAt(place, key, value)
  }

  /**
   * @param {string} key
   */
  async get (key) {
    const child = await this._findChild(key)

    if (child) {
      return child.value
    }
  }

  /**
   * @param {string} key
   */
  async del (key) {
    const place = await this._findPlace(key)
    const child = place.bucket._at(place.pos)

    if (child && child.key === key) {
      place.bucket._delAt(place.pos)
    }
  }

  /**
   * @returns {number}
   */
  leafCount () {
    const children = this._children.compactArray()

    return children.reduce((acc, child) => {
      if (child instanceof Bucket) {
        return acc + child.leafCount()
      }

      return acc + 1
    }, 0)
  }

  childrenCount () {
    return this._children.length
  }

  onlyChild () {
    return this._children.get(0)
  }

  /**
   * @returns {Iterable<BucketChild<T>>}
   */
  * eachLeafSeries () {
    const children = this._children.compactArray()

    for (const child of children) {
      if (child instanceof Bucket) {
        yield * child.eachLeafSeries()
      } else {
        yield child
      }
    }

    // this is necessary because tsc requires a @return annotation as it
    // can't derive a return type due to the recursion, and eslint requires
    // a return statement when there is a @return annotation
    return []
  }

  /**
   * @param {(value: BucketChild<T>, index: number) => T} map
   * @param {(reduced: any) => any} reduce
   */
  serialize (map, reduce) {
    /** @type {T[]} */
    const acc = []
    // serialize to a custom non-sparse representation
    return reduce(this._children.reduce((acc, child, index) => {
      if (child) {
        if (child instanceof Bucket) {
          acc.push(child.serialize(map, reduce))
        } else {
          acc.push(map(child, index))
        }
      }
      return acc
    }, acc))
  }

  /**
   * @param {(value: BucketChild<T>) => Promise<T[]>} asyncMap
   * @param {(reduced: any) => Promise<any>} asyncReduce
   */
  asyncTransform (asyncMap, asyncReduce) {
    return asyncTransformBucket(this, asyncMap, asyncReduce)
  }

  toJSON () {
    return this.serialize(mapNode, reduceNodes)
  }

  prettyPrint () {
    return JSON.stringify(this.toJSON(), null, '  ')
  }

  tableSize () {
    return Math.pow(2, this._options.bits)
  }

  /**
   * @param {string} key
   * @returns {Promise<BucketChild<T> | undefined>}
   */
  async _findChild (key) {
    const result = await this._findPlace(key)
    const child = result.bucket._at(result.pos)

    if (child instanceof Bucket) {
      // should not be possible, this._findPlace should always
      // return a location for a child, not a bucket
      return undefined
    }

    if (child && child.key === key) {
      return child
    }
  }

  /**
   * @param {string | InfiniteHash} key
   * @returns {Promise<BucketPosition<T>>}
   */
  async _findPlace (key) {
    const hashValue = this._options.hash(typeof key === 'string' ? uint8ArrayFromString(key) : key)
    const index = await hashValue.take(this._options.bits)

    const child = this._children.get(index)

    if (child instanceof Bucket) {
      return child._findPlace(hashValue)
    }

    return {
      bucket: this,
      pos: index,
      hash: hashValue,
      existingChild: child
    }
  }

  /**
   * @param {string | InfiniteHash} key
   * @returns {Promise<BucketPosition<T>>}
   */
  async _findNewBucketAndPos (key) {
    const place = await this._findPlace(key)

    if (place.existingChild && place.existingChild.key !== key) {
      // conflict
      const bucket = new Bucket(this._options, place.bucket, place.pos)
      place.bucket._putObjectAt(place.pos, bucket)

      // put the previous value
      const newPlace = await bucket._findPlace(place.existingChild.hash)
      newPlace.bucket._putAt(newPlace, place.existingChild.key, place.existingChild.value)

      return bucket._findNewBucketAndPos(place.hash)
    }

    // no conflict, we found the place
    return place
  }

  /**
   * @param {BucketPosition<T>} place
   * @param {string} key
   * @param {T} value
   */
  _putAt (place, key, value) {
    this._putObjectAt(place.pos, {
      key: key,
      value: value,
      hash: place.hash
    })
  }

  /**
   * @param {number} pos
   * @param {Bucket<T> | BucketChild<T>} object
   */
  _putObjectAt (pos, object) {
    if (!this._children.get(pos)) {
      this._popCount++
    }
    this._children.set(pos, object)
  }

  /**
   * @param {number} pos
   */
  _delAt (pos) {
    if (pos === -1) {
      throw new Error('Invalid position')
    }

    if (this._children.get(pos)) {
      this._popCount--
    }
    this._children.unset(pos)
    this._level()
  }

  _level () {
    if (this._parent && this._popCount <= 1) {
      if (this._popCount === 1) {
        // remove myself from parent, replacing me with my only child
        const onlyChild = this._children.find(exists)

        if (onlyChild && !(onlyChild instanceof Bucket)) {
          const hash = onlyChild.hash
          hash.untake(this._options.bits)
          const place = {
            pos: this._posAtParent,
            hash: hash,
            bucket: this._parent
          }
          this._parent._putAt(place, onlyChild.key, onlyChild.value)
        }
      } else {
        this._parent._delAt(this._posAtParent)
      }
    }
  }

  /**
   * @param {number} index
   * @returns {BucketChild<T> | Bucket<T> | undefined}
   */
  _at (index) {
    return this._children.get(index)
  }
}

/**
 * @param {any} o
 */
function exists (o) {
  return Boolean(o)
}

/**
 *
 * @param {*} node
 * @param {number} index
 */
function mapNode (node, index) {
  return node.key
}

/**
 * @param {*} nodes
 */
function reduceNodes (nodes) {
  return nodes
}

/**
 * @template T
 *
 * @param {Bucket<T>} bucket
 * @param {(value: BucketChild<T>) => Promise<T[]>} asyncMap
 * @param {(reduced: any) => Promise<any>} asyncReduce
 */
async function asyncTransformBucket (bucket, asyncMap, asyncReduce) {
  const output = []

  for (const child of bucket._children.compactArray()) {
    if (child instanceof Bucket) {
      await asyncTransformBucket(child, asyncMap, asyncReduce)
    } else {
      const mappedChildren = await asyncMap(child)

      output.push({
        bitField: bucket._children.bitField(),
        children: mappedChildren
      })
    }
  }

  return asyncReduce(output)
}

module.exports = Bucket


/***/ }),

/***/ 18281:
/***/ ((module) => {

"use strict";


const START_MASKS = [
  0b11111111,
  0b11111110,
  0b11111100,
  0b11111000,
  0b11110000,
  0b11100000,
  0b11000000,
  0b10000000
]

const STOP_MASKS = [
  0b00000001,
  0b00000011,
  0b00000111,
  0b00001111,
  0b00011111,
  0b00111111,
  0b01111111,
  0b11111111
]

module.exports = class ConsumableBuffer {
  /**
   * @param {Uint8Array} value
   */
  constructor (value) {
    this._value = value
    this._currentBytePos = value.length - 1
    this._currentBitPos = 7
  }

  availableBits () {
    return this._currentBitPos + 1 + this._currentBytePos * 8
  }

  totalBits () {
    return this._value.length * 8
  }

  /**
   * @param {number} bits
   */
  take (bits) {
    let pendingBits = bits
    let result = 0
    while (pendingBits && this._haveBits()) {
      const byte = this._value[this._currentBytePos]
      const availableBits = this._currentBitPos + 1
      const taking = Math.min(availableBits, pendingBits)
      const value = byteBitsToInt(byte, availableBits - taking, taking)
      result = (result << taking) + value

      pendingBits -= taking

      this._currentBitPos -= taking
      if (this._currentBitPos < 0) {
        this._currentBitPos = 7
        this._currentBytePos--
      }
    }

    return result
  }

  /**
   * @param {number} bits
   */
  untake (bits) {
    this._currentBitPos += bits
    while (this._currentBitPos > 7) {
      this._currentBitPos -= 8
      this._currentBytePos += 1
    }
  }

  _haveBits () {
    return this._currentBytePos >= 0
  }
}

/**
 * @param {number} byte
 * @param {number} start
 * @param {number} length
 */
function byteBitsToInt (byte, start, length) {
  const mask = maskFor(start, length)
  return (byte & mask) >>> start
}

/**
 * @param {number} start
 * @param {number} length
 */
function maskFor (start, length) {
  return START_MASKS[start] & STOP_MASKS[Math.min(length + start - 1, 7)]
}


/***/ }),

/***/ 90204:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

"use strict";


const ConsumableBuffer = __webpack_require__(18281)
const { concat: uint8ArrayConcat } = __webpack_require__(33391)

/**
 * @param {(value: Uint8Array) => Promise<Uint8Array>} hashFn
 */
function wrapHash (hashFn) {
  /**
   * @param {InfiniteHash | Uint8Array} value
   */
  function hashing (value) {
    if (value instanceof InfiniteHash) {
      // already a hash. return it
      return value
    } else {
      return new InfiniteHash(value, hashFn)
    }
  }

  return hashing
}

class InfiniteHash {
  /**
   *
   * @param {Uint8Array} value
   * @param {(value: Uint8Array) => Promise<Uint8Array>} hashFn
   */
  constructor (value, hashFn) {
    if (!(value instanceof Uint8Array)) {
      throw new Error('can only hash Uint8Arrays')
    }

    this._value = value
    this._hashFn = hashFn
    this._depth = -1
    this._availableBits = 0
    this._currentBufferIndex = 0

    /** @type {ConsumableBuffer[]} */
    this._buffers = []
  }

  /**
   * @param {number} bits
   */
  async take (bits) {
    let pendingBits = bits

    while (this._availableBits < pendingBits) {
      await this._produceMoreBits()
    }

    let result = 0

    while (pendingBits > 0) {
      const hash = this._buffers[this._currentBufferIndex]
      const available = Math.min(hash.availableBits(), pendingBits)
      const took = hash.take(available)
      result = (result << available) + took
      pendingBits -= available
      this._availableBits -= available

      if (hash.availableBits() === 0) {
        this._currentBufferIndex++
      }
    }

    return result
  }

  /**
   * @param {number} bits
   */
  untake (bits) {
    let pendingBits = bits

    while (pendingBits > 0) {
      const hash = this._buffers[this._currentBufferIndex]
      const availableForUntake = Math.min(hash.totalBits() - hash.availableBits(), pendingBits)
      hash.untake(availableForUntake)
      pendingBits -= availableForUntake
      this._availableBits += availableForUntake

      if (this._currentBufferIndex > 0 && hash.totalBits() === hash.availableBits()) {
        this._depth--
        this._currentBufferIndex--
      }
    }
  }

  async _produceMoreBits () {
    this._depth++

    const value = this._depth ? uint8ArrayConcat([this._value, Uint8Array.from([this._depth])]) : this._value
    const hashValue = await this._hashFn(value)
    const buffer = new ConsumableBuffer(hashValue)

    this._buffers.push(buffer)
    this._availableBits += buffer.availableBits()
  }
}

module.exports = wrapHash
module.exports.InfiniteHash = InfiniteHash


/***/ }),

/***/ 12103:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

"use strict";


const Bucket = __webpack_require__(59303)
const wrapHash = __webpack_require__(90204)

/**
 * @typedef {object} UserBucketOptions
 * @property {(value: Uint8Array) => Promise<Uint8Array>} hashFn
 * @property {number} [bits=8]
 */

/**
 * @param {UserBucketOptions} options
 */
function createHAMT (options) {
  if (!options || !options.hashFn) {
    throw new Error('please define an options.hashFn')
  }

  const bucketOptions = {
    bits: options.bits || 8,
    hash: wrapHash(options.hashFn)
  }

  return new Bucket(bucketOptions)
}

module.exports = {
  createHAMT,
  Bucket
}


/***/ }),

/***/ 44279:
/***/ ((module) => {

"use strict";


/**
 * Collects all values from an (async) iterable into an array and returns it.
 *
 * @template T
 * @param {AsyncIterable<T>|Iterable<T>} source
 */
const all = async (source) => {
  const arr = []

  for await (const entry of source) {
    arr.push(entry)
  }

  return arr
}

module.exports = all


/***/ }),

/***/ 40783:
/***/ ((module) => {

"use strict";


/**
 * Takes an (async) iterable that emits things and returns an async iterable that
 * emits those things in fixed-sized batches.
 *
 * @template T
 * @param {AsyncIterable<T>|Iterable<T>} source
 * @param {number} [size=1]
 * @returns {AsyncIterable<T[]>}
 */
async function * batch (source, size = 1) {
  /** @type {T[]} */
  let things = []

  if (size < 1) {
    size = 1
  }

  for await (const thing of source) {
    things.push(thing)

    while (things.length >= size) {
      yield things.slice(0, size)

      things = things.slice(size)
    }
  }

  while (things.length) {
    yield things.slice(0, size)

    things = things.slice(size)
  }
}

module.exports = batch


/***/ }),

/***/ 98259:
/***/ ((module) => {

"use strict";


/**
 * Drains an (async) iterable discarding its' content and does not return
 * anything.
 *
 * @template T
 * @param {AsyncIterable<T>|Iterable<T>} source
 * @returns {Promise<void>}
 */
const drain = async (source) => {
  for await (const _ of source) { } // eslint-disable-line no-unused-vars,no-empty
}

module.exports = drain


/***/ }),

/***/ 55863:
/***/ ((module) => {

"use strict";


/**
 * Filters the passed (async) iterable by using the filter function
 *
 * @template T
 * @param {AsyncIterable<T>|Iterable<T>} source
 * @param {function(T):boolean|Promise<boolean>} fn
 */
const filter = async function * (source, fn) {
  for await (const entry of source) {
    if (await fn(entry)) {
      yield entry
    }
  }
}

module.exports = filter


/***/ }),

/***/ 7754:
/***/ ((module) => {

"use strict";


/**
 * Returns the last item of an (async) iterable, unless empty, in which case
 * return `undefined`.
 *
 * @template T
 * @param {AsyncIterable<T>|Iterable<T>} source
 */
const last = async (source) => {
  let res

  for await (const entry of source) {
    res = entry
  }

  return res
}

module.exports = last


/***/ }),

/***/ 55594:
/***/ ((module) => {

"use strict";


/**
 * Takes an (async) iterable and returns one with each item mapped by the passed
 * function.
 *
 * @template I,O
 * @param {AsyncIterable<I>|Iterable<I>} source
 * @param {function(I):O|Promise<O>} func
 * @returns {AsyncIterable<O>}
 */
const map = async function * (source, func) {
  for await (const val of source) {
    yield func(val)
  }
}

module.exports = map


/***/ }),

/***/ 51046:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

"use strict";


const batch = __webpack_require__(40783)

/**
 * @template T
 * @typedef {{ok:true, value:T}} Success
 */

/**
 * @typedef {{ok:false, err:Error}} Failure
 */

/**
 * Takes an (async) iterator that emits promise-returning functions,
 * invokes them in parallel and emits the results as they become available but
 * in the same order as the input
 *
 * @template T
 * @param {AsyncIterable<() => Promise<T>>|Iterable<() => Promise<T>>} source
 * @param {number} [size=1]
 * @returns {AsyncIterable<T>}
 */
async function * parallelBatch (source, size = 1) {
  for await (const tasks of batch(source, size)) {
    /** @type {Promise<Success<T>|Failure>[]} */
    const things = tasks.map(
      /**
       * @param {() => Promise<T>} p
       */
      p => {
        return p().then(value => ({ ok: true, value }), err => ({ ok: false, err }))
      })

    for (let i = 0; i < things.length; i++) {
      const result = await things[i]

      if (result.ok) {
        yield result.value
      } else {
        throw result.err
      }
    }
  }
}

module.exports = parallelBatch


/***/ }),

/***/ 60127:
/***/ ((module) => {

"use strict";


/**
 * @template T
 * @typedef {Object} Peek
 * @property {() => IteratorResult<T, void>} peek
 */

/**
 * @template T
 * @typedef {Object} AsyncPeek
 * @property {() => Promise<IteratorResult<T, void>>} peek
 */

/**
 * @template T
 * @typedef {Object} Push
 * @property {(value:T) => void} push
 */

/**
 * @template T
 * @typedef {Iterable<T> & Peek<T> & Push<T> & Iterator<T>} Peekable<T>
 */

/**
 * @template T
 * @typedef {AsyncIterable<T> & AsyncPeek<T> & Push<T> & AsyncIterator<T>} AsyncPeekable<T>
 */

/**
 * @template {Iterable<any> | AsyncIterable<any>} I
 * @param {I} iterable
 * @returns {I extends Iterable<infer T>
 *  ? Peekable<T>
 *  : I extends AsyncIterable<infer T>
 *  ? AsyncPeekable<T>
 *  : never
 * }
 */
function peekableIterator (iterable) {
  // @ts-ignore
  const [iterator, symbol] = iterable[Symbol.asyncIterator]
    // @ts-ignore
    ? [iterable[Symbol.asyncIterator](), Symbol.asyncIterator]
    // @ts-ignore
    : [iterable[Symbol.iterator](), Symbol.iterator]

  /** @type {any[]} */
  const queue = []

  // @ts-ignore
  return {
    peek: () => {
      return iterator.next()
    },
    push: (value) => {
      queue.push(value)
    },
    next: () => {
      if (queue.length) {
        return {
          done: false,
          value: queue.shift()
        }
      }

      return iterator.next()
    },
    [symbol] () {
      return this
    }
  }
}

module.exports = peekableIterator


/***/ }),

/***/ 38947:
/***/ ((module) => {

const rawPipe = (...fns) => {
  let res
  while (fns.length) {
    res = fns.shift()(res)
  }
  return res
}

const isIterable = obj => obj && (
  typeof obj[Symbol.asyncIterator] === 'function' ||
  typeof obj[Symbol.iterator] === 'function' ||
  typeof obj.next === 'function' // Probably, right?
)

const isDuplex = obj => obj && typeof obj.sink === 'function' && isIterable(obj.source)

const duplexPipelineFn = duplex => source => {
  duplex.sink(source) // TODO: error on sink side is unhandled rejection - this is the same as pull streams
  return duplex.source
}

const pipe = (...fns) => {
  // Duplex at start: wrap in function and return duplex source
  if (isDuplex(fns[0])) {
    const duplex = fns[0]
    fns[0] = () => duplex.source
  // Iterable at start: wrap in function
  } else if (isIterable(fns[0])) {
    const source = fns[0]
    fns[0] = () => source
  }

  if (fns.length > 1) {
    // Duplex at end: use duplex sink
    if (isDuplex(fns[fns.length - 1])) {
      fns[fns.length - 1] = fns[fns.length - 1].sink
    }
  }

  if (fns.length > 2) {
    // Duplex in the middle, consume source with duplex sink and return duplex source
    for (let i = 1; i < fns.length - 1; i++) {
      if (isDuplex(fns[i])) {
        fns[i] = duplexPipelineFn(fns[i])
      }
    }
  }

  return rawPipe(...fns)
}

module.exports = pipe
module.exports.pipe = pipe
module.exports.rawPipe = rawPipe
module.exports.isIterable = isIterable
module.exports.isDuplex = isDuplex


/***/ }),

/***/ 61955:
/***/ ((module) => {

"use strict";


/**
 * Stop iteration after n items have been received.
 *
 * @template T
 * @param {AsyncIterable<T>|Iterable<T>} source
 * @param {number} limit
 * @returns {AsyncIterable<T>}
 */
const take = async function * (source, limit) {
  let items = 0

  if (limit < 1) {
    return
  }

  for await (const entry of source) {
    yield entry

    items++

    if (items === limit) {
      return
    }
  }
}

module.exports = take


/***/ }),

/***/ 70890:
/***/ (function(module, __unused_webpack_exports, __webpack_require__) {

"use strict";

const isOptionObject = __webpack_require__(21316);

const {hasOwnProperty} = Object.prototype;
const {propertyIsEnumerable} = Object;
const defineProperty = (object, name, value) => Object.defineProperty(object, name, {
	value,
	writable: true,
	enumerable: true,
	configurable: true
});

const globalThis = this;
const defaultMergeOptions = {
	concatArrays: false,
	ignoreUndefined: false
};

const getEnumerableOwnPropertyKeys = value => {
	const keys = [];

	for (const key in value) {
		if (hasOwnProperty.call(value, key)) {
			keys.push(key);
		}
	}

	/* istanbul ignore else  */
	if (Object.getOwnPropertySymbols) {
		const symbols = Object.getOwnPropertySymbols(value);

		for (const symbol of symbols) {
			if (propertyIsEnumerable.call(value, symbol)) {
				keys.push(symbol);
			}
		}
	}

	return keys;
};

function clone(value) {
	if (Array.isArray(value)) {
		return cloneArray(value);
	}

	if (isOptionObject(value)) {
		return cloneOptionObject(value);
	}

	return value;
}

function cloneArray(array) {
	const result = array.slice(0, 0);

	getEnumerableOwnPropertyKeys(array).forEach(key => {
		defineProperty(result, key, clone(array[key]));
	});

	return result;
}

function cloneOptionObject(object) {
	const result = Object.getPrototypeOf(object) === null ? Object.create(null) : {};

	getEnumerableOwnPropertyKeys(object).forEach(key => {
		defineProperty(result, key, clone(object[key]));
	});

	return result;
}

/**
 * @param {*} merged already cloned
 * @param {*} source something to merge
 * @param {string[]} keys keys to merge
 * @param {Object} config Config Object
 * @returns {*} cloned Object
 */
const mergeKeys = (merged, source, keys, config) => {
	keys.forEach(key => {
		if (typeof source[key] === 'undefined' && config.ignoreUndefined) {
			return;
		}

		// Do not recurse into prototype chain of merged
		if (key in merged && merged[key] !== Object.getPrototypeOf(merged)) {
			defineProperty(merged, key, merge(merged[key], source[key], config));
		} else {
			defineProperty(merged, key, clone(source[key]));
		}
	});

	return merged;
};

/**
 * @param {*} merged already cloned
 * @param {*} source something to merge
 * @param {Object} config Config Object
 * @returns {*} cloned Object
 *
 * see [Array.prototype.concat ( ...arguments )](http://www.ecma-international.org/ecma-262/6.0/#sec-array.prototype.concat)
 */
const concatArrays = (merged, source, config) => {
	let result = merged.slice(0, 0);
	let resultIndex = 0;

	[merged, source].forEach(array => {
		const indices = [];

		// `result.concat(array)` with cloning
		for (let k = 0; k < array.length; k++) {
			if (!hasOwnProperty.call(array, k)) {
				continue;
			}

			indices.push(String(k));

			if (array === merged) {
				// Already cloned
				defineProperty(result, resultIndex++, array[k]);
			} else {
				defineProperty(result, resultIndex++, clone(array[k]));
			}
		}

		// Merge non-index keys
		result = mergeKeys(result, array, getEnumerableOwnPropertyKeys(array).filter(key => !indices.includes(key)), config);
	});

	return result;
};

/**
 * @param {*} merged already cloned
 * @param {*} source something to merge
 * @param {Object} config Config Object
 * @returns {*} cloned Object
 */
function merge(merged, source, config) {
	if (config.concatArrays && Array.isArray(merged) && Array.isArray(source)) {
		return concatArrays(merged, source, config);
	}

	if (!isOptionObject(source) || !isOptionObject(merged)) {
		return clone(source);
	}

	return mergeKeys(merged, source, getEnumerableOwnPropertyKeys(source), config);
}

module.exports = function (...options) {
	const config = merge(clone(defaultMergeOptions), (this !== globalThis && this) || {}, defaultMergeOptions);
	let merged = {_: {}};

	for (const option of options) {
		if (option === undefined) {
			continue;
		}

		if (!isOptionObject(option)) {
			throw new TypeError('`' + option + '` is not an Option Object');
		}

		merged = merge(merged, {_: option}, config);
	}

	return merged._;
};


/***/ }),

/***/ 21316:
/***/ ((module) => {

"use strict";


module.exports = value => {
	if (Object.prototype.toString.call(value) !== '[object Object]') {
		return false;
	}

	const prototype = Object.getPrototypeOf(value);
	return prototype === null || prototype === Object.prototype;
};


/***/ }),

/***/ 63655:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

module.exports = __webpack_require__(49045);


/***/ }),

/***/ 49045:
/***/ (function(module, exports) {

/* jshint -W086: true */
// +----------------------------------------------------------------------+
// | murmurHash3js.js v3.0.1 // https://github.com/pid/murmurHash3js
// | A javascript implementation of MurmurHash3's x86 hashing algorithms. |
// |----------------------------------------------------------------------|
// | Copyright (c) 2012-2015 Karan Lyons                                       |
// | https://github.com/karanlyons/murmurHash3.js/blob/c1778f75792abef7bdd74bc85d2d4e1a3d25cfe9/murmurHash3.js |
// | Freely distributable under the MIT license.                          |
// +----------------------------------------------------------------------+

;(function (root, undefined) {
    'use strict';

    // Create a local object that'll be exported or referenced globally.
    var library = {
        'version': '3.0.0',
        'x86': {},
        'x64': {},
        'inputValidation': true
    };

    // PRIVATE FUNCTIONS
    // -----------------

    function _validBytes(bytes) {
        // check the input is an array or a typed array
        if (!Array.isArray(bytes) && !ArrayBuffer.isView(bytes)) {
            return false;
        }

        // check all bytes are actually bytes
        for (var i = 0; i < bytes.length; i++) {
            if (!Number.isInteger(bytes[i]) || bytes[i] < 0 || bytes[i] > 255) {
                return false;
            }
        }
        return true;
    }

    function _x86Multiply(m, n) {
        //
        // Given two 32bit ints, returns the two multiplied together as a
        // 32bit int.
        //

        return ((m & 0xffff) * n) + ((((m >>> 16) * n) & 0xffff) << 16);
    }

    function _x86Rotl(m, n) {
        //
        // Given a 32bit int and an int representing a number of bit positions,
        // returns the 32bit int rotated left by that number of positions.
        //

        return (m << n) | (m >>> (32 - n));
    }

    function _x86Fmix(h) {
        //
        // Given a block, returns murmurHash3's final x86 mix of that block.
        //

        h ^= h >>> 16;
        h = _x86Multiply(h, 0x85ebca6b);
        h ^= h >>> 13;
        h = _x86Multiply(h, 0xc2b2ae35);
        h ^= h >>> 16;

        return h;
    }

    function _x64Add(m, n) {
        //
        // Given two 64bit ints (as an array of two 32bit ints) returns the two
        // added together as a 64bit int (as an array of two 32bit ints).
        //

        m = [m[0] >>> 16, m[0] & 0xffff, m[1] >>> 16, m[1] & 0xffff];
        n = [n[0] >>> 16, n[0] & 0xffff, n[1] >>> 16, n[1] & 0xffff];
        var o = [0, 0, 0, 0];

        o[3] += m[3] + n[3];
        o[2] += o[3] >>> 16;
        o[3] &= 0xffff;

        o[2] += m[2] + n[2];
        o[1] += o[2] >>> 16;
        o[2] &= 0xffff;

        o[1] += m[1] + n[1];
        o[0] += o[1] >>> 16;
        o[1] &= 0xffff;

        o[0] += m[0] + n[0];
        o[0] &= 0xffff;

        return [(o[0] << 16) | o[1], (o[2] << 16) | o[3]];
    }

    function _x64Multiply(m, n) {
        //
        // Given two 64bit ints (as an array of two 32bit ints) returns the two
        // multiplied together as a 64bit int (as an array of two 32bit ints).
        //

        m = [m[0] >>> 16, m[0] & 0xffff, m[1] >>> 16, m[1] & 0xffff];
        n = [n[0] >>> 16, n[0] & 0xffff, n[1] >>> 16, n[1] & 0xffff];
        var o = [0, 0, 0, 0];

        o[3] += m[3] * n[3];
        o[2] += o[3] >>> 16;
        o[3] &= 0xffff;

        o[2] += m[2] * n[3];
        o[1] += o[2] >>> 16;
        o[2] &= 0xffff;

        o[2] += m[3] * n[2];
        o[1] += o[2] >>> 16;
        o[2] &= 0xffff;

        o[1] += m[1] * n[3];
        o[0] += o[1] >>> 16;
        o[1] &= 0xffff;

        o[1] += m[2] * n[2];
        o[0] += o[1] >>> 16;
        o[1] &= 0xffff;

        o[1] += m[3] * n[1];
        o[0] += o[1] >>> 16;
        o[1] &= 0xffff;

        o[0] += (m[0] * n[3]) + (m[1] * n[2]) + (m[2] * n[1]) + (m[3] * n[0]);
        o[0] &= 0xffff;

        return [(o[0] << 16) | o[1], (o[2] << 16) | o[3]];
    }

    function _x64Rotl(m, n) {
        //
        // Given a 64bit int (as an array of two 32bit ints) and an int
        // representing a number of bit positions, returns the 64bit int (as an
        // array of two 32bit ints) rotated left by that number of positions.
        //

        n %= 64;

        if (n === 32) {
            return [m[1], m[0]];
        } else if (n < 32) {
            return [(m[0] << n) | (m[1] >>> (32 - n)), (m[1] << n) | (m[0] >>> (32 - n))];
        } else {
            n -= 32;
            return [(m[1] << n) | (m[0] >>> (32 - n)), (m[0] << n) | (m[1] >>> (32 - n))];
        }
    }

    function _x64LeftShift(m, n) {
        //
        // Given a 64bit int (as an array of two 32bit ints) and an int
        // representing a number of bit positions, returns the 64bit int (as an
        // array of two 32bit ints) shifted left by that number of positions.
        //

        n %= 64;

        if (n === 0) {
            return m;
        } else if (n < 32) {
            return [(m[0] << n) | (m[1] >>> (32 - n)), m[1] << n];
        } else {
            return [m[1] << (n - 32), 0];
        }
    }

    function _x64Xor(m, n) {
        //
        // Given two 64bit ints (as an array of two 32bit ints) returns the two
        // xored together as a 64bit int (as an array of two 32bit ints).
        //

        return [m[0] ^ n[0], m[1] ^ n[1]];
    }

    function _x64Fmix(h) {
        //
        // Given a block, returns murmurHash3's final x64 mix of that block.
        // (`[0, h[0] >>> 1]` is a 33 bit unsigned right shift. This is the
        // only place where we need to right shift 64bit ints.)
        //

        h = _x64Xor(h, [0, h[0] >>> 1]);
        h = _x64Multiply(h, [0xff51afd7, 0xed558ccd]);
        h = _x64Xor(h, [0, h[0] >>> 1]);
        h = _x64Multiply(h, [0xc4ceb9fe, 0x1a85ec53]);
        h = _x64Xor(h, [0, h[0] >>> 1]);

        return h;
    }

    // PUBLIC FUNCTIONS
    // ----------------

    library.x86.hash32 = function (bytes, seed) {
        //
        // Given a string and an optional seed as an int, returns a 32 bit hash
        // using the x86 flavor of MurmurHash3, as an unsigned int.
        //
        if (library.inputValidation && !_validBytes(bytes)) {
            return undefined;
        }
        seed = seed || 0;

        var remainder = bytes.length % 4;
        var blocks = bytes.length - remainder;

        var h1 = seed;

        var k1 = 0;

        var c1 = 0xcc9e2d51;
        var c2 = 0x1b873593;

        for (var i = 0; i < blocks; i = i + 4) {
            k1 = (bytes[i]) | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24);

            k1 = _x86Multiply(k1, c1);
            k1 = _x86Rotl(k1, 15);
            k1 = _x86Multiply(k1, c2);

            h1 ^= k1;
            h1 = _x86Rotl(h1, 13);
            h1 = _x86Multiply(h1, 5) + 0xe6546b64;
        }

        k1 = 0;

        switch (remainder) {
            case 3:
                k1 ^= bytes[i + 2] << 16;

            case 2:
                k1 ^= bytes[i + 1] << 8;

            case 1:
                k1 ^= bytes[i];
                k1 = _x86Multiply(k1, c1);
                k1 = _x86Rotl(k1, 15);
                k1 = _x86Multiply(k1, c2);
                h1 ^= k1;
        }

        h1 ^= bytes.length;
        h1 = _x86Fmix(h1);

        return h1 >>> 0;
    };

    library.x86.hash128 = function (bytes, seed) {
        //
        // Given a string and an optional seed as an int, returns a 128 bit
        // hash using the x86 flavor of MurmurHash3, as an unsigned hex.
        //
        if (library.inputValidation && !_validBytes(bytes)) {
            return undefined;
        }

        seed = seed || 0;
        var remainder = bytes.length % 16;
        var blocks = bytes.length - remainder;

        var h1 = seed;
        var h2 = seed;
        var h3 = seed;
        var h4 = seed;

        var k1 = 0;
        var k2 = 0;
        var k3 = 0;
        var k4 = 0;

        var c1 = 0x239b961b;
        var c2 = 0xab0e9789;
        var c3 = 0x38b34ae5;
        var c4 = 0xa1e38b93;

        for (var i = 0; i < blocks; i = i + 16) {
            k1 = (bytes[i]) | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24);
            k2 = (bytes[i + 4]) | (bytes[i + 5] << 8) | (bytes[i + 6] << 16) | (bytes[i + 7] << 24);
            k3 = (bytes[i + 8]) | (bytes[i + 9] << 8) | (bytes[i + 10] << 16) | (bytes[i + 11] << 24);
            k4 = (bytes[i + 12]) | (bytes[i + 13] << 8) | (bytes[i + 14] << 16) | (bytes[i + 15] << 24);

            k1 = _x86Multiply(k1, c1);
            k1 = _x86Rotl(k1, 15);
            k1 = _x86Multiply(k1, c2);
            h1 ^= k1;

            h1 = _x86Rotl(h1, 19);
            h1 += h2;
            h1 = _x86Multiply(h1, 5) + 0x561ccd1b;

            k2 = _x86Multiply(k2, c2);
            k2 = _x86Rotl(k2, 16);
            k2 = _x86Multiply(k2, c3);
            h2 ^= k2;

            h2 = _x86Rotl(h2, 17);
            h2 += h3;
            h2 = _x86Multiply(h2, 5) + 0x0bcaa747;

            k3 = _x86Multiply(k3, c3);
            k3 = _x86Rotl(k3, 17);
            k3 = _x86Multiply(k3, c4);
            h3 ^= k3;

            h3 = _x86Rotl(h3, 15);
            h3 += h4;
            h3 = _x86Multiply(h3, 5) + 0x96cd1c35;

            k4 = _x86Multiply(k4, c4);
            k4 = _x86Rotl(k4, 18);
            k4 = _x86Multiply(k4, c1);
            h4 ^= k4;

            h4 = _x86Rotl(h4, 13);
            h4 += h1;
            h4 = _x86Multiply(h4, 5) + 0x32ac3b17;
        }

        k1 = 0;
        k2 = 0;
        k3 = 0;
        k4 = 0;

        switch (remainder) {
            case 15:
                k4 ^= bytes[i + 14] << 16;

            case 14:
                k4 ^= bytes[i + 13] << 8;

            case 13:
                k4 ^= bytes[i + 12];
                k4 = _x86Multiply(k4, c4);
                k4 = _x86Rotl(k4, 18);
                k4 = _x86Multiply(k4, c1);
                h4 ^= k4;

            case 12:
                k3 ^= bytes[i + 11] << 24;

            case 11:
                k3 ^= bytes[i + 10] << 16;

            case 10:
                k3 ^= bytes[i + 9] << 8;

            case 9:
                k3 ^= bytes[i + 8];
                k3 = _x86Multiply(k3, c3);
                k3 = _x86Rotl(k3, 17);
                k3 = _x86Multiply(k3, c4);
                h3 ^= k3;

            case 8:
                k2 ^= bytes[i + 7] << 24;

            case 7:
                k2 ^= bytes[i + 6] << 16;

            case 6:
                k2 ^= bytes[i + 5] << 8;

            case 5:
                k2 ^= bytes[i + 4];
                k2 = _x86Multiply(k2, c2);
                k2 = _x86Rotl(k2, 16);
                k2 = _x86Multiply(k2, c3);
                h2 ^= k2;

            case 4:
                k1 ^= bytes[i + 3] << 24;

            case 3:
                k1 ^= bytes[i + 2] << 16;

            case 2:
                k1 ^= bytes[i + 1] << 8;

            case 1:
                k1 ^= bytes[i];
                k1 = _x86Multiply(k1, c1);
                k1 = _x86Rotl(k1, 15);
                k1 = _x86Multiply(k1, c2);
                h1 ^= k1;
        }

        h1 ^= bytes.length;
        h2 ^= bytes.length;
        h3 ^= bytes.length;
        h4 ^= bytes.length;

        h1 += h2;
        h1 += h3;
        h1 += h4;
        h2 += h1;
        h3 += h1;
        h4 += h1;

        h1 = _x86Fmix(h1);
        h2 = _x86Fmix(h2);
        h3 = _x86Fmix(h3);
        h4 = _x86Fmix(h4);

        h1 += h2;
        h1 += h3;
        h1 += h4;
        h2 += h1;
        h3 += h1;
        h4 += h1;

        return ("00000000" + (h1 >>> 0).toString(16)).slice(-8) + ("00000000" + (h2 >>> 0).toString(16)).slice(-8) + ("00000000" + (h3 >>> 0).toString(16)).slice(-8) + ("00000000" + (h4 >>> 0).toString(16)).slice(-8);
    };

    library.x64.hash128 = function (bytes, seed) {
        //
        // Given a string and an optional seed as an int, returns a 128 bit
        // hash using the x64 flavor of MurmurHash3, as an unsigned hex.
        //
        if (library.inputValidation && !_validBytes(bytes)) {
            return undefined;
        }
        seed = seed || 0;

        var remainder = bytes.length % 16;
        var blocks = bytes.length - remainder;

        var h1 = [0, seed];
        var h2 = [0, seed];

        var k1 = [0, 0];
        var k2 = [0, 0];

        var c1 = [0x87c37b91, 0x114253d5];
        var c2 = [0x4cf5ad43, 0x2745937f];

        for (var i = 0; i < blocks; i = i + 16) {
            k1 = [(bytes[i + 4]) | (bytes[i + 5] << 8) | (bytes[i + 6] << 16) | (bytes[i + 7] << 24), (bytes[i]) |
                (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24)];
            k2 = [(bytes[i + 12]) | (bytes[i + 13] << 8) | (bytes[i + 14] << 16) | (bytes[i + 15] << 24), (bytes[i + 8]) |
                (bytes[i + 9] << 8) | (bytes[i + 10] << 16) | (bytes[i + 11] << 24)];

            k1 = _x64Multiply(k1, c1);
            k1 = _x64Rotl(k1, 31);
            k1 = _x64Multiply(k1, c2);
            h1 = _x64Xor(h1, k1);

            h1 = _x64Rotl(h1, 27);
            h1 = _x64Add(h1, h2);
            h1 = _x64Add(_x64Multiply(h1, [0, 5]), [0, 0x52dce729]);

            k2 = _x64Multiply(k2, c2);
            k2 = _x64Rotl(k2, 33);
            k2 = _x64Multiply(k2, c1);
            h2 = _x64Xor(h2, k2);

            h2 = _x64Rotl(h2, 31);
            h2 = _x64Add(h2, h1);
            h2 = _x64Add(_x64Multiply(h2, [0, 5]), [0, 0x38495ab5]);
        }

        k1 = [0, 0];
        k2 = [0, 0];

        switch (remainder) {
            case 15:
                k2 = _x64Xor(k2, _x64LeftShift([0, bytes[i + 14]], 48));

            case 14:
                k2 = _x64Xor(k2, _x64LeftShift([0, bytes[i + 13]], 40));

            case 13:
                k2 = _x64Xor(k2, _x64LeftShift([0, bytes[i + 12]], 32));

            case 12:
                k2 = _x64Xor(k2, _x64LeftShift([0, bytes[i + 11]], 24));

            case 11:
                k2 = _x64Xor(k2, _x64LeftShift([0, bytes[i + 10]], 16));

            case 10:
                k2 = _x64Xor(k2, _x64LeftShift([0, bytes[i + 9]], 8));

            case 9:
                k2 = _x64Xor(k2, [0, bytes[i + 8]]);
                k2 = _x64Multiply(k2, c2);
                k2 = _x64Rotl(k2, 33);
                k2 = _x64Multiply(k2, c1);
                h2 = _x64Xor(h2, k2);

            case 8:
                k1 = _x64Xor(k1, _x64LeftShift([0, bytes[i + 7]], 56));

            case 7:
                k1 = _x64Xor(k1, _x64LeftShift([0, bytes[i + 6]], 48));

            case 6:
                k1 = _x64Xor(k1, _x64LeftShift([0, bytes[i + 5]], 40));

            case 5:
                k1 = _x64Xor(k1, _x64LeftShift([0, bytes[i + 4]], 32));

            case 4:
                k1 = _x64Xor(k1, _x64LeftShift([0, bytes[i + 3]], 24));

            case 3:
                k1 = _x64Xor(k1, _x64LeftShift([0, bytes[i + 2]], 16));

            case 2:
                k1 = _x64Xor(k1, _x64LeftShift([0, bytes[i + 1]], 8));

            case 1:
                k1 = _x64Xor(k1, [0, bytes[i]]);
                k1 = _x64Multiply(k1, c1);
                k1 = _x64Rotl(k1, 31);
                k1 = _x64Multiply(k1, c2);
                h1 = _x64Xor(h1, k1);
        }

        h1 = _x64Xor(h1, [0, bytes.length]);
        h2 = _x64Xor(h2, [0, bytes.length]);

        h1 = _x64Add(h1, h2);
        h2 = _x64Add(h2, h1);

        h1 = _x64Fmix(h1);
        h2 = _x64Fmix(h2);

        h1 = _x64Add(h1, h2);
        h2 = _x64Add(h2, h1);

        return ("00000000" + (h1[0] >>> 0).toString(16)).slice(-8) + ("00000000" + (h1[1] >>> 0).toString(16)).slice(-8) + ("00000000" + (h2[0] >>> 0).toString(16)).slice(-8) + ("00000000" + (h2[1] >>> 0).toString(16)).slice(-8);
    };

    // INITIALIZATION
    // --------------

    // Export murmurHash3 for CommonJS, either as an AMD module or just as part
    // of the global object.
    if (true) {

        if ( true && module.exports) {
            exports = module.exports = library;
        }

        exports.murmurHash3 = library;

    } else {}
})(this);


/***/ }),

/***/ 71856:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

"use strict";

const retry = __webpack_require__(18520);

const networkErrorMsgs = [
	'Failed to fetch', // Chrome
	'NetworkError when attempting to fetch resource.', // Firefox
	'The Internet connection appears to be offline.', // Safari
	'Network request failed' // `cross-fetch`
];

class AbortError extends Error {
	constructor(message) {
		super();

		if (message instanceof Error) {
			this.originalError = message;
			({message} = message);
		} else {
			this.originalError = new Error(message);
			this.originalError.stack = this.stack;
		}

		this.name = 'AbortError';
		this.message = message;
	}
}

const decorateErrorWithCounts = (error, attemptNumber, options) => {
	// Minus 1 from attemptNumber because the first attempt does not count as a retry
	const retriesLeft = options.retries - (attemptNumber - 1);

	error.attemptNumber = attemptNumber;
	error.retriesLeft = retriesLeft;
	return error;
};

const isNetworkError = errorMessage => networkErrorMsgs.includes(errorMessage);

const pRetry = (input, options) => new Promise((resolve, reject) => {
	options = {
		onFailedAttempt: () => {},
		retries: 10,
		...options
	};

	const operation = retry.operation(options);

	operation.attempt(async attemptNumber => {
		try {
			resolve(await input(attemptNumber));
		} catch (error) {
			if (!(error instanceof Error)) {
				reject(new TypeError(`Non-error was thrown: "${error}". You should only throw errors.`));
				return;
			}

			if (error instanceof AbortError) {
				operation.stop();
				reject(error.originalError);
			} else if (error instanceof TypeError && !isNetworkError(error.message)) {
				operation.stop();
				reject(error);
			} else {
				decorateErrorWithCounts(error, attemptNumber, options);

				try {
					await options.onFailedAttempt(error);
				} catch (error) {
					reject(error);
					return;
				}

				if (!operation.retry(error)) {
					reject(operation.mainError());
				}
			}
		}
	});
});

module.exports = pRetry;
// TODO: remove this in the next major version
module.exports["default"] = pRetry;

module.exports.AbortError = AbortError;


/***/ }),

/***/ 51883:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

"use strict";
// minimal library entry point.


module.exports = __webpack_require__(82985);


/***/ }),

/***/ 82985:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

var protobuf = exports;

/**
 * Build type, one of `"full"`, `"light"` or `"minimal"`.
 * @name build
 * @type {string}
 * @const
 */
protobuf.build = "minimal";

// Serialization
protobuf.Writer       = __webpack_require__(84353);
protobuf.BufferWriter = __webpack_require__(81978);
protobuf.Reader       = __webpack_require__(95199);
protobuf.BufferReader = __webpack_require__(15213);

// Utility
protobuf.util         = __webpack_require__(18932);
protobuf.rpc          = __webpack_require__(69226);
protobuf.roots        = __webpack_require__(10182);
protobuf.configure    = configure;

/* istanbul ignore next */
/**
 * Reconfigures the library according to the environment.
 * @returns {undefined}
 */
function configure() {
    protobuf.util._configure();
    protobuf.Writer._configure(protobuf.BufferWriter);
    protobuf.Reader._configure(protobuf.BufferReader);
}

// Set up buffer utility according to the environment
configure();


/***/ }),

/***/ 95199:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

"use strict";

module.exports = Reader;

var util      = __webpack_require__(18932);

var BufferReader; // cyclic

var LongBits  = util.LongBits,
    utf8      = util.utf8;

/* istanbul ignore next */
function indexOutOfRange(reader, writeLength) {
    return RangeError("index out of range: " + reader.pos + " + " + (writeLength || 1) + " > " + reader.len);
}

/**
 * Constructs a new reader instance using the specified buffer.
 * @classdesc Wire format reader using `Uint8Array` if available, otherwise `Array`.
 * @constructor
 * @param {Uint8Array} buffer Buffer to read from
 */
function Reader(buffer) {

    /**
     * Read buffer.
     * @type {Uint8Array}
     */
    this.buf = buffer;

    /**
     * Read buffer position.
     * @type {number}
     */
    this.pos = 0;

    /**
     * Read buffer length.
     * @type {number}
     */
    this.len = buffer.length;
}

var create_array = typeof Uint8Array !== "undefined"
    ? function create_typed_array(buffer) {
        if (buffer instanceof Uint8Array || Array.isArray(buffer))
            return new Reader(buffer);
        throw Error("illegal buffer");
    }
    /* istanbul ignore next */
    : function create_array(buffer) {
        if (Array.isArray(buffer))
            return new Reader(buffer);
        throw Error("illegal buffer");
    };

var create = function create() {
    return util.Buffer
        ? function create_buffer_setup(buffer) {
            return (Reader.create = function create_buffer(buffer) {
                return util.Buffer.isBuffer(buffer)
                    ? new BufferReader(buffer)
                    /* istanbul ignore next */
                    : create_array(buffer);
            })(buffer);
        }
        /* istanbul ignore next */
        : create_array;
};

/**
 * Creates a new reader using the specified buffer.
 * @function
 * @param {Uint8Array|Buffer} buffer Buffer to read from
 * @returns {Reader|BufferReader} A {@link BufferReader} if `buffer` is a Buffer, otherwise a {@link Reader}
 * @throws {Error} If `buffer` is not a valid buffer
 */
Reader.create = create();

Reader.prototype._slice = util.Array.prototype.subarray || /* istanbul ignore next */ util.Array.prototype.slice;

/**
 * Reads a varint as an unsigned 32 bit value.
 * @function
 * @returns {number} Value read
 */
Reader.prototype.uint32 = (function read_uint32_setup() {
    var value = 4294967295; // optimizer type-hint, tends to deopt otherwise (?!)
    return function read_uint32() {
        value = (         this.buf[this.pos] & 127       ) >>> 0; if (this.buf[this.pos++] < 128) return value;
        value = (value | (this.buf[this.pos] & 127) <<  7) >>> 0; if (this.buf[this.pos++] < 128) return value;
        value = (value | (this.buf[this.pos] & 127) << 14) >>> 0; if (this.buf[this.pos++] < 128) return value;
        value = (value | (this.buf[this.pos] & 127) << 21) >>> 0; if (this.buf[this.pos++] < 128) return value;
        value = (value | (this.buf[this.pos] &  15) << 28) >>> 0; if (this.buf[this.pos++] < 128) return value;

        /* istanbul ignore if */
        if ((this.pos += 5) > this.len) {
            this.pos = this.len;
            throw indexOutOfRange(this, 10);
        }
        return value;
    };
})();

/**
 * Reads a varint as a signed 32 bit value.
 * @returns {number} Value read
 */
Reader.prototype.int32 = function read_int32() {
    return this.uint32() | 0;
};

/**
 * Reads a zig-zag encoded varint as a signed 32 bit value.
 * @returns {number} Value read
 */
Reader.prototype.sint32 = function read_sint32() {
    var value = this.uint32();
    return value >>> 1 ^ -(value & 1) | 0;
};

/* eslint-disable no-invalid-this */

function readLongVarint() {
    // tends to deopt with local vars for octet etc.
    var bits = new LongBits(0, 0);
    var i = 0;
    if (this.len - this.pos > 4) { // fast route (lo)
        for (; i < 4; ++i) {
            // 1st..4th
            bits.lo = (bits.lo | (this.buf[this.pos] & 127) << i * 7) >>> 0;
            if (this.buf[this.pos++] < 128)
                return bits;
        }
        // 5th
        bits.lo = (bits.lo | (this.buf[this.pos] & 127) << 28) >>> 0;
        bits.hi = (bits.hi | (this.buf[this.pos] & 127) >>  4) >>> 0;
        if (this.buf[this.pos++] < 128)
            return bits;
        i = 0;
    } else {
        for (; i < 3; ++i) {
            /* istanbul ignore if */
            if (this.pos >= this.len)
                throw indexOutOfRange(this);
            // 1st..3th
            bits.lo = (bits.lo | (this.buf[this.pos] & 127) << i * 7) >>> 0;
            if (this.buf[this.pos++] < 128)
                return bits;
        }
        // 4th
        bits.lo = (bits.lo | (this.buf[this.pos++] & 127) << i * 7) >>> 0;
        return bits;
    }
    if (this.len - this.pos > 4) { // fast route (hi)
        for (; i < 5; ++i) {
            // 6th..10th
            bits.hi = (bits.hi | (this.buf[this.pos] & 127) << i * 7 + 3) >>> 0;
            if (this.buf[this.pos++] < 128)
                return bits;
        }
    } else {
        for (; i < 5; ++i) {
            /* istanbul ignore if */
            if (this.pos >= this.len)
                throw indexOutOfRange(this);
            // 6th..10th
            bits.hi = (bits.hi | (this.buf[this.pos] & 127) << i * 7 + 3) >>> 0;
            if (this.buf[this.pos++] < 128)
                return bits;
        }
    }
    /* istanbul ignore next */
    throw Error("invalid varint encoding");
}

/* eslint-enable no-invalid-this */

/**
 * Reads a varint as a signed 64 bit value.
 * @name Reader#int64
 * @function
 * @returns {Long} Value read
 */

/**
 * Reads a varint as an unsigned 64 bit value.
 * @name Reader#uint64
 * @function
 * @returns {Long} Value read
 */

/**
 * Reads a zig-zag encoded varint as a signed 64 bit value.
 * @name Reader#sint64
 * @function
 * @returns {Long} Value read
 */

/**
 * Reads a varint as a boolean.
 * @returns {boolean} Value read
 */
Reader.prototype.bool = function read_bool() {
    return this.uint32() !== 0;
};

function readFixed32_end(buf, end) { // note that this uses `end`, not `pos`
    return (buf[end - 4]
          | buf[end - 3] << 8
          | buf[end - 2] << 16
          | buf[end - 1] << 24) >>> 0;
}

/**
 * Reads fixed 32 bits as an unsigned 32 bit integer.
 * @returns {number} Value read
 */
Reader.prototype.fixed32 = function read_fixed32() {

    /* istanbul ignore if */
    if (this.pos + 4 > this.len)
        throw indexOutOfRange(this, 4);

    return readFixed32_end(this.buf, this.pos += 4);
};

/**
 * Reads fixed 32 bits as a signed 32 bit integer.
 * @returns {number} Value read
 */
Reader.prototype.sfixed32 = function read_sfixed32() {

    /* istanbul ignore if */
    if (this.pos + 4 > this.len)
        throw indexOutOfRange(this, 4);

    return readFixed32_end(this.buf, this.pos += 4) | 0;
};

/* eslint-disable no-invalid-this */

function readFixed64(/* this: Reader */) {

    /* istanbul ignore if */
    if (this.pos + 8 > this.len)
        throw indexOutOfRange(this, 8);

    return new LongBits(readFixed32_end(this.buf, this.pos += 4), readFixed32_end(this.buf, this.pos += 4));
}

/* eslint-enable no-invalid-this */

/**
 * Reads fixed 64 bits.
 * @name Reader#fixed64
 * @function
 * @returns {Long} Value read
 */

/**
 * Reads zig-zag encoded fixed 64 bits.
 * @name Reader#sfixed64
 * @function
 * @returns {Long} Value read
 */

/**
 * Reads a float (32 bit) as a number.
 * @function
 * @returns {number} Value read
 */
Reader.prototype.float = function read_float() {

    /* istanbul ignore if */
    if (this.pos + 4 > this.len)
        throw indexOutOfRange(this, 4);

    var value = util.float.readFloatLE(this.buf, this.pos);
    this.pos += 4;
    return value;
};

/**
 * Reads a double (64 bit float) as a number.
 * @function
 * @returns {number} Value read
 */
Reader.prototype.double = function read_double() {

    /* istanbul ignore if */
    if (this.pos + 8 > this.len)
        throw indexOutOfRange(this, 4);

    var value = util.float.readDoubleLE(this.buf, this.pos);
    this.pos += 8;
    return value;
};

/**
 * Reads a sequence of bytes preceeded by its length as a varint.
 * @returns {Uint8Array} Value read
 */
Reader.prototype.bytes = function read_bytes() {
    var length = this.uint32(),
        start  = this.pos,
        end    = this.pos + length;

    /* istanbul ignore if */
    if (end > this.len)
        throw indexOutOfRange(this, length);

    this.pos += length;
    if (Array.isArray(this.buf)) // plain array
        return this.buf.slice(start, end);
    return start === end // fix for IE 10/Win8 and others' subarray returning array of size 1
        ? new this.buf.constructor(0)
        : this._slice.call(this.buf, start, end);
};

/**
 * Reads a string preceeded by its byte length as a varint.
 * @returns {string} Value read
 */
Reader.prototype.string = function read_string() {
    var bytes = this.bytes();
    return utf8.read(bytes, 0, bytes.length);
};

/**
 * Skips the specified number of bytes if specified, otherwise skips a varint.
 * @param {number} [length] Length if known, otherwise a varint is assumed
 * @returns {Reader} `this`
 */
Reader.prototype.skip = function skip(length) {
    if (typeof length === "number") {
        /* istanbul ignore if */
        if (this.pos + length > this.len)
            throw indexOutOfRange(this, length);
        this.pos += length;
    } else {
        do {
            /* istanbul ignore if */
            if (this.pos >= this.len)
                throw indexOutOfRange(this);
        } while (this.buf[this.pos++] & 128);
    }
    return this;
};

/**
 * Skips the next element of the specified wire type.
 * @param {number} wireType Wire type received
 * @returns {Reader} `this`
 */
Reader.prototype.skipType = function(wireType) {
    switch (wireType) {
        case 0:
            this.skip();
            break;
        case 1:
            this.skip(8);
            break;
        case 2:
            this.skip(this.uint32());
            break;
        case 3:
            while ((wireType = this.uint32() & 7) !== 4) {
                this.skipType(wireType);
            }
            break;
        case 5:
            this.skip(4);
            break;

        /* istanbul ignore next */
        default:
            throw Error("invalid wire type " + wireType + " at offset " + this.pos);
    }
    return this;
};

Reader._configure = function(BufferReader_) {
    BufferReader = BufferReader_;
    Reader.create = create();
    BufferReader._configure();

    var fn = util.Long ? "toLong" : /* istanbul ignore next */ "toNumber";
    util.merge(Reader.prototype, {

        int64: function read_int64() {
            return readLongVarint.call(this)[fn](false);
        },

        uint64: function read_uint64() {
            return readLongVarint.call(this)[fn](true);
        },

        sint64: function read_sint64() {
            return readLongVarint.call(this).zzDecode()[fn](false);
        },

        fixed64: function read_fixed64() {
            return readFixed64.call(this)[fn](true);
        },

        sfixed64: function read_sfixed64() {
            return readFixed64.call(this)[fn](false);
        }

    });
};


/***/ }),

/***/ 15213:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

"use strict";

module.exports = BufferReader;

// extends Reader
var Reader = __webpack_require__(95199);
(BufferReader.prototype = Object.create(Reader.prototype)).constructor = BufferReader;

var util = __webpack_require__(18932);

/**
 * Constructs a new buffer reader instance.
 * @classdesc Wire format reader using node buffers.
 * @extends Reader
 * @constructor
 * @param {Buffer} buffer Buffer to read from
 */
function BufferReader(buffer) {
    Reader.call(this, buffer);

    /**
     * Read buffer.
     * @name BufferReader#buf
     * @type {Buffer}
     */
}

BufferReader._configure = function () {
    /* istanbul ignore else */
    if (util.Buffer)
        BufferReader.prototype._slice = util.Buffer.prototype.slice;
};


/**
 * @override
 */
BufferReader.prototype.string = function read_string_buffer() {
    var len = this.uint32(); // modifies pos
    return this.buf.utf8Slice
        ? this.buf.utf8Slice(this.pos, this.pos = Math.min(this.pos + len, this.len))
        : this.buf.toString("utf-8", this.pos, this.pos = Math.min(this.pos + len, this.len));
};

/**
 * Reads a sequence of bytes preceeded by its length as a varint.
 * @name BufferReader#bytes
 * @function
 * @returns {Buffer} Value read
 */

BufferReader._configure();


/***/ }),

/***/ 10182:
/***/ ((module) => {

"use strict";

module.exports = {};

/**
 * Named roots.
 * This is where pbjs stores generated structures (the option `-r, --root` specifies a name).
 * Can also be used manually to make roots available accross modules.
 * @name roots
 * @type {Object.<string,Root>}
 * @example
 * // pbjs -r myroot -o compiled.js ...
 *
 * // in another module:
 * require("./compiled.js");
 *
 * // in any subsequent module:
 * var root = protobuf.roots["myroot"];
 */


/***/ }),

/***/ 69226:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";


/**
 * Streaming RPC helpers.
 * @namespace
 */
var rpc = exports;

/**
 * RPC implementation passed to {@link Service#create} performing a service request on network level, i.e. by utilizing http requests or websockets.
 * @typedef RPCImpl
 * @type {function}
 * @param {Method|rpc.ServiceMethod<Message<{}>,Message<{}>>} method Reflected or static method being called
 * @param {Uint8Array} requestData Request data
 * @param {RPCImplCallback} callback Callback function
 * @returns {undefined}
 * @example
 * function rpcImpl(method, requestData, callback) {
 *     if (protobuf.util.lcFirst(method.name) !== "myMethod") // compatible with static code
 *         throw Error("no such method");
 *     asynchronouslyObtainAResponse(requestData, function(err, responseData) {
 *         callback(err, responseData);
 *     });
 * }
 */

/**
 * Node-style callback as used by {@link RPCImpl}.
 * @typedef RPCImplCallback
 * @type {function}
 * @param {Error|null} error Error, if any, otherwise `null`
 * @param {Uint8Array|null} [response] Response data or `null` to signal end of stream, if there hasn't been an error
 * @returns {undefined}
 */

rpc.Service = __webpack_require__(12741);


/***/ }),

/***/ 12741:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

"use strict";

module.exports = Service;

var util = __webpack_require__(18932);

// Extends EventEmitter
(Service.prototype = Object.create(util.EventEmitter.prototype)).constructor = Service;

/**
 * A service method callback as used by {@link rpc.ServiceMethod|ServiceMethod}.
 *
 * Differs from {@link RPCImplCallback} in that it is an actual callback of a service method which may not return `response = null`.
 * @typedef rpc.ServiceMethodCallback
 * @template TRes extends Message<TRes>
 * @type {function}
 * @param {Error|null} error Error, if any
 * @param {TRes} [response] Response message
 * @returns {undefined}
 */

/**
 * A service method part of a {@link rpc.Service} as created by {@link Service.create}.
 * @typedef rpc.ServiceMethod
 * @template TReq extends Message<TReq>
 * @template TRes extends Message<TRes>
 * @type {function}
 * @param {TReq|Properties<TReq>} request Request message or plain object
 * @param {rpc.ServiceMethodCallback<TRes>} [callback] Node-style callback called with the error, if any, and the response message
 * @returns {Promise<Message<TRes>>} Promise if `callback` has been omitted, otherwise `undefined`
 */

/**
 * Constructs a new RPC service instance.
 * @classdesc An RPC service as returned by {@link Service#create}.
 * @exports rpc.Service
 * @extends util.EventEmitter
 * @constructor
 * @param {RPCImpl} rpcImpl RPC implementation
 * @param {boolean} [requestDelimited=false] Whether requests are length-delimited
 * @param {boolean} [responseDelimited=false] Whether responses are length-delimited
 */
function Service(rpcImpl, requestDelimited, responseDelimited) {

    if (typeof rpcImpl !== "function")
        throw TypeError("rpcImpl must be a function");

    util.EventEmitter.call(this);

    /**
     * RPC implementation. Becomes `null` once the service is ended.
     * @type {RPCImpl|null}
     */
    this.rpcImpl = rpcImpl;

    /**
     * Whether requests are length-delimited.
     * @type {boolean}
     */
    this.requestDelimited = Boolean(requestDelimited);

    /**
     * Whether responses are length-delimited.
     * @type {boolean}
     */
    this.responseDelimited = Boolean(responseDelimited);
}

/**
 * Calls a service method through {@link rpc.Service#rpcImpl|rpcImpl}.
 * @param {Method|rpc.ServiceMethod<TReq,TRes>} method Reflected or static method
 * @param {Constructor<TReq>} requestCtor Request constructor
 * @param {Constructor<TRes>} responseCtor Response constructor
 * @param {TReq|Properties<TReq>} request Request message or plain object
 * @param {rpc.ServiceMethodCallback<TRes>} callback Service callback
 * @returns {undefined}
 * @template TReq extends Message<TReq>
 * @template TRes extends Message<TRes>
 */
Service.prototype.rpcCall = function rpcCall(method, requestCtor, responseCtor, request, callback) {

    if (!request)
        throw TypeError("request must be specified");

    var self = this;
    if (!callback)
        return util.asPromise(rpcCall, self, method, requestCtor, responseCtor, request);

    if (!self.rpcImpl) {
        setTimeout(function() { callback(Error("already ended")); }, 0);
        return undefined;
    }

    try {
        return self.rpcImpl(
            method,
            requestCtor[self.requestDelimited ? "encodeDelimited" : "encode"](request).finish(),
            function rpcCallback(err, response) {

                if (err) {
                    self.emit("error", err, method);
                    return callback(err);
                }

                if (response === null) {
                    self.end(/* endedByRPC */ true);
                    return undefined;
                }

                if (!(response instanceof responseCtor)) {
                    try {
                        response = responseCtor[self.responseDelimited ? "decodeDelimited" : "decode"](response);
                    } catch (err) {
                        self.emit("error", err, method);
                        return callback(err);
                    }
                }

                self.emit("data", response, method);
                return callback(null, response);
            }
        );
    } catch (err) {
        self.emit("error", err, method);
        setTimeout(function() { callback(err); }, 0);
        return undefined;
    }
};

/**
 * Ends this service and emits the `end` event.
 * @param {boolean} [endedByRPC=false] Whether the service has been ended by the RPC implementation.
 * @returns {rpc.Service} `this`
 */
Service.prototype.end = function end(endedByRPC) {
    if (this.rpcImpl) {
        if (!endedByRPC) // signal end to rpcImpl
            this.rpcImpl(null, null, null);
        this.rpcImpl = null;
        this.emit("end").off();
    }
    return this;
};


/***/ }),

/***/ 41168:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

"use strict";

module.exports = LongBits;

var util = __webpack_require__(18932);

/**
 * Constructs new long bits.
 * @classdesc Helper class for working with the low and high bits of a 64 bit value.
 * @memberof util
 * @constructor
 * @param {number} lo Low 32 bits, unsigned
 * @param {number} hi High 32 bits, unsigned
 */
function LongBits(lo, hi) {

    // note that the casts below are theoretically unnecessary as of today, but older statically
    // generated converter code might still call the ctor with signed 32bits. kept for compat.

    /**
     * Low bits.
     * @type {number}
     */
    this.lo = lo >>> 0;

    /**
     * High bits.
     * @type {number}
     */
    this.hi = hi >>> 0;
}

/**
 * Zero bits.
 * @memberof util.LongBits
 * @type {util.LongBits}
 */
var zero = LongBits.zero = new LongBits(0, 0);

zero.toNumber = function() { return 0; };
zero.zzEncode = zero.zzDecode = function() { return this; };
zero.length = function() { return 1; };

/**
 * Zero hash.
 * @memberof util.LongBits
 * @type {string}
 */
var zeroHash = LongBits.zeroHash = "\0\0\0\0\0\0\0\0";

/**
 * Constructs new long bits from the specified number.
 * @param {number} value Value
 * @returns {util.LongBits} Instance
 */
LongBits.fromNumber = function fromNumber(value) {
    if (value === 0)
        return zero;
    var sign = value < 0;
    if (sign)
        value = -value;
    var lo = value >>> 0,
        hi = (value - lo) / 4294967296 >>> 0;
    if (sign) {
        hi = ~hi >>> 0;
        lo = ~lo >>> 0;
        if (++lo > 4294967295) {
            lo = 0;
            if (++hi > 4294967295)
                hi = 0;
        }
    }
    return new LongBits(lo, hi);
};

/**
 * Constructs new long bits from a number, long or string.
 * @param {Long|number|string} value Value
 * @returns {util.LongBits} Instance
 */
LongBits.from = function from(value) {
    if (typeof value === "number")
        return LongBits.fromNumber(value);
    if (util.isString(value)) {
        /* istanbul ignore else */
        if (util.Long)
            value = util.Long.fromString(value);
        else
            return LongBits.fromNumber(parseInt(value, 10));
    }
    return value.low || value.high ? new LongBits(value.low >>> 0, value.high >>> 0) : zero;
};

/**
 * Converts this long bits to a possibly unsafe JavaScript number.
 * @param {boolean} [unsigned=false] Whether unsigned or not
 * @returns {number} Possibly unsafe number
 */
LongBits.prototype.toNumber = function toNumber(unsigned) {
    if (!unsigned && this.hi >>> 31) {
        var lo = ~this.lo + 1 >>> 0,
            hi = ~this.hi     >>> 0;
        if (!lo)
            hi = hi + 1 >>> 0;
        return -(lo + hi * 4294967296);
    }
    return this.lo + this.hi * 4294967296;
};

/**
 * Converts this long bits to a long.
 * @param {boolean} [unsigned=false] Whether unsigned or not
 * @returns {Long} Long
 */
LongBits.prototype.toLong = function toLong(unsigned) {
    return util.Long
        ? new util.Long(this.lo | 0, this.hi | 0, Boolean(unsigned))
        /* istanbul ignore next */
        : { low: this.lo | 0, high: this.hi | 0, unsigned: Boolean(unsigned) };
};

var charCodeAt = String.prototype.charCodeAt;

/**
 * Constructs new long bits from the specified 8 characters long hash.
 * @param {string} hash Hash
 * @returns {util.LongBits} Bits
 */
LongBits.fromHash = function fromHash(hash) {
    if (hash === zeroHash)
        return zero;
    return new LongBits(
        ( charCodeAt.call(hash, 0)
        | charCodeAt.call(hash, 1) << 8
        | charCodeAt.call(hash, 2) << 16
        | charCodeAt.call(hash, 3) << 24) >>> 0
    ,
        ( charCodeAt.call(hash, 4)
        | charCodeAt.call(hash, 5) << 8
        | charCodeAt.call(hash, 6) << 16
        | charCodeAt.call(hash, 7) << 24) >>> 0
    );
};

/**
 * Converts this long bits to a 8 characters long hash.
 * @returns {string} Hash
 */
LongBits.prototype.toHash = function toHash() {
    return String.fromCharCode(
        this.lo        & 255,
        this.lo >>> 8  & 255,
        this.lo >>> 16 & 255,
        this.lo >>> 24      ,
        this.hi        & 255,
        this.hi >>> 8  & 255,
        this.hi >>> 16 & 255,
        this.hi >>> 24
    );
};

/**
 * Zig-zag encodes this long bits.
 * @returns {util.LongBits} `this`
 */
LongBits.prototype.zzEncode = function zzEncode() {
    var mask =   this.hi >> 31;
    this.hi  = ((this.hi << 1 | this.lo >>> 31) ^ mask) >>> 0;
    this.lo  = ( this.lo << 1                   ^ mask) >>> 0;
    return this;
};

/**
 * Zig-zag decodes this long bits.
 * @returns {util.LongBits} `this`
 */
LongBits.prototype.zzDecode = function zzDecode() {
    var mask = -(this.lo & 1);
    this.lo  = ((this.lo >>> 1 | this.hi << 31) ^ mask) >>> 0;
    this.hi  = ( this.hi >>> 1                  ^ mask) >>> 0;
    return this;
};

/**
 * Calculates the length of this longbits when encoded as a varint.
 * @returns {number} Length
 */
LongBits.prototype.length = function length() {
    var part0 =  this.lo,
        part1 = (this.lo >>> 28 | this.hi << 4) >>> 0,
        part2 =  this.hi >>> 24;
    return part2 === 0
         ? part1 === 0
           ? part0 < 16384
             ? part0 < 128 ? 1 : 2
             : part0 < 2097152 ? 3 : 4
           : part1 < 16384
             ? part1 < 128 ? 5 : 6
             : part1 < 2097152 ? 7 : 8
         : part2 < 128 ? 9 : 10;
};


/***/ }),

/***/ 18932:
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";

var util = exports;

// used to return a Promise where callback is omitted
util.asPromise = __webpack_require__(18670);

// converts to / from base64 encoded strings
util.base64 = __webpack_require__(36009);

// base class of rpc.Service
util.EventEmitter = __webpack_require__(50107);

// float handling accross browsers
util.float = __webpack_require__(71188);

// requires modules optionally and hides the call from bundlers
util.inquire = __webpack_require__(28031);

// converts to / from utf8 encoded strings
util.utf8 = __webpack_require__(67148);

// provides a node-like buffer pool in the browser
util.pool = __webpack_require__(14314);

// utility to work with the low and high bits of a 64 bit value
util.LongBits = __webpack_require__(41168);

/**
 * Whether running within node or not.
 * @memberof util
 * @type {boolean}
 */
util.isNode = Boolean(typeof global !== "undefined"
                   && global
                   && global.process
                   && global.process.versions
                   && global.process.versions.node);

/**
 * Global object reference.
 * @memberof util
 * @type {Object}
 */
util.global = util.isNode && global
           || typeof window !== "undefined" && window
           || typeof self   !== "undefined" && self
           || this; // eslint-disable-line no-invalid-this

/**
 * An immuable empty array.
 * @memberof util
 * @type {Array.<*>}
 * @const
 */
util.emptyArray = Object.freeze ? Object.freeze([]) : /* istanbul ignore next */ []; // used on prototypes

/**
 * An immutable empty object.
 * @type {Object}
 * @const
 */
util.emptyObject = Object.freeze ? Object.freeze({}) : /* istanbul ignore next */ {}; // used on prototypes

/**
 * Tests if the specified value is an integer.
 * @function
 * @param {*} value Value to test
 * @returns {boolean} `true` if the value is an integer
 */
util.isInteger = Number.isInteger || /* istanbul ignore next */ function isInteger(value) {
    return typeof value === "number" && isFinite(value) && Math.floor(value) === value;
};

/**
 * Tests if the specified value is a string.
 * @param {*} value Value to test
 * @returns {boolean} `true` if the value is a string
 */
util.isString = function isString(value) {
    return typeof value === "string" || value instanceof String;
};

/**
 * Tests if the specified value is a non-null object.
 * @param {*} value Value to test
 * @returns {boolean} `true` if the value is a non-null object
 */
util.isObject = function isObject(value) {
    return value && typeof value === "object";
};

/**
 * Checks if a property on a message is considered to be present.
 * This is an alias of {@link util.isSet}.
 * @function
 * @param {Object} obj Plain object or message instance
 * @param {string} prop Property name
 * @returns {boolean} `true` if considered to be present, otherwise `false`
 */
util.isset =

/**
 * Checks if a property on a message is considered to be present.
 * @param {Object} obj Plain object or message instance
 * @param {string} prop Property name
 * @returns {boolean} `true` if considered to be present, otherwise `false`
 */
util.isSet = function isSet(obj, prop) {
    var value = obj[prop];
    if (value != null && obj.hasOwnProperty(prop)) // eslint-disable-line eqeqeq, no-prototype-builtins
        return typeof value !== "object" || (Array.isArray(value) ? value.length : Object.keys(value).length) > 0;
    return false;
};

/**
 * Any compatible Buffer instance.
 * This is a minimal stand-alone definition of a Buffer instance. The actual type is that exported by node's typings.
 * @interface Buffer
 * @extends Uint8Array
 */

/**
 * Node's Buffer class if available.
 * @type {Constructor<Buffer>}
 */
util.Buffer = (function() {
    try {
        var Buffer = util.inquire("buffer").Buffer;
        // refuse to use non-node buffers if not explicitly assigned (perf reasons):
        return Buffer.prototype.utf8Write ? Buffer : /* istanbul ignore next */ null;
    } catch (e) {
        /* istanbul ignore next */
        return null;
    }
})();

// Internal alias of or polyfull for Buffer.from.
util._Buffer_from = null;

// Internal alias of or polyfill for Buffer.allocUnsafe.
util._Buffer_allocUnsafe = null;

/**
 * Creates a new buffer of whatever type supported by the environment.
 * @param {number|number[]} [sizeOrArray=0] Buffer size or number array
 * @returns {Uint8Array|Buffer} Buffer
 */
util.newBuffer = function newBuffer(sizeOrArray) {
    /* istanbul ignore next */
    return typeof sizeOrArray === "number"
        ? util.Buffer
            ? util._Buffer_allocUnsafe(sizeOrArray)
            : new util.Array(sizeOrArray)
        : util.Buffer
            ? util._Buffer_from(sizeOrArray)
            : typeof Uint8Array === "undefined"
                ? sizeOrArray
                : new Uint8Array(sizeOrArray);
};

/**
 * Array implementation used in the browser. `Uint8Array` if supported, otherwise `Array`.
 * @type {Constructor<Uint8Array>}
 */
util.Array = typeof Uint8Array !== "undefined" ? Uint8Array /* istanbul ignore next */ : Array;

/**
 * Any compatible Long instance.
 * This is a minimal stand-alone definition of a Long instance. The actual type is that exported by long.js.
 * @interface Long
 * @property {number} low Low bits
 * @property {number} high High bits
 * @property {boolean} unsigned Whether unsigned or not
 */

/**
 * Long.js's Long class if available.
 * @type {Constructor<Long>}
 */
util.Long = /* istanbul ignore next */ util.global.dcodeIO && /* istanbul ignore next */ util.global.dcodeIO.Long
         || /* istanbul ignore next */ util.global.Long
         || util.inquire("long");

/**
 * Regular expression used to verify 2 bit (`bool`) map keys.
 * @type {RegExp}
 * @const
 */
util.key2Re = /^true|false|0|1$/;

/**
 * Regular expression used to verify 32 bit (`int32` etc.) map keys.
 * @type {RegExp}
 * @const
 */
util.key32Re = /^-?(?:0|[1-9][0-9]*)$/;

/**
 * Regular expression used to verify 64 bit (`int64` etc.) map keys.
 * @type {RegExp}
 * @const
 */
util.key64Re = /^(?:[\\x00-\\xff]{8}|-?(?:0|[1-9][0-9]*))$/;

/**
 * Converts a number or long to an 8 characters long hash string.
 * @param {Long|number} value Value to convert
 * @returns {string} Hash
 */
util.longToHash = function longToHash(value) {
    return value
        ? util.LongBits.from(value).toHash()
        : util.LongBits.zeroHash;
};

/**
 * Converts an 8 characters long hash string to a long or number.
 * @param {string} hash Hash
 * @param {boolean} [unsigned=false] Whether unsigned or not
 * @returns {Long|number} Original value
 */
util.longFromHash = function longFromHash(hash, unsigned) {
    var bits = util.LongBits.fromHash(hash);
    if (util.Long)
        return util.Long.fromBits(bits.lo, bits.hi, unsigned);
    return bits.toNumber(Boolean(unsigned));
};

/**
 * Merges the properties of the source object into the destination object.
 * @memberof util
 * @param {Object.<string,*>} dst Destination object
 * @param {Object.<string,*>} src Source object
 * @param {boolean} [ifNotSet=false] Merges only if the key is not already set
 * @returns {Object.<string,*>} Destination object
 */
function merge(dst, src, ifNotSet) { // used by converters
    for (var keys = Object.keys(src), i = 0; i < keys.length; ++i)
        if (dst[keys[i]] === undefined || !ifNotSet)
            dst[keys[i]] = src[keys[i]];
    return dst;
}

util.merge = merge;

/**
 * Converts the first character of a string to lower case.
 * @param {string} str String to convert
 * @returns {string} Converted string
 */
util.lcFirst = function lcFirst(str) {
    return str.charAt(0).toLowerCase() + str.substring(1);
};

/**
 * Creates a custom error constructor.
 * @memberof util
 * @param {string} name Error name
 * @returns {Constructor<Error>} Custom error constructor
 */
function newError(name) {

    function CustomError(message, properties) {

        if (!(this instanceof CustomError))
            return new CustomError(message, properties);

        // Error.call(this, message);
        // ^ just returns a new error instance because the ctor can be called as a function

        Object.defineProperty(this, "message", { get: function() { return message; } });

        /* istanbul ignore next */
        if (Error.captureStackTrace) // node
            Error.captureStackTrace(this, CustomError);
        else
            Object.defineProperty(this, "stack", { value: new Error().stack || "" });

        if (properties)
            merge(this, properties);
    }

    (CustomError.prototype = Object.create(Error.prototype)).constructor = CustomError;

    Object.defineProperty(CustomError.prototype, "name", { get: function() { return name; } });

    CustomError.prototype.toString = function toString() {
        return this.name + ": " + this.message;
    };

    return CustomError;
}

util.newError = newError;

/**
 * Constructs a new protocol error.
 * @classdesc Error subclass indicating a protocol specifc error.
 * @memberof util
 * @extends Error
 * @template T extends Message<T>
 * @constructor
 * @param {string} message Error message
 * @param {Object.<string,*>} [properties] Additional properties
 * @example
 * try {
 *     MyMessage.decode(someBuffer); // throws if required fields are missing
 * } catch (e) {
 *     if (e instanceof ProtocolError && e.instance)
 *         console.log("decoded so far: " + JSON.stringify(e.instance));
 * }
 */
util.ProtocolError = newError("ProtocolError");

/**
 * So far decoded message instance.
 * @name util.ProtocolError#instance
 * @type {Message<T>}
 */

/**
 * A OneOf getter as returned by {@link util.oneOfGetter}.
 * @typedef OneOfGetter
 * @type {function}
 * @returns {string|undefined} Set field name, if any
 */

/**
 * Builds a getter for a oneof's present field name.
 * @param {string[]} fieldNames Field names
 * @returns {OneOfGetter} Unbound getter
 */
util.oneOfGetter = function getOneOf(fieldNames) {
    var fieldMap = {};
    for (var i = 0; i < fieldNames.length; ++i)
        fieldMap[fieldNames[i]] = 1;

    /**
     * @returns {string|undefined} Set field name, if any
     * @this Object
     * @ignore
     */
    return function() { // eslint-disable-line consistent-return
        for (var keys = Object.keys(this), i = keys.length - 1; i > -1; --i)
            if (fieldMap[keys[i]] === 1 && this[keys[i]] !== undefined && this[keys[i]] !== null)
                return keys[i];
    };
};

/**
 * A OneOf setter as returned by {@link util.oneOfSetter}.
 * @typedef OneOfSetter
 * @type {function}
 * @param {string|undefined} value Field name
 * @returns {undefined}
 */

/**
 * Builds a setter for a oneof's present field name.
 * @param {string[]} fieldNames Field names
 * @returns {OneOfSetter} Unbound setter
 */
util.oneOfSetter = function setOneOf(fieldNames) {

    /**
     * @param {string} name Field name
     * @returns {undefined}
     * @this Object
     * @ignore
     */
    return function(name) {
        for (var i = 0; i < fieldNames.length; ++i)
            if (fieldNames[i] !== name)
                delete this[fieldNames[i]];
    };
};

/**
 * Default conversion options used for {@link Message#toJSON} implementations.
 *
 * These options are close to proto3's JSON mapping with the exception that internal types like Any are handled just like messages. More precisely:
 *
 * - Longs become strings
 * - Enums become string keys
 * - Bytes become base64 encoded strings
 * - (Sub-)Messages become plain objects
 * - Maps become plain objects with all string keys
 * - Repeated fields become arrays
 * - NaN and Infinity for float and double fields become strings
 *
 * @type {IConversionOptions}
 * @see https://developers.google.com/protocol-buffers/docs/proto3?hl=en#json
 */
util.toJSONOptions = {
    longs: String,
    enums: String,
    bytes: String,
    json: true
};

// Sets up buffer utility according to the environment (called in index-minimal)
util._configure = function() {
    var Buffer = util.Buffer;
    /* istanbul ignore if */
    if (!Buffer) {
        util._Buffer_from = util._Buffer_allocUnsafe = null;
        return;
    }
    // because node 4.x buffers are incompatible & immutable
    // see: https://github.com/dcodeIO/protobuf.js/pull/665
    util._Buffer_from = Buffer.from !== Uint8Array.from && Buffer.from ||
        /* istanbul ignore next */
        function Buffer_from(value, encoding) {
            return new Buffer(value, encoding);
        };
    util._Buffer_allocUnsafe = Buffer.allocUnsafe ||
        /* istanbul ignore next */
        function Buffer_allocUnsafe(size) {
            return new Buffer(size);
        };
};


/***/ }),

/***/ 84353:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

"use strict";

module.exports = Writer;

var util      = __webpack_require__(18932);

var BufferWriter; // cyclic

var LongBits  = util.LongBits,
    base64    = util.base64,
    utf8      = util.utf8;

/**
 * Constructs a new writer operation instance.
 * @classdesc Scheduled writer operation.
 * @constructor
 * @param {function(*, Uint8Array, number)} fn Function to call
 * @param {number} len Value byte length
 * @param {*} val Value to write
 * @ignore
 */
function Op(fn, len, val) {

    /**
     * Function to call.
     * @type {function(Uint8Array, number, *)}
     */
    this.fn = fn;

    /**
     * Value byte length.
     * @type {number}
     */
    this.len = len;

    /**
     * Next operation.
     * @type {Writer.Op|undefined}
     */
    this.next = undefined;

    /**
     * Value to write.
     * @type {*}
     */
    this.val = val; // type varies
}

/* istanbul ignore next */
function noop() {} // eslint-disable-line no-empty-function

/**
 * Constructs a new writer state instance.
 * @classdesc Copied writer state.
 * @memberof Writer
 * @constructor
 * @param {Writer} writer Writer to copy state from
 * @ignore
 */
function State(writer) {

    /**
     * Current head.
     * @type {Writer.Op}
     */
    this.head = writer.head;

    /**
     * Current tail.
     * @type {Writer.Op}
     */
    this.tail = writer.tail;

    /**
     * Current buffer length.
     * @type {number}
     */
    this.len = writer.len;

    /**
     * Next state.
     * @type {State|null}
     */
    this.next = writer.states;
}

/**
 * Constructs a new writer instance.
 * @classdesc Wire format writer using `Uint8Array` if available, otherwise `Array`.
 * @constructor
 */
function Writer() {

    /**
     * Current length.
     * @type {number}
     */
    this.len = 0;

    /**
     * Operations head.
     * @type {Object}
     */
    this.head = new Op(noop, 0, 0);

    /**
     * Operations tail
     * @type {Object}
     */
    this.tail = this.head;

    /**
     * Linked forked states.
     * @type {Object|null}
     */
    this.states = null;

    // When a value is written, the writer calculates its byte length and puts it into a linked
    // list of operations to perform when finish() is called. This both allows us to allocate
    // buffers of the exact required size and reduces the amount of work we have to do compared
    // to first calculating over objects and then encoding over objects. In our case, the encoding
    // part is just a linked list walk calling operations with already prepared values.
}

var create = function create() {
    return util.Buffer
        ? function create_buffer_setup() {
            return (Writer.create = function create_buffer() {
                return new BufferWriter();
            })();
        }
        /* istanbul ignore next */
        : function create_array() {
            return new Writer();
        };
};

/**
 * Creates a new writer.
 * @function
 * @returns {BufferWriter|Writer} A {@link BufferWriter} when Buffers are supported, otherwise a {@link Writer}
 */
Writer.create = create();

/**
 * Allocates a buffer of the specified size.
 * @param {number} size Buffer size
 * @returns {Uint8Array} Buffer
 */
Writer.alloc = function alloc(size) {
    return new util.Array(size);
};

// Use Uint8Array buffer pool in the browser, just like node does with buffers
/* istanbul ignore else */
if (util.Array !== Array)
    Writer.alloc = util.pool(Writer.alloc, util.Array.prototype.subarray);

/**
 * Pushes a new operation to the queue.
 * @param {function(Uint8Array, number, *)} fn Function to call
 * @param {number} len Value byte length
 * @param {number} val Value to write
 * @returns {Writer} `this`
 * @private
 */
Writer.prototype._push = function push(fn, len, val) {
    this.tail = this.tail.next = new Op(fn, len, val);
    this.len += len;
    return this;
};

function writeByte(val, buf, pos) {
    buf[pos] = val & 255;
}

function writeVarint32(val, buf, pos) {
    while (val > 127) {
        buf[pos++] = val & 127 | 128;
        val >>>= 7;
    }
    buf[pos] = val;
}

/**
 * Constructs a new varint writer operation instance.
 * @classdesc Scheduled varint writer operation.
 * @extends Op
 * @constructor
 * @param {number} len Value byte length
 * @param {number} val Value to write
 * @ignore
 */
function VarintOp(len, val) {
    this.len = len;
    this.next = undefined;
    this.val = val;
}

VarintOp.prototype = Object.create(Op.prototype);
VarintOp.prototype.fn = writeVarint32;

/**
 * Writes an unsigned 32 bit value as a varint.
 * @param {number} value Value to write
 * @returns {Writer} `this`
 */
Writer.prototype.uint32 = function write_uint32(value) {
    // here, the call to this.push has been inlined and a varint specific Op subclass is used.
    // uint32 is by far the most frequently used operation and benefits significantly from this.
    this.len += (this.tail = this.tail.next = new VarintOp(
        (value = value >>> 0)
                < 128       ? 1
        : value < 16384     ? 2
        : value < 2097152   ? 3
        : value < 268435456 ? 4
        :                     5,
    value)).len;
    return this;
};

/**
 * Writes a signed 32 bit value as a varint.
 * @function
 * @param {number} value Value to write
 * @returns {Writer} `this`
 */
Writer.prototype.int32 = function write_int32(value) {
    return value < 0
        ? this._push(writeVarint64, 10, LongBits.fromNumber(value)) // 10 bytes per spec
        : this.uint32(value);
};

/**
 * Writes a 32 bit value as a varint, zig-zag encoded.
 * @param {number} value Value to write
 * @returns {Writer} `this`
 */
Writer.prototype.sint32 = function write_sint32(value) {
    return this.uint32((value << 1 ^ value >> 31) >>> 0);
};

function writeVarint64(val, buf, pos) {
    while (val.hi) {
        buf[pos++] = val.lo & 127 | 128;
        val.lo = (val.lo >>> 7 | val.hi << 25) >>> 0;
        val.hi >>>= 7;
    }
    while (val.lo > 127) {
        buf[pos++] = val.lo & 127 | 128;
        val.lo = val.lo >>> 7;
    }
    buf[pos++] = val.lo;
}

/**
 * Writes an unsigned 64 bit value as a varint.
 * @param {Long|number|string} value Value to write
 * @returns {Writer} `this`
 * @throws {TypeError} If `value` is a string and no long library is present.
 */
Writer.prototype.uint64 = function write_uint64(value) {
    var bits = LongBits.from(value);
    return this._push(writeVarint64, bits.length(), bits);
};

/**
 * Writes a signed 64 bit value as a varint.
 * @function
 * @param {Long|number|string} value Value to write
 * @returns {Writer} `this`
 * @throws {TypeError} If `value` is a string and no long library is present.
 */
Writer.prototype.int64 = Writer.prototype.uint64;

/**
 * Writes a signed 64 bit value as a varint, zig-zag encoded.
 * @param {Long|number|string} value Value to write
 * @returns {Writer} `this`
 * @throws {TypeError} If `value` is a string and no long library is present.
 */
Writer.prototype.sint64 = function write_sint64(value) {
    var bits = LongBits.from(value).zzEncode();
    return this._push(writeVarint64, bits.length(), bits);
};

/**
 * Writes a boolish value as a varint.
 * @param {boolean} value Value to write
 * @returns {Writer} `this`
 */
Writer.prototype.bool = function write_bool(value) {
    return this._push(writeByte, 1, value ? 1 : 0);
};

function writeFixed32(val, buf, pos) {
    buf[pos    ] =  val         & 255;
    buf[pos + 1] =  val >>> 8   & 255;
    buf[pos + 2] =  val >>> 16  & 255;
    buf[pos + 3] =  val >>> 24;
}

/**
 * Writes an unsigned 32 bit value as fixed 32 bits.
 * @param {number} value Value to write
 * @returns {Writer} `this`
 */
Writer.prototype.fixed32 = function write_fixed32(value) {
    return this._push(writeFixed32, 4, value >>> 0);
};

/**
 * Writes a signed 32 bit value as fixed 32 bits.
 * @function
 * @param {number} value Value to write
 * @returns {Writer} `this`
 */
Writer.prototype.sfixed32 = Writer.prototype.fixed32;

/**
 * Writes an unsigned 64 bit value as fixed 64 bits.
 * @param {Long|number|string} value Value to write
 * @returns {Writer} `this`
 * @throws {TypeError} If `value` is a string and no long library is present.
 */
Writer.prototype.fixed64 = function write_fixed64(value) {
    var bits = LongBits.from(value);
    return this._push(writeFixed32, 4, bits.lo)._push(writeFixed32, 4, bits.hi);
};

/**
 * Writes a signed 64 bit value as fixed 64 bits.
 * @function
 * @param {Long|number|string} value Value to write
 * @returns {Writer} `this`
 * @throws {TypeError} If `value` is a string and no long library is present.
 */
Writer.prototype.sfixed64 = Writer.prototype.fixed64;

/**
 * Writes a float (32 bit).
 * @function
 * @param {number} value Value to write
 * @returns {Writer} `this`
 */
Writer.prototype.float = function write_float(value) {
    return this._push(util.float.writeFloatLE, 4, value);
};

/**
 * Writes a double (64 bit float).
 * @function
 * @param {number} value Value to write
 * @returns {Writer} `this`
 */
Writer.prototype.double = function write_double(value) {
    return this._push(util.float.writeDoubleLE, 8, value);
};

var writeBytes = util.Array.prototype.set
    ? function writeBytes_set(val, buf, pos) {
        buf.set(val, pos); // also works for plain array values
    }
    /* istanbul ignore next */
    : function writeBytes_for(val, buf, pos) {
        for (var i = 0; i < val.length; ++i)
            buf[pos + i] = val[i];
    };

/**
 * Writes a sequence of bytes.
 * @param {Uint8Array|string} value Buffer or base64 encoded string to write
 * @returns {Writer} `this`
 */
Writer.prototype.bytes = function write_bytes(value) {
    var len = value.length >>> 0;
    if (!len)
        return this._push(writeByte, 1, 0);
    if (util.isString(value)) {
        var buf = Writer.alloc(len = base64.length(value));
        base64.decode(value, buf, 0);
        value = buf;
    }
    return this.uint32(len)._push(writeBytes, len, value);
};

/**
 * Writes a string.
 * @param {string} value Value to write
 * @returns {Writer} `this`
 */
Writer.prototype.string = function write_string(value) {
    var len = utf8.length(value);
    return len
        ? this.uint32(len)._push(utf8.write, len, value)
        : this._push(writeByte, 1, 0);
};

/**
 * Forks this writer's state by pushing it to a stack.
 * Calling {@link Writer#reset|reset} or {@link Writer#ldelim|ldelim} resets the writer to the previous state.
 * @returns {Writer} `this`
 */
Writer.prototype.fork = function fork() {
    this.states = new State(this);
    this.head = this.tail = new Op(noop, 0, 0);
    this.len = 0;
    return this;
};

/**
 * Resets this instance to the last state.
 * @returns {Writer} `this`
 */
Writer.prototype.reset = function reset() {
    if (this.states) {
        this.head   = this.states.head;
        this.tail   = this.states.tail;
        this.len    = this.states.len;
        this.states = this.states.next;
    } else {
        this.head = this.tail = new Op(noop, 0, 0);
        this.len  = 0;
    }
    return this;
};

/**
 * Resets to the last state and appends the fork state's current write length as a varint followed by its operations.
 * @returns {Writer} `this`
 */
Writer.prototype.ldelim = function ldelim() {
    var head = this.head,
        tail = this.tail,
        len  = this.len;
    this.reset().uint32(len);
    if (len) {
        this.tail.next = head.next; // skip noop
        this.tail = tail;
        this.len += len;
    }
    return this;
};

/**
 * Finishes the write operation.
 * @returns {Uint8Array} Finished buffer
 */
Writer.prototype.finish = function finish() {
    var head = this.head.next, // skip noop
        buf  = this.constructor.alloc(this.len),
        pos  = 0;
    while (head) {
        head.fn(head.val, buf, pos);
        pos += head.len;
        head = head.next;
    }
    // this.head = this.tail = null;
    return buf;
};

Writer._configure = function(BufferWriter_) {
    BufferWriter = BufferWriter_;
    Writer.create = create();
    BufferWriter._configure();
};


/***/ }),

/***/ 81978:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

"use strict";

module.exports = BufferWriter;

// extends Writer
var Writer = __webpack_require__(84353);
(BufferWriter.prototype = Object.create(Writer.prototype)).constructor = BufferWriter;

var util = __webpack_require__(18932);

/**
 * Constructs a new buffer writer instance.
 * @classdesc Wire format writer using node buffers.
 * @extends Writer
 * @constructor
 */
function BufferWriter() {
    Writer.call(this);
}

BufferWriter._configure = function () {
    /**
     * Allocates a buffer of the specified size.
     * @function
     * @param {number} size Buffer size
     * @returns {Buffer} Buffer
     */
    BufferWriter.alloc = util._Buffer_allocUnsafe;

    BufferWriter.writeBytesBuffer = util.Buffer && util.Buffer.prototype instanceof Uint8Array && util.Buffer.prototype.set.name === "set"
        ? function writeBytesBuffer_set(val, buf, pos) {
          buf.set(val, pos); // faster than copy (requires node >= 4 where Buffers extend Uint8Array and set is properly inherited)
          // also works for plain array values
        }
        /* istanbul ignore next */
        : function writeBytesBuffer_copy(val, buf, pos) {
          if (val.copy) // Buffer values
            val.copy(buf, pos, 0, val.length);
          else for (var i = 0; i < val.length;) // plain array values
            buf[pos++] = val[i++];
        };
};


/**
 * @override
 */
BufferWriter.prototype.bytes = function write_bytes_buffer(value) {
    if (util.isString(value))
        value = util._Buffer_from(value, "base64");
    var len = value.length >>> 0;
    this.uint32(len);
    if (len)
        this._push(BufferWriter.writeBytesBuffer, len, value);
    return this;
};

function writeStringBuffer(val, buf, pos) {
    if (val.length < 40) // plain js is faster for short strings (probably due to redundant assertions)
        util.utf8.write(val, buf, pos);
    else if (buf.utf8Write)
        buf.utf8Write(val, pos);
    else
        buf.write(val, pos);
}

/**
 * @override
 */
BufferWriter.prototype.string = function write_string_buffer(value) {
    var len = util.Buffer.byteLength(value);
    this.uint32(len);
    if (len)
        this._push(writeStringBuffer, len, value);
    return this;
};


/**
 * Finishes the write operation.
 * @name BufferWriter#finish
 * @function
 * @returns {Buffer} Finished buffer
 */

BufferWriter._configure();


/***/ }),

/***/ 77308:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {


const { instantiateSync } = __webpack_require__(28332);
const fs = __webpack_require__(57147)

loadWebAssembly.supported = typeof WebAssembly !== 'undefined'

async function loadWebAssembly (imp = {}) {
  if (!loadWebAssembly.supported) return null
  
  return instantiateSync(fs.readFileSync(__dirname + "/../dist/rabin.wasm"), imp);
}
module.exports = loadWebAssembly


/***/ }),

/***/ 67893:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

const Rabin = __webpack_require__(99894)
const getRabin = __webpack_require__(77308)

const create = async (avg, min, max, windowSize, polynomial) => {
    const compiled = await getRabin()
    return new Rabin(compiled, avg, min, max, windowSize, polynomial)
}

module.exports = {
    Rabin,
    create
}


/***/ }),

/***/ 99894:
/***/ ((module) => {

/**
 * Rabin fingerprinting
 *
 * @class Rabin
 */
class Rabin {
    /**
     * Creates an instance of Rabin.
     * @param { import("./../dist/rabin-wasm") } asModule
     * @param {number} [bits=12]
     * @param {number} [min=8 * 1024]
     * @param {number} [max=32 * 1024]
     * @param {number} polynomial
     * @memberof Rabin
     */
    constructor(asModule, bits = 12, min = 8 * 1024, max = 32 * 1024, windowSize = 64, polynomial) {
        this.bits = bits
        this.min = min
        this.max = max
        this.asModule = asModule
        this.rabin = new asModule.Rabin(bits, min, max, windowSize, polynomial)
        this.polynomial = polynomial
    }

    /**
     * Fingerprints the buffer
     *
     * @param {Uint8Array} buf
     * @returns {Array<number>}
     * @memberof Rabin
     */
    fingerprint(buf) {
        const {
            __retain,
            __release,
            __allocArray,
            __getInt32Array,
            Int32Array_ID,
            Uint8Array_ID
        } = this.asModule

        const lengths = new Int32Array(Math.ceil(buf.length/this.min))
        const lengthsPtr = __retain(__allocArray(Int32Array_ID, lengths))
        const pointer = __retain(__allocArray(Uint8Array_ID, buf))

        const out = this.rabin.fingerprint(pointer, lengthsPtr)
        const processed = __getInt32Array(out)

        __release(pointer)
        __release(lengthsPtr)

        const end = processed.indexOf(0);
        return end >= 0 ? processed.subarray(0, end) : processed;
    }
}

module.exports = Rabin

/***/ }),

/***/ 18520:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

module.exports = __webpack_require__(47095);

/***/ }),

/***/ 47095:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

var RetryOperation = __webpack_require__(5020);

exports.operation = function(options) {
  var timeouts = exports.timeouts(options);
  return new RetryOperation(timeouts, {
      forever: options && (options.forever || options.retries === Infinity),
      unref: options && options.unref,
      maxRetryTime: options && options.maxRetryTime
  });
};

exports.timeouts = function(options) {
  if (options instanceof Array) {
    return [].concat(options);
  }

  var opts = {
    retries: 10,
    factor: 2,
    minTimeout: 1 * 1000,
    maxTimeout: Infinity,
    randomize: false
  };
  for (var key in options) {
    opts[key] = options[key];
  }

  if (opts.minTimeout > opts.maxTimeout) {
    throw new Error('minTimeout is greater than maxTimeout');
  }

  var timeouts = [];
  for (var i = 0; i < opts.retries; i++) {
    timeouts.push(this.createTimeout(i, opts));
  }

  if (options && options.forever && !timeouts.length) {
    timeouts.push(this.createTimeout(i, opts));
  }

  // sort the array numerically ascending
  timeouts.sort(function(a,b) {
    return a - b;
  });

  return timeouts;
};

exports.createTimeout = function(attempt, opts) {
  var random = (opts.randomize)
    ? (Math.random() + 1)
    : 1;

  var timeout = Math.round(random * Math.max(opts.minTimeout, 1) * Math.pow(opts.factor, attempt));
  timeout = Math.min(timeout, opts.maxTimeout);

  return timeout;
};

exports.wrap = function(obj, options, methods) {
  if (options instanceof Array) {
    methods = options;
    options = null;
  }

  if (!methods) {
    methods = [];
    for (var key in obj) {
      if (typeof obj[key] === 'function') {
        methods.push(key);
      }
    }
  }

  for (var i = 0; i < methods.length; i++) {
    var method   = methods[i];
    var original = obj[method];

    obj[method] = function retryWrapper(original) {
      var op       = exports.operation(options);
      var args     = Array.prototype.slice.call(arguments, 1);
      var callback = args.pop();

      args.push(function(err) {
        if (op.retry(err)) {
          return;
        }
        if (err) {
          arguments[0] = op.mainError();
        }
        callback.apply(this, arguments);
      });

      op.attempt(function() {
        original.apply(obj, args);
      });
    }.bind(obj, original);
    obj[method].options = options;
  }
};


/***/ }),

/***/ 5020:
/***/ ((module) => {

function RetryOperation(timeouts, options) {
  // Compatibility for the old (timeouts, retryForever) signature
  if (typeof options === 'boolean') {
    options = { forever: options };
  }

  this._originalTimeouts = JSON.parse(JSON.stringify(timeouts));
  this._timeouts = timeouts;
  this._options = options || {};
  this._maxRetryTime = options && options.maxRetryTime || Infinity;
  this._fn = null;
  this._errors = [];
  this._attempts = 1;
  this._operationTimeout = null;
  this._operationTimeoutCb = null;
  this._timeout = null;
  this._operationStart = null;
  this._timer = null;

  if (this._options.forever) {
    this._cachedTimeouts = this._timeouts.slice(0);
  }
}
module.exports = RetryOperation;

RetryOperation.prototype.reset = function() {
  this._attempts = 1;
  this._timeouts = this._originalTimeouts.slice(0);
}

RetryOperation.prototype.stop = function() {
  if (this._timeout) {
    clearTimeout(this._timeout);
  }
  if (this._timer) {
    clearTimeout(this._timer);
  }

  this._timeouts       = [];
  this._cachedTimeouts = null;
};

RetryOperation.prototype.retry = function(err) {
  if (this._timeout) {
    clearTimeout(this._timeout);
  }

  if (!err) {
    return false;
  }
  var currentTime = new Date().getTime();
  if (err && currentTime - this._operationStart >= this._maxRetryTime) {
    this._errors.push(err);
    this._errors.unshift(new Error('RetryOperation timeout occurred'));
    return false;
  }

  this._errors.push(err);

  var timeout = this._timeouts.shift();
  if (timeout === undefined) {
    if (this._cachedTimeouts) {
      // retry forever, only keep last error
      this._errors.splice(0, this._errors.length - 1);
      timeout = this._cachedTimeouts.slice(-1);
    } else {
      return false;
    }
  }

  var self = this;
  this._timer = setTimeout(function() {
    self._attempts++;

    if (self._operationTimeoutCb) {
      self._timeout = setTimeout(function() {
        self._operationTimeoutCb(self._attempts);
      }, self._operationTimeout);

      if (self._options.unref) {
          self._timeout.unref();
      }
    }

    self._fn(self._attempts);
  }, timeout);

  if (this._options.unref) {
      this._timer.unref();
  }

  return true;
};

RetryOperation.prototype.attempt = function(fn, timeoutOps) {
  this._fn = fn;

  if (timeoutOps) {
    if (timeoutOps.timeout) {
      this._operationTimeout = timeoutOps.timeout;
    }
    if (timeoutOps.cb) {
      this._operationTimeoutCb = timeoutOps.cb;
    }
  }

  var self = this;
  if (this._operationTimeoutCb) {
    this._timeout = setTimeout(function() {
      self._operationTimeoutCb();
    }, self._operationTimeout);
  }

  this._operationStart = new Date().getTime();

  this._fn(this._attempts);
};

RetryOperation.prototype.try = function(fn) {
  console.log('Using RetryOperation.try() is deprecated');
  this.attempt(fn);
};

RetryOperation.prototype.start = function(fn) {
  console.log('Using RetryOperation.start() is deprecated');
  this.attempt(fn);
};

RetryOperation.prototype.start = RetryOperation.prototype.try;

RetryOperation.prototype.errors = function() {
  return this._errors;
};

RetryOperation.prototype.attempts = function() {
  return this._attempts;
};

RetryOperation.prototype.mainError = function() {
  if (this._errors.length === 0) {
    return null;
  }

  var counts = {};
  var mainError = null;
  var mainErrorCount = 0;

  for (var i = 0; i < this._errors.length; i++) {
    var error = this._errors[i];
    var message = error.message;
    var count = (counts[message] || 0) + 1;

    counts[message] = count;

    if (count >= mainErrorCount) {
      mainError = error;
      mainErrorCount = count;
    }
  }

  return mainError;
};


/***/ }),

/***/ 50334:
/***/ ((module) => {

"use strict";


// JS treats subjects of bitwise operators as SIGNED 32 bit numbers,
// which means the maximum amount of bits we can store inside each byte
// is 7..
const BITS_PER_BYTE = 7

module.exports = class SparseArray {
  constructor () {
    this._bitArrays = []
    this._data = []
    this._length = 0
    this._changedLength = false
    this._changedData = false
  }

  set (index, value) {
    let pos = this._internalPositionFor(index, false)
    if (value === undefined) {
      // unsetting
      if (pos !== -1) {
        // remove item from bit array and array itself
        this._unsetInternalPos(pos)
        this._unsetBit(index)
        this._changedLength = true
        this._changedData = true
      }
    } else {
      let needsSort = false
      if (pos === -1) {
        pos = this._data.length
        this._setBit(index)
        this._changedData = true
      } else {
        needsSort = true
      }
      this._setInternalPos(pos, index, value, needsSort)
      this._changedLength = true
    }
  }

  unset (index) {
    this.set(index, undefined)
  }

  get (index) {
    this._sortData()
    const pos = this._internalPositionFor(index, true)
    if (pos === -1) {
      return undefined
    }
    return this._data[pos][1]
  }

  push (value) {
    this.set(this.length, value)
    return this.length
  }

  get length () {
    this._sortData()
    if (this._changedLength) {
      const last = this._data[this._data.length - 1]
      this._length = last ? last[0] + 1 : 0
      this._changedLength = false
    }
    return this._length
  }

  forEach (iterator) {
    let i = 0
    while(i < this.length) {
      iterator(this.get(i), i, this)
      i++
    }
  }

  map (iterator) {
    let i = 0
    let mapped = new Array(this.length)
    while(i < this.length) {
      mapped[i] = iterator(this.get(i), i, this)
      i++
    }
    return mapped
  }

  reduce (reducer, initialValue) {
    let i = 0
    let acc = initialValue
    while(i < this.length) {
      const value = this.get(i)
      acc = reducer(acc, value, i)
      i++
    }
    return acc
  }

  find (finder) {
    let i = 0, found, last
    while ((i < this.length) && !found) {
      last = this.get(i)
      found = finder(last)
      i++
    }
    return found ? last : undefined
  }

  _internalPositionFor (index, noCreate) {
    const bytePos = this._bytePosFor(index, noCreate)
    if (bytePos >= this._bitArrays.length) {
      return -1
    }
    const byte = this._bitArrays[bytePos]
    const bitPos = index - bytePos * BITS_PER_BYTE
    const exists = (byte & (1 << bitPos)) > 0
    if (!exists) {
      return -1
    }
    const previousPopCount = this._bitArrays.slice(0, bytePos).reduce(popCountReduce, 0)

    const mask = ~(0xffffffff << (bitPos + 1))
    const bytePopCount = popCount(byte & mask)
    const arrayPos = previousPopCount + bytePopCount - 1
    return arrayPos
  }

  _bytePosFor (index, noCreate) {
    const bytePos = Math.floor(index / BITS_PER_BYTE)
    const targetLength = bytePos + 1
    while (!noCreate && this._bitArrays.length < targetLength) {
      this._bitArrays.push(0)
    }
    return bytePos
  }

  _setBit (index) {
    const bytePos = this._bytePosFor(index, false)
    this._bitArrays[bytePos] |= (1 << (index - (bytePos * BITS_PER_BYTE)))
  }

  _unsetBit(index) {
    const bytePos = this._bytePosFor(index, false)
    this._bitArrays[bytePos] &= ~(1 << (index - (bytePos * BITS_PER_BYTE)))
  }

  _setInternalPos(pos, index, value, needsSort) {
    const data =this._data
    const elem = [index, value]
    if (needsSort) {
      this._sortData()
      data[pos] = elem
    } else {
      // new element. just shove it into the array
      // but be nice about where we shove it
      // in order to make sorting it later easier
      if (data.length) {
        if (data[data.length - 1][0] >= index) {
          data.push(elem)
        } else if (data[0][0] <= index) {
          data.unshift(elem)
        } else {
          const randomIndex = Math.round(data.length / 2)
          this._data = data.slice(0, randomIndex).concat(elem).concat(data.slice(randomIndex))
        }
      } else {
        this._data.push(elem)
      }
      this._changedData = true
      this._changedLength = true
    }
  }

  _unsetInternalPos (pos) {
    this._data.splice(pos, 1)
  }

  _sortData () {
    if (this._changedData) {
      this._data.sort(sortInternal)
    }

    this._changedData = false
  }

  bitField () {
    const bytes = []
    let pendingBitsForResultingByte = 8
    let pendingBitsForNewByte = 0
    let resultingByte = 0
    let newByte
    const pending = this._bitArrays.slice()
    while (pending.length || pendingBitsForNewByte) {
      if (pendingBitsForNewByte === 0) {
        newByte = pending.shift()
        pendingBitsForNewByte = 7
      }

      const usingBits = Math.min(pendingBitsForNewByte, pendingBitsForResultingByte)
      const mask = ~(0b11111111 << usingBits)
      const masked = newByte & mask
      resultingByte |= masked << (8 - pendingBitsForResultingByte)
      newByte = newByte >>> usingBits
      pendingBitsForNewByte -= usingBits
      pendingBitsForResultingByte -= usingBits

      if (!pendingBitsForResultingByte || (!pendingBitsForNewByte && !pending.length)) {
        bytes.push(resultingByte)
        resultingByte = 0
        pendingBitsForResultingByte = 8
      }
    }

    // remove trailing zeroes
    for(var i = bytes.length - 1; i > 0; i--) {
      const value = bytes[i]
      if (value === 0) {
        bytes.pop()
      } else {
        break
      }
    }

    return bytes
  }

  compactArray () {
    this._sortData()
    return this._data.map(valueOnly)
  }
}

function popCountReduce (count, byte) {
  return count + popCount(byte)
}

function popCount(_v) {
  let v = _v
  v = v - ((v >> 1) & 0x55555555)                    // reuse input as temporary
  v = (v & 0x33333333) + ((v >> 2) & 0x33333333)     // temp
  return ((v + (v >> 4) & 0xF0F0F0F) * 0x1010101) >> 24
}

function sortInternal (a, b) {
  return a[0] - b[0]
}

function valueOnly (elem) {
  return elem[1]
}

/***/ }),

/***/ 10275:
/***/ ((module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
function throttledQueue(maxRequestsPerInterval, interval, evenlySpaced) {
    if (evenlySpaced === void 0) { evenlySpaced = false; }
    /**
     * If all requests should be evenly spaced, adjust to suit.
     */
    if (evenlySpaced) {
        interval = interval / maxRequestsPerInterval;
        maxRequestsPerInterval = 1;
    }
    var queue = [];
    var lastIntervalStart = 0;
    var numRequestsPerInterval = 0;
    var timeout;
    /**
     * Gets called at a set interval to remove items from the queue.
     * This is a self-adjusting timer, since the browser's setTimeout is highly inaccurate.
     */
    var dequeue = function () {
        var intervalEnd = lastIntervalStart + interval;
        var now = Date.now();
        /**
         * Adjust the timer if it was called too early.
         */
        if (now < intervalEnd) {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
            timeout !== undefined && clearTimeout(timeout);
            timeout = setTimeout(dequeue, intervalEnd - now);
            return;
        }
        lastIntervalStart = now;
        numRequestsPerInterval = 0;
        for (var _i = 0, _a = queue.splice(0, maxRequestsPerInterval); _i < _a.length; _i++) {
            var callback = _a[_i];
            numRequestsPerInterval++;
            void callback();
        }
        if (queue.length) {
            timeout = setTimeout(dequeue, interval);
        }
        else {
            timeout = undefined;
        }
    };
    return function (fn) { return new Promise(function (resolve, reject) {
        var callback = function () { return Promise.resolve().then(fn).then(resolve).catch(reject); };
        var now = Date.now();
        if (timeout === undefined && (now - lastIntervalStart) > interval) {
            lastIntervalStart = now;
            numRequestsPerInterval = 0;
        }
        if (numRequestsPerInterval++ < maxRequestsPerInterval) {
            void callback();
        }
        else {
            queue.push(callback);
            if (timeout === undefined) {
                timeout = setTimeout(dequeue, lastIntervalStart + interval - now);
            }
        }
    }); };
}
module.exports = throttledQueue;
exports["default"] = throttledQueue;
//# sourceMappingURL=throttledQueue.js.map

/***/ }),

/***/ 57920:
/***/ ((module) => {

module.exports = read

var MSB = 0x80
  , REST = 0x7F

function read(buf, offset) {
  var res    = 0
    , offset = offset || 0
    , shift  = 0
    , counter = offset
    , b
    , l = buf.length

  do {
    if (counter >= l || shift > 49) {
      read.bytes = 0
      throw new RangeError('Could not decode varint')
    }
    b = buf[counter++]
    res += shift < 28
      ? (b & REST) << shift
      : (b & REST) * Math.pow(2, shift)
    shift += 7
  } while (b >= MSB)

  read.bytes = counter - offset

  return res
}


/***/ }),

/***/ 1684:
/***/ ((module) => {

module.exports = encode

var MSB = 0x80
  , REST = 0x7F
  , MSBALL = ~REST
  , INT = Math.pow(2, 31)

function encode(num, out, offset) {
  if (Number.MAX_SAFE_INTEGER && num > Number.MAX_SAFE_INTEGER) {
    encode.bytes = 0
    throw new RangeError('Could not encode varint')
  }
  out = out || []
  offset = offset || 0
  var oldOffset = offset

  while(num >= INT) {
    out[offset++] = (num & 0xFF) | MSB
    num /= 128
  }
  while(num & MSBALL) {
    out[offset++] = (num & 0xFF) | MSB
    num >>>= 7
  }
  out[offset] = num | 0
  
  encode.bytes = offset - oldOffset + 1
  
  return out
}


/***/ }),

/***/ 22782:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

module.exports = {
    encode: __webpack_require__(1684)
  , decode: __webpack_require__(57920)
  , encodingLength: __webpack_require__(1151)
}


/***/ }),

/***/ 1151:
/***/ ((module) => {


var N1 = Math.pow(2,  7)
var N2 = Math.pow(2, 14)
var N3 = Math.pow(2, 21)
var N4 = Math.pow(2, 28)
var N5 = Math.pow(2, 35)
var N6 = Math.pow(2, 42)
var N7 = Math.pow(2, 49)
var N8 = Math.pow(2, 56)
var N9 = Math.pow(2, 63)

module.exports = function (value) {
  return (
    value < N1 ? 1
  : value < N2 ? 2
  : value < N3 ? 3
  : value < N4 ? 4
  : value < N5 ? 5
  : value < N6 ? 6
  : value < N7 ? 7
  : value < N8 ? 8
  : value < N9 ? 9
  :              10
  )
}


/***/ }),

/***/ 7856:
/***/ (function(__unused_webpack_module, exports) {

/**
 * web-streams-polyfill v3.2.1
 */
(function (global, factory) {
     true ? factory(exports) :
    0;
}(this, (function (exports) { 'use strict';

    /// <reference lib="es2015.symbol" />
    var SymbolPolyfill = typeof Symbol === 'function' && typeof Symbol.iterator === 'symbol' ?
        Symbol :
        function (description) { return "Symbol(" + description + ")"; };

    /// <reference lib="dom" />
    function noop() {
        return undefined;
    }
    function getGlobals() {
        if (typeof self !== 'undefined') {
            return self;
        }
        else if (typeof window !== 'undefined') {
            return window;
        }
        else if (typeof global !== 'undefined') {
            return global;
        }
        return undefined;
    }
    var globals = getGlobals();

    function typeIsObject(x) {
        return (typeof x === 'object' && x !== null) || typeof x === 'function';
    }
    var rethrowAssertionErrorRejection = noop;

    var originalPromise = Promise;
    var originalPromiseThen = Promise.prototype.then;
    var originalPromiseResolve = Promise.resolve.bind(originalPromise);
    var originalPromiseReject = Promise.reject.bind(originalPromise);
    function newPromise(executor) {
        return new originalPromise(executor);
    }
    function promiseResolvedWith(value) {
        return originalPromiseResolve(value);
    }
    function promiseRejectedWith(reason) {
        return originalPromiseReject(reason);
    }
    function PerformPromiseThen(promise, onFulfilled, onRejected) {
        // There doesn't appear to be any way to correctly emulate the behaviour from JavaScript, so this is just an
        // approximation.
        return originalPromiseThen.call(promise, onFulfilled, onRejected);
    }
    function uponPromise(promise, onFulfilled, onRejected) {
        PerformPromiseThen(PerformPromiseThen(promise, onFulfilled, onRejected), undefined, rethrowAssertionErrorRejection);
    }
    function uponFulfillment(promise, onFulfilled) {
        uponPromise(promise, onFulfilled);
    }
    function uponRejection(promise, onRejected) {
        uponPromise(promise, undefined, onRejected);
    }
    function transformPromiseWith(promise, fulfillmentHandler, rejectionHandler) {
        return PerformPromiseThen(promise, fulfillmentHandler, rejectionHandler);
    }
    function setPromiseIsHandledToTrue(promise) {
        PerformPromiseThen(promise, undefined, rethrowAssertionErrorRejection);
    }
    var queueMicrotask = (function () {
        var globalQueueMicrotask = globals && globals.queueMicrotask;
        if (typeof globalQueueMicrotask === 'function') {
            return globalQueueMicrotask;
        }
        var resolvedPromise = promiseResolvedWith(undefined);
        return function (fn) { return PerformPromiseThen(resolvedPromise, fn); };
    })();
    function reflectCall(F, V, args) {
        if (typeof F !== 'function') {
            throw new TypeError('Argument is not a function');
        }
        return Function.prototype.apply.call(F, V, args);
    }
    function promiseCall(F, V, args) {
        try {
            return promiseResolvedWith(reflectCall(F, V, args));
        }
        catch (value) {
            return promiseRejectedWith(value);
        }
    }

    // Original from Chromium
    // https://chromium.googlesource.com/chromium/src/+/0aee4434a4dba42a42abaea9bfbc0cd196a63bc1/third_party/blink/renderer/core/streams/SimpleQueue.js
    var QUEUE_MAX_ARRAY_SIZE = 16384;
    /**
     * Simple queue structure.
     *
     * Avoids scalability issues with using a packed array directly by using
     * multiple arrays in a linked list and keeping the array size bounded.
     */
    var SimpleQueue = /** @class */ (function () {
        function SimpleQueue() {
            this._cursor = 0;
            this._size = 0;
            // _front and _back are always defined.
            this._front = {
                _elements: [],
                _next: undefined
            };
            this._back = this._front;
            // The cursor is used to avoid calling Array.shift().
            // It contains the index of the front element of the array inside the
            // front-most node. It is always in the range [0, QUEUE_MAX_ARRAY_SIZE).
            this._cursor = 0;
            // When there is only one node, size === elements.length - cursor.
            this._size = 0;
        }
        Object.defineProperty(SimpleQueue.prototype, "length", {
            get: function () {
                return this._size;
            },
            enumerable: false,
            configurable: true
        });
        // For exception safety, this method is structured in order:
        // 1. Read state
        // 2. Calculate required state mutations
        // 3. Perform state mutations
        SimpleQueue.prototype.push = function (element) {
            var oldBack = this._back;
            var newBack = oldBack;
            if (oldBack._elements.length === QUEUE_MAX_ARRAY_SIZE - 1) {
                newBack = {
                    _elements: [],
                    _next: undefined
                };
            }
            // push() is the mutation most likely to throw an exception, so it
            // goes first.
            oldBack._elements.push(element);
            if (newBack !== oldBack) {
                this._back = newBack;
                oldBack._next = newBack;
            }
            ++this._size;
        };
        // Like push(), shift() follows the read -> calculate -> mutate pattern for
        // exception safety.
        SimpleQueue.prototype.shift = function () { // must not be called on an empty queue
            var oldFront = this._front;
            var newFront = oldFront;
            var oldCursor = this._cursor;
            var newCursor = oldCursor + 1;
            var elements = oldFront._elements;
            var element = elements[oldCursor];
            if (newCursor === QUEUE_MAX_ARRAY_SIZE) {
                newFront = oldFront._next;
                newCursor = 0;
            }
            // No mutations before this point.
            --this._size;
            this._cursor = newCursor;
            if (oldFront !== newFront) {
                this._front = newFront;
            }
            // Permit shifted element to be garbage collected.
            elements[oldCursor] = undefined;
            return element;
        };
        // The tricky thing about forEach() is that it can be called
        // re-entrantly. The queue may be mutated inside the callback. It is easy to
        // see that push() within the callback has no negative effects since the end
        // of the queue is checked for on every iteration. If shift() is called
        // repeatedly within the callback then the next iteration may return an
        // element that has been removed. In this case the callback will be called
        // with undefined values until we either "catch up" with elements that still
        // exist or reach the back of the queue.
        SimpleQueue.prototype.forEach = function (callback) {
            var i = this._cursor;
            var node = this._front;
            var elements = node._elements;
            while (i !== elements.length || node._next !== undefined) {
                if (i === elements.length) {
                    node = node._next;
                    elements = node._elements;
                    i = 0;
                    if (elements.length === 0) {
                        break;
                    }
                }
                callback(elements[i]);
                ++i;
            }
        };
        // Return the element that would be returned if shift() was called now,
        // without modifying the queue.
        SimpleQueue.prototype.peek = function () { // must not be called on an empty queue
            var front = this._front;
            var cursor = this._cursor;
            return front._elements[cursor];
        };
        return SimpleQueue;
    }());

    function ReadableStreamReaderGenericInitialize(reader, stream) {
        reader._ownerReadableStream = stream;
        stream._reader = reader;
        if (stream._state === 'readable') {
            defaultReaderClosedPromiseInitialize(reader);
        }
        else if (stream._state === 'closed') {
            defaultReaderClosedPromiseInitializeAsResolved(reader);
        }
        else {
            defaultReaderClosedPromiseInitializeAsRejected(reader, stream._storedError);
        }
    }
    // A client of ReadableStreamDefaultReader and ReadableStreamBYOBReader may use these functions directly to bypass state
    // check.
    function ReadableStreamReaderGenericCancel(reader, reason) {
        var stream = reader._ownerReadableStream;
        return ReadableStreamCancel(stream, reason);
    }
    function ReadableStreamReaderGenericRelease(reader) {
        if (reader._ownerReadableStream._state === 'readable') {
            defaultReaderClosedPromiseReject(reader, new TypeError("Reader was released and can no longer be used to monitor the stream's closedness"));
        }
        else {
            defaultReaderClosedPromiseResetToRejected(reader, new TypeError("Reader was released and can no longer be used to monitor the stream's closedness"));
        }
        reader._ownerReadableStream._reader = undefined;
        reader._ownerReadableStream = undefined;
    }
    // Helper functions for the readers.
    function readerLockException(name) {
        return new TypeError('Cannot ' + name + ' a stream using a released reader');
    }
    // Helper functions for the ReadableStreamDefaultReader.
    function defaultReaderClosedPromiseInitialize(reader) {
        reader._closedPromise = newPromise(function (resolve, reject) {
            reader._closedPromise_resolve = resolve;
            reader._closedPromise_reject = reject;
        });
    }
    function defaultReaderClosedPromiseInitializeAsRejected(reader, reason) {
        defaultReaderClosedPromiseInitialize(reader);
        defaultReaderClosedPromiseReject(reader, reason);
    }
    function defaultReaderClosedPromiseInitializeAsResolved(reader) {
        defaultReaderClosedPromiseInitialize(reader);
        defaultReaderClosedPromiseResolve(reader);
    }
    function defaultReaderClosedPromiseReject(reader, reason) {
        if (reader._closedPromise_reject === undefined) {
            return;
        }
        setPromiseIsHandledToTrue(reader._closedPromise);
        reader._closedPromise_reject(reason);
        reader._closedPromise_resolve = undefined;
        reader._closedPromise_reject = undefined;
    }
    function defaultReaderClosedPromiseResetToRejected(reader, reason) {
        defaultReaderClosedPromiseInitializeAsRejected(reader, reason);
    }
    function defaultReaderClosedPromiseResolve(reader) {
        if (reader._closedPromise_resolve === undefined) {
            return;
        }
        reader._closedPromise_resolve(undefined);
        reader._closedPromise_resolve = undefined;
        reader._closedPromise_reject = undefined;
    }

    var AbortSteps = SymbolPolyfill('[[AbortSteps]]');
    var ErrorSteps = SymbolPolyfill('[[ErrorSteps]]');
    var CancelSteps = SymbolPolyfill('[[CancelSteps]]');
    var PullSteps = SymbolPolyfill('[[PullSteps]]');

    /// <reference lib="es2015.core" />
    // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Number/isFinite#Polyfill
    var NumberIsFinite = Number.isFinite || function (x) {
        return typeof x === 'number' && isFinite(x);
    };

    /// <reference lib="es2015.core" />
    // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math/trunc#Polyfill
    var MathTrunc = Math.trunc || function (v) {
        return v < 0 ? Math.ceil(v) : Math.floor(v);
    };

    // https://heycam.github.io/webidl/#idl-dictionaries
    function isDictionary(x) {
        return typeof x === 'object' || typeof x === 'function';
    }
    function assertDictionary(obj, context) {
        if (obj !== undefined && !isDictionary(obj)) {
            throw new TypeError(context + " is not an object.");
        }
    }
    // https://heycam.github.io/webidl/#idl-callback-functions
    function assertFunction(x, context) {
        if (typeof x !== 'function') {
            throw new TypeError(context + " is not a function.");
        }
    }
    // https://heycam.github.io/webidl/#idl-object
    function isObject(x) {
        return (typeof x === 'object' && x !== null) || typeof x === 'function';
    }
    function assertObject(x, context) {
        if (!isObject(x)) {
            throw new TypeError(context + " is not an object.");
        }
    }
    function assertRequiredArgument(x, position, context) {
        if (x === undefined) {
            throw new TypeError("Parameter " + position + " is required in '" + context + "'.");
        }
    }
    function assertRequiredField(x, field, context) {
        if (x === undefined) {
            throw new TypeError(field + " is required in '" + context + "'.");
        }
    }
    // https://heycam.github.io/webidl/#idl-unrestricted-double
    function convertUnrestrictedDouble(value) {
        return Number(value);
    }
    function censorNegativeZero(x) {
        return x === 0 ? 0 : x;
    }
    function integerPart(x) {
        return censorNegativeZero(MathTrunc(x));
    }
    // https://heycam.github.io/webidl/#idl-unsigned-long-long
    function convertUnsignedLongLongWithEnforceRange(value, context) {
        var lowerBound = 0;
        var upperBound = Number.MAX_SAFE_INTEGER;
        var x = Number(value);
        x = censorNegativeZero(x);
        if (!NumberIsFinite(x)) {
            throw new TypeError(context + " is not a finite number");
        }
        x = integerPart(x);
        if (x < lowerBound || x > upperBound) {
            throw new TypeError(context + " is outside the accepted range of " + lowerBound + " to " + upperBound + ", inclusive");
        }
        if (!NumberIsFinite(x) || x === 0) {
            return 0;
        }
        // TODO Use BigInt if supported?
        // let xBigInt = BigInt(integerPart(x));
        // xBigInt = BigInt.asUintN(64, xBigInt);
        // return Number(xBigInt);
        return x;
    }

    function assertReadableStream(x, context) {
        if (!IsReadableStream(x)) {
            throw new TypeError(context + " is not a ReadableStream.");
        }
    }

    // Abstract operations for the ReadableStream.
    function AcquireReadableStreamDefaultReader(stream) {
        return new ReadableStreamDefaultReader(stream);
    }
    // ReadableStream API exposed for controllers.
    function ReadableStreamAddReadRequest(stream, readRequest) {
        stream._reader._readRequests.push(readRequest);
    }
    function ReadableStreamFulfillReadRequest(stream, chunk, done) {
        var reader = stream._reader;
        var readRequest = reader._readRequests.shift();
        if (done) {
            readRequest._closeSteps();
        }
        else {
            readRequest._chunkSteps(chunk);
        }
    }
    function ReadableStreamGetNumReadRequests(stream) {
        return stream._reader._readRequests.length;
    }
    function ReadableStreamHasDefaultReader(stream) {
        var reader = stream._reader;
        if (reader === undefined) {
            return false;
        }
        if (!IsReadableStreamDefaultReader(reader)) {
            return false;
        }
        return true;
    }
    /**
     * A default reader vended by a {@link ReadableStream}.
     *
     * @public
     */
    var ReadableStreamDefaultReader = /** @class */ (function () {
        function ReadableStreamDefaultReader(stream) {
            assertRequiredArgument(stream, 1, 'ReadableStreamDefaultReader');
            assertReadableStream(stream, 'First parameter');
            if (IsReadableStreamLocked(stream)) {
                throw new TypeError('This stream has already been locked for exclusive reading by another reader');
            }
            ReadableStreamReaderGenericInitialize(this, stream);
            this._readRequests = new SimpleQueue();
        }
        Object.defineProperty(ReadableStreamDefaultReader.prototype, "closed", {
            /**
             * Returns a promise that will be fulfilled when the stream becomes closed,
             * or rejected if the stream ever errors or the reader's lock is released before the stream finishes closing.
             */
            get: function () {
                if (!IsReadableStreamDefaultReader(this)) {
                    return promiseRejectedWith(defaultReaderBrandCheckException('closed'));
                }
                return this._closedPromise;
            },
            enumerable: false,
            configurable: true
        });
        /**
         * If the reader is active, behaves the same as {@link ReadableStream.cancel | stream.cancel(reason)}.
         */
        ReadableStreamDefaultReader.prototype.cancel = function (reason) {
            if (reason === void 0) { reason = undefined; }
            if (!IsReadableStreamDefaultReader(this)) {
                return promiseRejectedWith(defaultReaderBrandCheckException('cancel'));
            }
            if (this._ownerReadableStream === undefined) {
                return promiseRejectedWith(readerLockException('cancel'));
            }
            return ReadableStreamReaderGenericCancel(this, reason);
        };
        /**
         * Returns a promise that allows access to the next chunk from the stream's internal queue, if available.
         *
         * If reading a chunk causes the queue to become empty, more data will be pulled from the underlying source.
         */
        ReadableStreamDefaultReader.prototype.read = function () {
            if (!IsReadableStreamDefaultReader(this)) {
                return promiseRejectedWith(defaultReaderBrandCheckException('read'));
            }
            if (this._ownerReadableStream === undefined) {
                return promiseRejectedWith(readerLockException('read from'));
            }
            var resolvePromise;
            var rejectPromise;
            var promise = newPromise(function (resolve, reject) {
                resolvePromise = resolve;
                rejectPromise = reject;
            });
            var readRequest = {
                _chunkSteps: function (chunk) { return resolvePromise({ value: chunk, done: false }); },
                _closeSteps: function () { return resolvePromise({ value: undefined, done: true }); },
                _errorSteps: function (e) { return rejectPromise(e); }
            };
            ReadableStreamDefaultReaderRead(this, readRequest);
            return promise;
        };
        /**
         * Releases the reader's lock on the corresponding stream. After the lock is released, the reader is no longer active.
         * If the associated stream is errored when the lock is released, the reader will appear errored in the same way
         * from now on; otherwise, the reader will appear closed.
         *
         * A reader's lock cannot be released while it still has a pending read request, i.e., if a promise returned by
         * the reader's {@link ReadableStreamDefaultReader.read | read()} method has not yet been settled. Attempting to
         * do so will throw a `TypeError` and leave the reader locked to the stream.
         */
        ReadableStreamDefaultReader.prototype.releaseLock = function () {
            if (!IsReadableStreamDefaultReader(this)) {
                throw defaultReaderBrandCheckException('releaseLock');
            }
            if (this._ownerReadableStream === undefined) {
                return;
            }
            if (this._readRequests.length > 0) {
                throw new TypeError('Tried to release a reader lock when that reader has pending read() calls un-settled');
            }
            ReadableStreamReaderGenericRelease(this);
        };
        return ReadableStreamDefaultReader;
    }());
    Object.defineProperties(ReadableStreamDefaultReader.prototype, {
        cancel: { enumerable: true },
        read: { enumerable: true },
        releaseLock: { enumerable: true },
        closed: { enumerable: true }
    });
    if (typeof SymbolPolyfill.toStringTag === 'symbol') {
        Object.defineProperty(ReadableStreamDefaultReader.prototype, SymbolPolyfill.toStringTag, {
            value: 'ReadableStreamDefaultReader',
            configurable: true
        });
    }
    // Abstract operations for the readers.
    function IsReadableStreamDefaultReader(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_readRequests')) {
            return false;
        }
        return x instanceof ReadableStreamDefaultReader;
    }
    function ReadableStreamDefaultReaderRead(reader, readRequest) {
        var stream = reader._ownerReadableStream;
        stream._disturbed = true;
        if (stream._state === 'closed') {
            readRequest._closeSteps();
        }
        else if (stream._state === 'errored') {
            readRequest._errorSteps(stream._storedError);
        }
        else {
            stream._readableStreamController[PullSteps](readRequest);
        }
    }
    // Helper functions for the ReadableStreamDefaultReader.
    function defaultReaderBrandCheckException(name) {
        return new TypeError("ReadableStreamDefaultReader.prototype." + name + " can only be used on a ReadableStreamDefaultReader");
    }

    /// <reference lib="es2018.asynciterable" />
    var _a;
    var AsyncIteratorPrototype;
    if (typeof SymbolPolyfill.asyncIterator === 'symbol') {
        // We're running inside a ES2018+ environment, but we're compiling to an older syntax.
        // We cannot access %AsyncIteratorPrototype% without non-ES2018 syntax, but we can re-create it.
        AsyncIteratorPrototype = (_a = {},
            // 25.1.3.1 %AsyncIteratorPrototype% [ @@asyncIterator ] ( )
            // https://tc39.github.io/ecma262/#sec-asynciteratorprototype-asynciterator
            _a[SymbolPolyfill.asyncIterator] = function () {
                return this;
            },
            _a);
        Object.defineProperty(AsyncIteratorPrototype, SymbolPolyfill.asyncIterator, { enumerable: false });
    }

    /// <reference lib="es2018.asynciterable" />
    var ReadableStreamAsyncIteratorImpl = /** @class */ (function () {
        function ReadableStreamAsyncIteratorImpl(reader, preventCancel) {
            this._ongoingPromise = undefined;
            this._isFinished = false;
            this._reader = reader;
            this._preventCancel = preventCancel;
        }
        ReadableStreamAsyncIteratorImpl.prototype.next = function () {
            var _this = this;
            var nextSteps = function () { return _this._nextSteps(); };
            this._ongoingPromise = this._ongoingPromise ?
                transformPromiseWith(this._ongoingPromise, nextSteps, nextSteps) :
                nextSteps();
            return this._ongoingPromise;
        };
        ReadableStreamAsyncIteratorImpl.prototype.return = function (value) {
            var _this = this;
            var returnSteps = function () { return _this._returnSteps(value); };
            return this._ongoingPromise ?
                transformPromiseWith(this._ongoingPromise, returnSteps, returnSteps) :
                returnSteps();
        };
        ReadableStreamAsyncIteratorImpl.prototype._nextSteps = function () {
            var _this = this;
            if (this._isFinished) {
                return Promise.resolve({ value: undefined, done: true });
            }
            var reader = this._reader;
            if (reader._ownerReadableStream === undefined) {
                return promiseRejectedWith(readerLockException('iterate'));
            }
            var resolvePromise;
            var rejectPromise;
            var promise = newPromise(function (resolve, reject) {
                resolvePromise = resolve;
                rejectPromise = reject;
            });
            var readRequest = {
                _chunkSteps: function (chunk) {
                    _this._ongoingPromise = undefined;
                    // This needs to be delayed by one microtask, otherwise we stop pulling too early which breaks a test.
                    // FIXME Is this a bug in the specification, or in the test?
                    queueMicrotask(function () { return resolvePromise({ value: chunk, done: false }); });
                },
                _closeSteps: function () {
                    _this._ongoingPromise = undefined;
                    _this._isFinished = true;
                    ReadableStreamReaderGenericRelease(reader);
                    resolvePromise({ value: undefined, done: true });
                },
                _errorSteps: function (reason) {
                    _this._ongoingPromise = undefined;
                    _this._isFinished = true;
                    ReadableStreamReaderGenericRelease(reader);
                    rejectPromise(reason);
                }
            };
            ReadableStreamDefaultReaderRead(reader, readRequest);
            return promise;
        };
        ReadableStreamAsyncIteratorImpl.prototype._returnSteps = function (value) {
            if (this._isFinished) {
                return Promise.resolve({ value: value, done: true });
            }
            this._isFinished = true;
            var reader = this._reader;
            if (reader._ownerReadableStream === undefined) {
                return promiseRejectedWith(readerLockException('finish iterating'));
            }
            if (!this._preventCancel) {
                var result = ReadableStreamReaderGenericCancel(reader, value);
                ReadableStreamReaderGenericRelease(reader);
                return transformPromiseWith(result, function () { return ({ value: value, done: true }); });
            }
            ReadableStreamReaderGenericRelease(reader);
            return promiseResolvedWith({ value: value, done: true });
        };
        return ReadableStreamAsyncIteratorImpl;
    }());
    var ReadableStreamAsyncIteratorPrototype = {
        next: function () {
            if (!IsReadableStreamAsyncIterator(this)) {
                return promiseRejectedWith(streamAsyncIteratorBrandCheckException('next'));
            }
            return this._asyncIteratorImpl.next();
        },
        return: function (value) {
            if (!IsReadableStreamAsyncIterator(this)) {
                return promiseRejectedWith(streamAsyncIteratorBrandCheckException('return'));
            }
            return this._asyncIteratorImpl.return(value);
        }
    };
    if (AsyncIteratorPrototype !== undefined) {
        Object.setPrototypeOf(ReadableStreamAsyncIteratorPrototype, AsyncIteratorPrototype);
    }
    // Abstract operations for the ReadableStream.
    function AcquireReadableStreamAsyncIterator(stream, preventCancel) {
        var reader = AcquireReadableStreamDefaultReader(stream);
        var impl = new ReadableStreamAsyncIteratorImpl(reader, preventCancel);
        var iterator = Object.create(ReadableStreamAsyncIteratorPrototype);
        iterator._asyncIteratorImpl = impl;
        return iterator;
    }
    function IsReadableStreamAsyncIterator(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_asyncIteratorImpl')) {
            return false;
        }
        try {
            // noinspection SuspiciousTypeOfGuard
            return x._asyncIteratorImpl instanceof
                ReadableStreamAsyncIteratorImpl;
        }
        catch (_a) {
            return false;
        }
    }
    // Helper functions for the ReadableStream.
    function streamAsyncIteratorBrandCheckException(name) {
        return new TypeError("ReadableStreamAsyncIterator." + name + " can only be used on a ReadableSteamAsyncIterator");
    }

    /// <reference lib="es2015.core" />
    // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Number/isNaN#Polyfill
    var NumberIsNaN = Number.isNaN || function (x) {
        // eslint-disable-next-line no-self-compare
        return x !== x;
    };

    function CreateArrayFromList(elements) {
        // We use arrays to represent lists, so this is basically a no-op.
        // Do a slice though just in case we happen to depend on the unique-ness.
        return elements.slice();
    }
    function CopyDataBlockBytes(dest, destOffset, src, srcOffset, n) {
        new Uint8Array(dest).set(new Uint8Array(src, srcOffset, n), destOffset);
    }
    // Not implemented correctly
    function TransferArrayBuffer(O) {
        return O;
    }
    // Not implemented correctly
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    function IsDetachedBuffer(O) {
        return false;
    }
    function ArrayBufferSlice(buffer, begin, end) {
        // ArrayBuffer.prototype.slice is not available on IE10
        // https://www.caniuse.com/mdn-javascript_builtins_arraybuffer_slice
        if (buffer.slice) {
            return buffer.slice(begin, end);
        }
        var length = end - begin;
        var slice = new ArrayBuffer(length);
        CopyDataBlockBytes(slice, 0, buffer, begin, length);
        return slice;
    }

    function IsNonNegativeNumber(v) {
        if (typeof v !== 'number') {
            return false;
        }
        if (NumberIsNaN(v)) {
            return false;
        }
        if (v < 0) {
            return false;
        }
        return true;
    }
    function CloneAsUint8Array(O) {
        var buffer = ArrayBufferSlice(O.buffer, O.byteOffset, O.byteOffset + O.byteLength);
        return new Uint8Array(buffer);
    }

    function DequeueValue(container) {
        var pair = container._queue.shift();
        container._queueTotalSize -= pair.size;
        if (container._queueTotalSize < 0) {
            container._queueTotalSize = 0;
        }
        return pair.value;
    }
    function EnqueueValueWithSize(container, value, size) {
        if (!IsNonNegativeNumber(size) || size === Infinity) {
            throw new RangeError('Size must be a finite, non-NaN, non-negative number.');
        }
        container._queue.push({ value: value, size: size });
        container._queueTotalSize += size;
    }
    function PeekQueueValue(container) {
        var pair = container._queue.peek();
        return pair.value;
    }
    function ResetQueue(container) {
        container._queue = new SimpleQueue();
        container._queueTotalSize = 0;
    }

    /**
     * A pull-into request in a {@link ReadableByteStreamController}.
     *
     * @public
     */
    var ReadableStreamBYOBRequest = /** @class */ (function () {
        function ReadableStreamBYOBRequest() {
            throw new TypeError('Illegal constructor');
        }
        Object.defineProperty(ReadableStreamBYOBRequest.prototype, "view", {
            /**
             * Returns the view for writing in to, or `null` if the BYOB request has already been responded to.
             */
            get: function () {
                if (!IsReadableStreamBYOBRequest(this)) {
                    throw byobRequestBrandCheckException('view');
                }
                return this._view;
            },
            enumerable: false,
            configurable: true
        });
        ReadableStreamBYOBRequest.prototype.respond = function (bytesWritten) {
            if (!IsReadableStreamBYOBRequest(this)) {
                throw byobRequestBrandCheckException('respond');
            }
            assertRequiredArgument(bytesWritten, 1, 'respond');
            bytesWritten = convertUnsignedLongLongWithEnforceRange(bytesWritten, 'First parameter');
            if (this._associatedReadableByteStreamController === undefined) {
                throw new TypeError('This BYOB request has been invalidated');
            }
            if (IsDetachedBuffer(this._view.buffer)) ;
            ReadableByteStreamControllerRespond(this._associatedReadableByteStreamController, bytesWritten);
        };
        ReadableStreamBYOBRequest.prototype.respondWithNewView = function (view) {
            if (!IsReadableStreamBYOBRequest(this)) {
                throw byobRequestBrandCheckException('respondWithNewView');
            }
            assertRequiredArgument(view, 1, 'respondWithNewView');
            if (!ArrayBuffer.isView(view)) {
                throw new TypeError('You can only respond with array buffer views');
            }
            if (this._associatedReadableByteStreamController === undefined) {
                throw new TypeError('This BYOB request has been invalidated');
            }
            if (IsDetachedBuffer(view.buffer)) ;
            ReadableByteStreamControllerRespondWithNewView(this._associatedReadableByteStreamController, view);
        };
        return ReadableStreamBYOBRequest;
    }());
    Object.defineProperties(ReadableStreamBYOBRequest.prototype, {
        respond: { enumerable: true },
        respondWithNewView: { enumerable: true },
        view: { enumerable: true }
    });
    if (typeof SymbolPolyfill.toStringTag === 'symbol') {
        Object.defineProperty(ReadableStreamBYOBRequest.prototype, SymbolPolyfill.toStringTag, {
            value: 'ReadableStreamBYOBRequest',
            configurable: true
        });
    }
    /**
     * Allows control of a {@link ReadableStream | readable byte stream}'s state and internal queue.
     *
     * @public
     */
    var ReadableByteStreamController = /** @class */ (function () {
        function ReadableByteStreamController() {
            throw new TypeError('Illegal constructor');
        }
        Object.defineProperty(ReadableByteStreamController.prototype, "byobRequest", {
            /**
             * Returns the current BYOB pull request, or `null` if there isn't one.
             */
            get: function () {
                if (!IsReadableByteStreamController(this)) {
                    throw byteStreamControllerBrandCheckException('byobRequest');
                }
                return ReadableByteStreamControllerGetBYOBRequest(this);
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(ReadableByteStreamController.prototype, "desiredSize", {
            /**
             * Returns the desired size to fill the controlled stream's internal queue. It can be negative, if the queue is
             * over-full. An underlying byte source ought to use this information to determine when and how to apply backpressure.
             */
            get: function () {
                if (!IsReadableByteStreamController(this)) {
                    throw byteStreamControllerBrandCheckException('desiredSize');
                }
                return ReadableByteStreamControllerGetDesiredSize(this);
            },
            enumerable: false,
            configurable: true
        });
        /**
         * Closes the controlled readable stream. Consumers will still be able to read any previously-enqueued chunks from
         * the stream, but once those are read, the stream will become closed.
         */
        ReadableByteStreamController.prototype.close = function () {
            if (!IsReadableByteStreamController(this)) {
                throw byteStreamControllerBrandCheckException('close');
            }
            if (this._closeRequested) {
                throw new TypeError('The stream has already been closed; do not close it again!');
            }
            var state = this._controlledReadableByteStream._state;
            if (state !== 'readable') {
                throw new TypeError("The stream (in " + state + " state) is not in the readable state and cannot be closed");
            }
            ReadableByteStreamControllerClose(this);
        };
        ReadableByteStreamController.prototype.enqueue = function (chunk) {
            if (!IsReadableByteStreamController(this)) {
                throw byteStreamControllerBrandCheckException('enqueue');
            }
            assertRequiredArgument(chunk, 1, 'enqueue');
            if (!ArrayBuffer.isView(chunk)) {
                throw new TypeError('chunk must be an array buffer view');
            }
            if (chunk.byteLength === 0) {
                throw new TypeError('chunk must have non-zero byteLength');
            }
            if (chunk.buffer.byteLength === 0) {
                throw new TypeError("chunk's buffer must have non-zero byteLength");
            }
            if (this._closeRequested) {
                throw new TypeError('stream is closed or draining');
            }
            var state = this._controlledReadableByteStream._state;
            if (state !== 'readable') {
                throw new TypeError("The stream (in " + state + " state) is not in the readable state and cannot be enqueued to");
            }
            ReadableByteStreamControllerEnqueue(this, chunk);
        };
        /**
         * Errors the controlled readable stream, making all future interactions with it fail with the given error `e`.
         */
        ReadableByteStreamController.prototype.error = function (e) {
            if (e === void 0) { e = undefined; }
            if (!IsReadableByteStreamController(this)) {
                throw byteStreamControllerBrandCheckException('error');
            }
            ReadableByteStreamControllerError(this, e);
        };
        /** @internal */
        ReadableByteStreamController.prototype[CancelSteps] = function (reason) {
            ReadableByteStreamControllerClearPendingPullIntos(this);
            ResetQueue(this);
            var result = this._cancelAlgorithm(reason);
            ReadableByteStreamControllerClearAlgorithms(this);
            return result;
        };
        /** @internal */
        ReadableByteStreamController.prototype[PullSteps] = function (readRequest) {
            var stream = this._controlledReadableByteStream;
            if (this._queueTotalSize > 0) {
                var entry = this._queue.shift();
                this._queueTotalSize -= entry.byteLength;
                ReadableByteStreamControllerHandleQueueDrain(this);
                var view = new Uint8Array(entry.buffer, entry.byteOffset, entry.byteLength);
                readRequest._chunkSteps(view);
                return;
            }
            var autoAllocateChunkSize = this._autoAllocateChunkSize;
            if (autoAllocateChunkSize !== undefined) {
                var buffer = void 0;
                try {
                    buffer = new ArrayBuffer(autoAllocateChunkSize);
                }
                catch (bufferE) {
                    readRequest._errorSteps(bufferE);
                    return;
                }
                var pullIntoDescriptor = {
                    buffer: buffer,
                    bufferByteLength: autoAllocateChunkSize,
                    byteOffset: 0,
                    byteLength: autoAllocateChunkSize,
                    bytesFilled: 0,
                    elementSize: 1,
                    viewConstructor: Uint8Array,
                    readerType: 'default'
                };
                this._pendingPullIntos.push(pullIntoDescriptor);
            }
            ReadableStreamAddReadRequest(stream, readRequest);
            ReadableByteStreamControllerCallPullIfNeeded(this);
        };
        return ReadableByteStreamController;
    }());
    Object.defineProperties(ReadableByteStreamController.prototype, {
        close: { enumerable: true },
        enqueue: { enumerable: true },
        error: { enumerable: true },
        byobRequest: { enumerable: true },
        desiredSize: { enumerable: true }
    });
    if (typeof SymbolPolyfill.toStringTag === 'symbol') {
        Object.defineProperty(ReadableByteStreamController.prototype, SymbolPolyfill.toStringTag, {
            value: 'ReadableByteStreamController',
            configurable: true
        });
    }
    // Abstract operations for the ReadableByteStreamController.
    function IsReadableByteStreamController(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_controlledReadableByteStream')) {
            return false;
        }
        return x instanceof ReadableByteStreamController;
    }
    function IsReadableStreamBYOBRequest(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_associatedReadableByteStreamController')) {
            return false;
        }
        return x instanceof ReadableStreamBYOBRequest;
    }
    function ReadableByteStreamControllerCallPullIfNeeded(controller) {
        var shouldPull = ReadableByteStreamControllerShouldCallPull(controller);
        if (!shouldPull) {
            return;
        }
        if (controller._pulling) {
            controller._pullAgain = true;
            return;
        }
        controller._pulling = true;
        // TODO: Test controller argument
        var pullPromise = controller._pullAlgorithm();
        uponPromise(pullPromise, function () {
            controller._pulling = false;
            if (controller._pullAgain) {
                controller._pullAgain = false;
                ReadableByteStreamControllerCallPullIfNeeded(controller);
            }
        }, function (e) {
            ReadableByteStreamControllerError(controller, e);
        });
    }
    function ReadableByteStreamControllerClearPendingPullIntos(controller) {
        ReadableByteStreamControllerInvalidateBYOBRequest(controller);
        controller._pendingPullIntos = new SimpleQueue();
    }
    function ReadableByteStreamControllerCommitPullIntoDescriptor(stream, pullIntoDescriptor) {
        var done = false;
        if (stream._state === 'closed') {
            done = true;
        }
        var filledView = ReadableByteStreamControllerConvertPullIntoDescriptor(pullIntoDescriptor);
        if (pullIntoDescriptor.readerType === 'default') {
            ReadableStreamFulfillReadRequest(stream, filledView, done);
        }
        else {
            ReadableStreamFulfillReadIntoRequest(stream, filledView, done);
        }
    }
    function ReadableByteStreamControllerConvertPullIntoDescriptor(pullIntoDescriptor) {
        var bytesFilled = pullIntoDescriptor.bytesFilled;
        var elementSize = pullIntoDescriptor.elementSize;
        return new pullIntoDescriptor.viewConstructor(pullIntoDescriptor.buffer, pullIntoDescriptor.byteOffset, bytesFilled / elementSize);
    }
    function ReadableByteStreamControllerEnqueueChunkToQueue(controller, buffer, byteOffset, byteLength) {
        controller._queue.push({ buffer: buffer, byteOffset: byteOffset, byteLength: byteLength });
        controller._queueTotalSize += byteLength;
    }
    function ReadableByteStreamControllerFillPullIntoDescriptorFromQueue(controller, pullIntoDescriptor) {
        var elementSize = pullIntoDescriptor.elementSize;
        var currentAlignedBytes = pullIntoDescriptor.bytesFilled - pullIntoDescriptor.bytesFilled % elementSize;
        var maxBytesToCopy = Math.min(controller._queueTotalSize, pullIntoDescriptor.byteLength - pullIntoDescriptor.bytesFilled);
        var maxBytesFilled = pullIntoDescriptor.bytesFilled + maxBytesToCopy;
        var maxAlignedBytes = maxBytesFilled - maxBytesFilled % elementSize;
        var totalBytesToCopyRemaining = maxBytesToCopy;
        var ready = false;
        if (maxAlignedBytes > currentAlignedBytes) {
            totalBytesToCopyRemaining = maxAlignedBytes - pullIntoDescriptor.bytesFilled;
            ready = true;
        }
        var queue = controller._queue;
        while (totalBytesToCopyRemaining > 0) {
            var headOfQueue = queue.peek();
            var bytesToCopy = Math.min(totalBytesToCopyRemaining, headOfQueue.byteLength);
            var destStart = pullIntoDescriptor.byteOffset + pullIntoDescriptor.bytesFilled;
            CopyDataBlockBytes(pullIntoDescriptor.buffer, destStart, headOfQueue.buffer, headOfQueue.byteOffset, bytesToCopy);
            if (headOfQueue.byteLength === bytesToCopy) {
                queue.shift();
            }
            else {
                headOfQueue.byteOffset += bytesToCopy;
                headOfQueue.byteLength -= bytesToCopy;
            }
            controller._queueTotalSize -= bytesToCopy;
            ReadableByteStreamControllerFillHeadPullIntoDescriptor(controller, bytesToCopy, pullIntoDescriptor);
            totalBytesToCopyRemaining -= bytesToCopy;
        }
        return ready;
    }
    function ReadableByteStreamControllerFillHeadPullIntoDescriptor(controller, size, pullIntoDescriptor) {
        pullIntoDescriptor.bytesFilled += size;
    }
    function ReadableByteStreamControllerHandleQueueDrain(controller) {
        if (controller._queueTotalSize === 0 && controller._closeRequested) {
            ReadableByteStreamControllerClearAlgorithms(controller);
            ReadableStreamClose(controller._controlledReadableByteStream);
        }
        else {
            ReadableByteStreamControllerCallPullIfNeeded(controller);
        }
    }
    function ReadableByteStreamControllerInvalidateBYOBRequest(controller) {
        if (controller._byobRequest === null) {
            return;
        }
        controller._byobRequest._associatedReadableByteStreamController = undefined;
        controller._byobRequest._view = null;
        controller._byobRequest = null;
    }
    function ReadableByteStreamControllerProcessPullIntoDescriptorsUsingQueue(controller) {
        while (controller._pendingPullIntos.length > 0) {
            if (controller._queueTotalSize === 0) {
                return;
            }
            var pullIntoDescriptor = controller._pendingPullIntos.peek();
            if (ReadableByteStreamControllerFillPullIntoDescriptorFromQueue(controller, pullIntoDescriptor)) {
                ReadableByteStreamControllerShiftPendingPullInto(controller);
                ReadableByteStreamControllerCommitPullIntoDescriptor(controller._controlledReadableByteStream, pullIntoDescriptor);
            }
        }
    }
    function ReadableByteStreamControllerPullInto(controller, view, readIntoRequest) {
        var stream = controller._controlledReadableByteStream;
        var elementSize = 1;
        if (view.constructor !== DataView) {
            elementSize = view.constructor.BYTES_PER_ELEMENT;
        }
        var ctor = view.constructor;
        // try {
        var buffer = TransferArrayBuffer(view.buffer);
        // } catch (e) {
        //   readIntoRequest._errorSteps(e);
        //   return;
        // }
        var pullIntoDescriptor = {
            buffer: buffer,
            bufferByteLength: buffer.byteLength,
            byteOffset: view.byteOffset,
            byteLength: view.byteLength,
            bytesFilled: 0,
            elementSize: elementSize,
            viewConstructor: ctor,
            readerType: 'byob'
        };
        if (controller._pendingPullIntos.length > 0) {
            controller._pendingPullIntos.push(pullIntoDescriptor);
            // No ReadableByteStreamControllerCallPullIfNeeded() call since:
            // - No change happens on desiredSize
            // - The source has already been notified of that there's at least 1 pending read(view)
            ReadableStreamAddReadIntoRequest(stream, readIntoRequest);
            return;
        }
        if (stream._state === 'closed') {
            var emptyView = new ctor(pullIntoDescriptor.buffer, pullIntoDescriptor.byteOffset, 0);
            readIntoRequest._closeSteps(emptyView);
            return;
        }
        if (controller._queueTotalSize > 0) {
            if (ReadableByteStreamControllerFillPullIntoDescriptorFromQueue(controller, pullIntoDescriptor)) {
                var filledView = ReadableByteStreamControllerConvertPullIntoDescriptor(pullIntoDescriptor);
                ReadableByteStreamControllerHandleQueueDrain(controller);
                readIntoRequest._chunkSteps(filledView);
                return;
            }
            if (controller._closeRequested) {
                var e = new TypeError('Insufficient bytes to fill elements in the given buffer');
                ReadableByteStreamControllerError(controller, e);
                readIntoRequest._errorSteps(e);
                return;
            }
        }
        controller._pendingPullIntos.push(pullIntoDescriptor);
        ReadableStreamAddReadIntoRequest(stream, readIntoRequest);
        ReadableByteStreamControllerCallPullIfNeeded(controller);
    }
    function ReadableByteStreamControllerRespondInClosedState(controller, firstDescriptor) {
        var stream = controller._controlledReadableByteStream;
        if (ReadableStreamHasBYOBReader(stream)) {
            while (ReadableStreamGetNumReadIntoRequests(stream) > 0) {
                var pullIntoDescriptor = ReadableByteStreamControllerShiftPendingPullInto(controller);
                ReadableByteStreamControllerCommitPullIntoDescriptor(stream, pullIntoDescriptor);
            }
        }
    }
    function ReadableByteStreamControllerRespondInReadableState(controller, bytesWritten, pullIntoDescriptor) {
        ReadableByteStreamControllerFillHeadPullIntoDescriptor(controller, bytesWritten, pullIntoDescriptor);
        if (pullIntoDescriptor.bytesFilled < pullIntoDescriptor.elementSize) {
            return;
        }
        ReadableByteStreamControllerShiftPendingPullInto(controller);
        var remainderSize = pullIntoDescriptor.bytesFilled % pullIntoDescriptor.elementSize;
        if (remainderSize > 0) {
            var end = pullIntoDescriptor.byteOffset + pullIntoDescriptor.bytesFilled;
            var remainder = ArrayBufferSlice(pullIntoDescriptor.buffer, end - remainderSize, end);
            ReadableByteStreamControllerEnqueueChunkToQueue(controller, remainder, 0, remainder.byteLength);
        }
        pullIntoDescriptor.bytesFilled -= remainderSize;
        ReadableByteStreamControllerCommitPullIntoDescriptor(controller._controlledReadableByteStream, pullIntoDescriptor);
        ReadableByteStreamControllerProcessPullIntoDescriptorsUsingQueue(controller);
    }
    function ReadableByteStreamControllerRespondInternal(controller, bytesWritten) {
        var firstDescriptor = controller._pendingPullIntos.peek();
        ReadableByteStreamControllerInvalidateBYOBRequest(controller);
        var state = controller._controlledReadableByteStream._state;
        if (state === 'closed') {
            ReadableByteStreamControllerRespondInClosedState(controller);
        }
        else {
            ReadableByteStreamControllerRespondInReadableState(controller, bytesWritten, firstDescriptor);
        }
        ReadableByteStreamControllerCallPullIfNeeded(controller);
    }
    function ReadableByteStreamControllerShiftPendingPullInto(controller) {
        var descriptor = controller._pendingPullIntos.shift();
        return descriptor;
    }
    function ReadableByteStreamControllerShouldCallPull(controller) {
        var stream = controller._controlledReadableByteStream;
        if (stream._state !== 'readable') {
            return false;
        }
        if (controller._closeRequested) {
            return false;
        }
        if (!controller._started) {
            return false;
        }
        if (ReadableStreamHasDefaultReader(stream) && ReadableStreamGetNumReadRequests(stream) > 0) {
            return true;
        }
        if (ReadableStreamHasBYOBReader(stream) && ReadableStreamGetNumReadIntoRequests(stream) > 0) {
            return true;
        }
        var desiredSize = ReadableByteStreamControllerGetDesiredSize(controller);
        if (desiredSize > 0) {
            return true;
        }
        return false;
    }
    function ReadableByteStreamControllerClearAlgorithms(controller) {
        controller._pullAlgorithm = undefined;
        controller._cancelAlgorithm = undefined;
    }
    // A client of ReadableByteStreamController may use these functions directly to bypass state check.
    function ReadableByteStreamControllerClose(controller) {
        var stream = controller._controlledReadableByteStream;
        if (controller._closeRequested || stream._state !== 'readable') {
            return;
        }
        if (controller._queueTotalSize > 0) {
            controller._closeRequested = true;
            return;
        }
        if (controller._pendingPullIntos.length > 0) {
            var firstPendingPullInto = controller._pendingPullIntos.peek();
            if (firstPendingPullInto.bytesFilled > 0) {
                var e = new TypeError('Insufficient bytes to fill elements in the given buffer');
                ReadableByteStreamControllerError(controller, e);
                throw e;
            }
        }
        ReadableByteStreamControllerClearAlgorithms(controller);
        ReadableStreamClose(stream);
    }
    function ReadableByteStreamControllerEnqueue(controller, chunk) {
        var stream = controller._controlledReadableByteStream;
        if (controller._closeRequested || stream._state !== 'readable') {
            return;
        }
        var buffer = chunk.buffer;
        var byteOffset = chunk.byteOffset;
        var byteLength = chunk.byteLength;
        var transferredBuffer = TransferArrayBuffer(buffer);
        if (controller._pendingPullIntos.length > 0) {
            var firstPendingPullInto = controller._pendingPullIntos.peek();
            if (IsDetachedBuffer(firstPendingPullInto.buffer)) ;
            firstPendingPullInto.buffer = TransferArrayBuffer(firstPendingPullInto.buffer);
        }
        ReadableByteStreamControllerInvalidateBYOBRequest(controller);
        if (ReadableStreamHasDefaultReader(stream)) {
            if (ReadableStreamGetNumReadRequests(stream) === 0) {
                ReadableByteStreamControllerEnqueueChunkToQueue(controller, transferredBuffer, byteOffset, byteLength);
            }
            else {
                if (controller._pendingPullIntos.length > 0) {
                    ReadableByteStreamControllerShiftPendingPullInto(controller);
                }
                var transferredView = new Uint8Array(transferredBuffer, byteOffset, byteLength);
                ReadableStreamFulfillReadRequest(stream, transferredView, false);
            }
        }
        else if (ReadableStreamHasBYOBReader(stream)) {
            // TODO: Ideally in this branch detaching should happen only if the buffer is not consumed fully.
            ReadableByteStreamControllerEnqueueChunkToQueue(controller, transferredBuffer, byteOffset, byteLength);
            ReadableByteStreamControllerProcessPullIntoDescriptorsUsingQueue(controller);
        }
        else {
            ReadableByteStreamControllerEnqueueChunkToQueue(controller, transferredBuffer, byteOffset, byteLength);
        }
        ReadableByteStreamControllerCallPullIfNeeded(controller);
    }
    function ReadableByteStreamControllerError(controller, e) {
        var stream = controller._controlledReadableByteStream;
        if (stream._state !== 'readable') {
            return;
        }
        ReadableByteStreamControllerClearPendingPullIntos(controller);
        ResetQueue(controller);
        ReadableByteStreamControllerClearAlgorithms(controller);
        ReadableStreamError(stream, e);
    }
    function ReadableByteStreamControllerGetBYOBRequest(controller) {
        if (controller._byobRequest === null && controller._pendingPullIntos.length > 0) {
            var firstDescriptor = controller._pendingPullIntos.peek();
            var view = new Uint8Array(firstDescriptor.buffer, firstDescriptor.byteOffset + firstDescriptor.bytesFilled, firstDescriptor.byteLength - firstDescriptor.bytesFilled);
            var byobRequest = Object.create(ReadableStreamBYOBRequest.prototype);
            SetUpReadableStreamBYOBRequest(byobRequest, controller, view);
            controller._byobRequest = byobRequest;
        }
        return controller._byobRequest;
    }
    function ReadableByteStreamControllerGetDesiredSize(controller) {
        var state = controller._controlledReadableByteStream._state;
        if (state === 'errored') {
            return null;
        }
        if (state === 'closed') {
            return 0;
        }
        return controller._strategyHWM - controller._queueTotalSize;
    }
    function ReadableByteStreamControllerRespond(controller, bytesWritten) {
        var firstDescriptor = controller._pendingPullIntos.peek();
        var state = controller._controlledReadableByteStream._state;
        if (state === 'closed') {
            if (bytesWritten !== 0) {
                throw new TypeError('bytesWritten must be 0 when calling respond() on a closed stream');
            }
        }
        else {
            if (bytesWritten === 0) {
                throw new TypeError('bytesWritten must be greater than 0 when calling respond() on a readable stream');
            }
            if (firstDescriptor.bytesFilled + bytesWritten > firstDescriptor.byteLength) {
                throw new RangeError('bytesWritten out of range');
            }
        }
        firstDescriptor.buffer = TransferArrayBuffer(firstDescriptor.buffer);
        ReadableByteStreamControllerRespondInternal(controller, bytesWritten);
    }
    function ReadableByteStreamControllerRespondWithNewView(controller, view) {
        var firstDescriptor = controller._pendingPullIntos.peek();
        var state = controller._controlledReadableByteStream._state;
        if (state === 'closed') {
            if (view.byteLength !== 0) {
                throw new TypeError('The view\'s length must be 0 when calling respondWithNewView() on a closed stream');
            }
        }
        else {
            if (view.byteLength === 0) {
                throw new TypeError('The view\'s length must be greater than 0 when calling respondWithNewView() on a readable stream');
            }
        }
        if (firstDescriptor.byteOffset + firstDescriptor.bytesFilled !== view.byteOffset) {
            throw new RangeError('The region specified by view does not match byobRequest');
        }
        if (firstDescriptor.bufferByteLength !== view.buffer.byteLength) {
            throw new RangeError('The buffer of view has different capacity than byobRequest');
        }
        if (firstDescriptor.bytesFilled + view.byteLength > firstDescriptor.byteLength) {
            throw new RangeError('The region specified by view is larger than byobRequest');
        }
        var viewByteLength = view.byteLength;
        firstDescriptor.buffer = TransferArrayBuffer(view.buffer);
        ReadableByteStreamControllerRespondInternal(controller, viewByteLength);
    }
    function SetUpReadableByteStreamController(stream, controller, startAlgorithm, pullAlgorithm, cancelAlgorithm, highWaterMark, autoAllocateChunkSize) {
        controller._controlledReadableByteStream = stream;
        controller._pullAgain = false;
        controller._pulling = false;
        controller._byobRequest = null;
        // Need to set the slots so that the assert doesn't fire. In the spec the slots already exist implicitly.
        controller._queue = controller._queueTotalSize = undefined;
        ResetQueue(controller);
        controller._closeRequested = false;
        controller._started = false;
        controller._strategyHWM = highWaterMark;
        controller._pullAlgorithm = pullAlgorithm;
        controller._cancelAlgorithm = cancelAlgorithm;
        controller._autoAllocateChunkSize = autoAllocateChunkSize;
        controller._pendingPullIntos = new SimpleQueue();
        stream._readableStreamController = controller;
        var startResult = startAlgorithm();
        uponPromise(promiseResolvedWith(startResult), function () {
            controller._started = true;
            ReadableByteStreamControllerCallPullIfNeeded(controller);
        }, function (r) {
            ReadableByteStreamControllerError(controller, r);
        });
    }
    function SetUpReadableByteStreamControllerFromUnderlyingSource(stream, underlyingByteSource, highWaterMark) {
        var controller = Object.create(ReadableByteStreamController.prototype);
        var startAlgorithm = function () { return undefined; };
        var pullAlgorithm = function () { return promiseResolvedWith(undefined); };
        var cancelAlgorithm = function () { return promiseResolvedWith(undefined); };
        if (underlyingByteSource.start !== undefined) {
            startAlgorithm = function () { return underlyingByteSource.start(controller); };
        }
        if (underlyingByteSource.pull !== undefined) {
            pullAlgorithm = function () { return underlyingByteSource.pull(controller); };
        }
        if (underlyingByteSource.cancel !== undefined) {
            cancelAlgorithm = function (reason) { return underlyingByteSource.cancel(reason); };
        }
        var autoAllocateChunkSize = underlyingByteSource.autoAllocateChunkSize;
        if (autoAllocateChunkSize === 0) {
            throw new TypeError('autoAllocateChunkSize must be greater than 0');
        }
        SetUpReadableByteStreamController(stream, controller, startAlgorithm, pullAlgorithm, cancelAlgorithm, highWaterMark, autoAllocateChunkSize);
    }
    function SetUpReadableStreamBYOBRequest(request, controller, view) {
        request._associatedReadableByteStreamController = controller;
        request._view = view;
    }
    // Helper functions for the ReadableStreamBYOBRequest.
    function byobRequestBrandCheckException(name) {
        return new TypeError("ReadableStreamBYOBRequest.prototype." + name + " can only be used on a ReadableStreamBYOBRequest");
    }
    // Helper functions for the ReadableByteStreamController.
    function byteStreamControllerBrandCheckException(name) {
        return new TypeError("ReadableByteStreamController.prototype." + name + " can only be used on a ReadableByteStreamController");
    }

    // Abstract operations for the ReadableStream.
    function AcquireReadableStreamBYOBReader(stream) {
        return new ReadableStreamBYOBReader(stream);
    }
    // ReadableStream API exposed for controllers.
    function ReadableStreamAddReadIntoRequest(stream, readIntoRequest) {
        stream._reader._readIntoRequests.push(readIntoRequest);
    }
    function ReadableStreamFulfillReadIntoRequest(stream, chunk, done) {
        var reader = stream._reader;
        var readIntoRequest = reader._readIntoRequests.shift();
        if (done) {
            readIntoRequest._closeSteps(chunk);
        }
        else {
            readIntoRequest._chunkSteps(chunk);
        }
    }
    function ReadableStreamGetNumReadIntoRequests(stream) {
        return stream._reader._readIntoRequests.length;
    }
    function ReadableStreamHasBYOBReader(stream) {
        var reader = stream._reader;
        if (reader === undefined) {
            return false;
        }
        if (!IsReadableStreamBYOBReader(reader)) {
            return false;
        }
        return true;
    }
    /**
     * A BYOB reader vended by a {@link ReadableStream}.
     *
     * @public
     */
    var ReadableStreamBYOBReader = /** @class */ (function () {
        function ReadableStreamBYOBReader(stream) {
            assertRequiredArgument(stream, 1, 'ReadableStreamBYOBReader');
            assertReadableStream(stream, 'First parameter');
            if (IsReadableStreamLocked(stream)) {
                throw new TypeError('This stream has already been locked for exclusive reading by another reader');
            }
            if (!IsReadableByteStreamController(stream._readableStreamController)) {
                throw new TypeError('Cannot construct a ReadableStreamBYOBReader for a stream not constructed with a byte ' +
                    'source');
            }
            ReadableStreamReaderGenericInitialize(this, stream);
            this._readIntoRequests = new SimpleQueue();
        }
        Object.defineProperty(ReadableStreamBYOBReader.prototype, "closed", {
            /**
             * Returns a promise that will be fulfilled when the stream becomes closed, or rejected if the stream ever errors or
             * the reader's lock is released before the stream finishes closing.
             */
            get: function () {
                if (!IsReadableStreamBYOBReader(this)) {
                    return promiseRejectedWith(byobReaderBrandCheckException('closed'));
                }
                return this._closedPromise;
            },
            enumerable: false,
            configurable: true
        });
        /**
         * If the reader is active, behaves the same as {@link ReadableStream.cancel | stream.cancel(reason)}.
         */
        ReadableStreamBYOBReader.prototype.cancel = function (reason) {
            if (reason === void 0) { reason = undefined; }
            if (!IsReadableStreamBYOBReader(this)) {
                return promiseRejectedWith(byobReaderBrandCheckException('cancel'));
            }
            if (this._ownerReadableStream === undefined) {
                return promiseRejectedWith(readerLockException('cancel'));
            }
            return ReadableStreamReaderGenericCancel(this, reason);
        };
        /**
         * Attempts to reads bytes into view, and returns a promise resolved with the result.
         *
         * If reading a chunk causes the queue to become empty, more data will be pulled from the underlying source.
         */
        ReadableStreamBYOBReader.prototype.read = function (view) {
            if (!IsReadableStreamBYOBReader(this)) {
                return promiseRejectedWith(byobReaderBrandCheckException('read'));
            }
            if (!ArrayBuffer.isView(view)) {
                return promiseRejectedWith(new TypeError('view must be an array buffer view'));
            }
            if (view.byteLength === 0) {
                return promiseRejectedWith(new TypeError('view must have non-zero byteLength'));
            }
            if (view.buffer.byteLength === 0) {
                return promiseRejectedWith(new TypeError("view's buffer must have non-zero byteLength"));
            }
            if (IsDetachedBuffer(view.buffer)) ;
            if (this._ownerReadableStream === undefined) {
                return promiseRejectedWith(readerLockException('read from'));
            }
            var resolvePromise;
            var rejectPromise;
            var promise = newPromise(function (resolve, reject) {
                resolvePromise = resolve;
                rejectPromise = reject;
            });
            var readIntoRequest = {
                _chunkSteps: function (chunk) { return resolvePromise({ value: chunk, done: false }); },
                _closeSteps: function (chunk) { return resolvePromise({ value: chunk, done: true }); },
                _errorSteps: function (e) { return rejectPromise(e); }
            };
            ReadableStreamBYOBReaderRead(this, view, readIntoRequest);
            return promise;
        };
        /**
         * Releases the reader's lock on the corresponding stream. After the lock is released, the reader is no longer active.
         * If the associated stream is errored when the lock is released, the reader will appear errored in the same way
         * from now on; otherwise, the reader will appear closed.
         *
         * A reader's lock cannot be released while it still has a pending read request, i.e., if a promise returned by
         * the reader's {@link ReadableStreamBYOBReader.read | read()} method has not yet been settled. Attempting to
         * do so will throw a `TypeError` and leave the reader locked to the stream.
         */
        ReadableStreamBYOBReader.prototype.releaseLock = function () {
            if (!IsReadableStreamBYOBReader(this)) {
                throw byobReaderBrandCheckException('releaseLock');
            }
            if (this._ownerReadableStream === undefined) {
                return;
            }
            if (this._readIntoRequests.length > 0) {
                throw new TypeError('Tried to release a reader lock when that reader has pending read() calls un-settled');
            }
            ReadableStreamReaderGenericRelease(this);
        };
        return ReadableStreamBYOBReader;
    }());
    Object.defineProperties(ReadableStreamBYOBReader.prototype, {
        cancel: { enumerable: true },
        read: { enumerable: true },
        releaseLock: { enumerable: true },
        closed: { enumerable: true }
    });
    if (typeof SymbolPolyfill.toStringTag === 'symbol') {
        Object.defineProperty(ReadableStreamBYOBReader.prototype, SymbolPolyfill.toStringTag, {
            value: 'ReadableStreamBYOBReader',
            configurable: true
        });
    }
    // Abstract operations for the readers.
    function IsReadableStreamBYOBReader(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_readIntoRequests')) {
            return false;
        }
        return x instanceof ReadableStreamBYOBReader;
    }
    function ReadableStreamBYOBReaderRead(reader, view, readIntoRequest) {
        var stream = reader._ownerReadableStream;
        stream._disturbed = true;
        if (stream._state === 'errored') {
            readIntoRequest._errorSteps(stream._storedError);
        }
        else {
            ReadableByteStreamControllerPullInto(stream._readableStreamController, view, readIntoRequest);
        }
    }
    // Helper functions for the ReadableStreamBYOBReader.
    function byobReaderBrandCheckException(name) {
        return new TypeError("ReadableStreamBYOBReader.prototype." + name + " can only be used on a ReadableStreamBYOBReader");
    }

    function ExtractHighWaterMark(strategy, defaultHWM) {
        var highWaterMark = strategy.highWaterMark;
        if (highWaterMark === undefined) {
            return defaultHWM;
        }
        if (NumberIsNaN(highWaterMark) || highWaterMark < 0) {
            throw new RangeError('Invalid highWaterMark');
        }
        return highWaterMark;
    }
    function ExtractSizeAlgorithm(strategy) {
        var size = strategy.size;
        if (!size) {
            return function () { return 1; };
        }
        return size;
    }

    function convertQueuingStrategy(init, context) {
        assertDictionary(init, context);
        var highWaterMark = init === null || init === void 0 ? void 0 : init.highWaterMark;
        var size = init === null || init === void 0 ? void 0 : init.size;
        return {
            highWaterMark: highWaterMark === undefined ? undefined : convertUnrestrictedDouble(highWaterMark),
            size: size === undefined ? undefined : convertQueuingStrategySize(size, context + " has member 'size' that")
        };
    }
    function convertQueuingStrategySize(fn, context) {
        assertFunction(fn, context);
        return function (chunk) { return convertUnrestrictedDouble(fn(chunk)); };
    }

    function convertUnderlyingSink(original, context) {
        assertDictionary(original, context);
        var abort = original === null || original === void 0 ? void 0 : original.abort;
        var close = original === null || original === void 0 ? void 0 : original.close;
        var start = original === null || original === void 0 ? void 0 : original.start;
        var type = original === null || original === void 0 ? void 0 : original.type;
        var write = original === null || original === void 0 ? void 0 : original.write;
        return {
            abort: abort === undefined ?
                undefined :
                convertUnderlyingSinkAbortCallback(abort, original, context + " has member 'abort' that"),
            close: close === undefined ?
                undefined :
                convertUnderlyingSinkCloseCallback(close, original, context + " has member 'close' that"),
            start: start === undefined ?
                undefined :
                convertUnderlyingSinkStartCallback(start, original, context + " has member 'start' that"),
            write: write === undefined ?
                undefined :
                convertUnderlyingSinkWriteCallback(write, original, context + " has member 'write' that"),
            type: type
        };
    }
    function convertUnderlyingSinkAbortCallback(fn, original, context) {
        assertFunction(fn, context);
        return function (reason) { return promiseCall(fn, original, [reason]); };
    }
    function convertUnderlyingSinkCloseCallback(fn, original, context) {
        assertFunction(fn, context);
        return function () { return promiseCall(fn, original, []); };
    }
    function convertUnderlyingSinkStartCallback(fn, original, context) {
        assertFunction(fn, context);
        return function (controller) { return reflectCall(fn, original, [controller]); };
    }
    function convertUnderlyingSinkWriteCallback(fn, original, context) {
        assertFunction(fn, context);
        return function (chunk, controller) { return promiseCall(fn, original, [chunk, controller]); };
    }

    function assertWritableStream(x, context) {
        if (!IsWritableStream(x)) {
            throw new TypeError(context + " is not a WritableStream.");
        }
    }

    function isAbortSignal(value) {
        if (typeof value !== 'object' || value === null) {
            return false;
        }
        try {
            return typeof value.aborted === 'boolean';
        }
        catch (_a) {
            // AbortSignal.prototype.aborted throws if its brand check fails
            return false;
        }
    }
    var supportsAbortController = typeof AbortController === 'function';
    /**
     * Construct a new AbortController, if supported by the platform.
     *
     * @internal
     */
    function createAbortController() {
        if (supportsAbortController) {
            return new AbortController();
        }
        return undefined;
    }

    /**
     * A writable stream represents a destination for data, into which you can write.
     *
     * @public
     */
    var WritableStream = /** @class */ (function () {
        function WritableStream(rawUnderlyingSink, rawStrategy) {
            if (rawUnderlyingSink === void 0) { rawUnderlyingSink = {}; }
            if (rawStrategy === void 0) { rawStrategy = {}; }
            if (rawUnderlyingSink === undefined) {
                rawUnderlyingSink = null;
            }
            else {
                assertObject(rawUnderlyingSink, 'First parameter');
            }
            var strategy = convertQueuingStrategy(rawStrategy, 'Second parameter');
            var underlyingSink = convertUnderlyingSink(rawUnderlyingSink, 'First parameter');
            InitializeWritableStream(this);
            var type = underlyingSink.type;
            if (type !== undefined) {
                throw new RangeError('Invalid type is specified');
            }
            var sizeAlgorithm = ExtractSizeAlgorithm(strategy);
            var highWaterMark = ExtractHighWaterMark(strategy, 1);
            SetUpWritableStreamDefaultControllerFromUnderlyingSink(this, underlyingSink, highWaterMark, sizeAlgorithm);
        }
        Object.defineProperty(WritableStream.prototype, "locked", {
            /**
             * Returns whether or not the writable stream is locked to a writer.
             */
            get: function () {
                if (!IsWritableStream(this)) {
                    throw streamBrandCheckException$2('locked');
                }
                return IsWritableStreamLocked(this);
            },
            enumerable: false,
            configurable: true
        });
        /**
         * Aborts the stream, signaling that the producer can no longer successfully write to the stream and it is to be
         * immediately moved to an errored state, with any queued-up writes discarded. This will also execute any abort
         * mechanism of the underlying sink.
         *
         * The returned promise will fulfill if the stream shuts down successfully, or reject if the underlying sink signaled
         * that there was an error doing so. Additionally, it will reject with a `TypeError` (without attempting to cancel
         * the stream) if the stream is currently locked.
         */
        WritableStream.prototype.abort = function (reason) {
            if (reason === void 0) { reason = undefined; }
            if (!IsWritableStream(this)) {
                return promiseRejectedWith(streamBrandCheckException$2('abort'));
            }
            if (IsWritableStreamLocked(this)) {
                return promiseRejectedWith(new TypeError('Cannot abort a stream that already has a writer'));
            }
            return WritableStreamAbort(this, reason);
        };
        /**
         * Closes the stream. The underlying sink will finish processing any previously-written chunks, before invoking its
         * close behavior. During this time any further attempts to write will fail (without erroring the stream).
         *
         * The method returns a promise that will fulfill if all remaining chunks are successfully written and the stream
         * successfully closes, or rejects if an error is encountered during this process. Additionally, it will reject with
         * a `TypeError` (without attempting to cancel the stream) if the stream is currently locked.
         */
        WritableStream.prototype.close = function () {
            if (!IsWritableStream(this)) {
                return promiseRejectedWith(streamBrandCheckException$2('close'));
            }
            if (IsWritableStreamLocked(this)) {
                return promiseRejectedWith(new TypeError('Cannot close a stream that already has a writer'));
            }
            if (WritableStreamCloseQueuedOrInFlight(this)) {
                return promiseRejectedWith(new TypeError('Cannot close an already-closing stream'));
            }
            return WritableStreamClose(this);
        };
        /**
         * Creates a {@link WritableStreamDefaultWriter | writer} and locks the stream to the new writer. While the stream
         * is locked, no other writer can be acquired until this one is released.
         *
         * This functionality is especially useful for creating abstractions that desire the ability to write to a stream
         * without interruption or interleaving. By getting a writer for the stream, you can ensure nobody else can write at
         * the same time, which would cause the resulting written data to be unpredictable and probably useless.
         */
        WritableStream.prototype.getWriter = function () {
            if (!IsWritableStream(this)) {
                throw streamBrandCheckException$2('getWriter');
            }
            return AcquireWritableStreamDefaultWriter(this);
        };
        return WritableStream;
    }());
    Object.defineProperties(WritableStream.prototype, {
        abort: { enumerable: true },
        close: { enumerable: true },
        getWriter: { enumerable: true },
        locked: { enumerable: true }
    });
    if (typeof SymbolPolyfill.toStringTag === 'symbol') {
        Object.defineProperty(WritableStream.prototype, SymbolPolyfill.toStringTag, {
            value: 'WritableStream',
            configurable: true
        });
    }
    // Abstract operations for the WritableStream.
    function AcquireWritableStreamDefaultWriter(stream) {
        return new WritableStreamDefaultWriter(stream);
    }
    // Throws if and only if startAlgorithm throws.
    function CreateWritableStream(startAlgorithm, writeAlgorithm, closeAlgorithm, abortAlgorithm, highWaterMark, sizeAlgorithm) {
        if (highWaterMark === void 0) { highWaterMark = 1; }
        if (sizeAlgorithm === void 0) { sizeAlgorithm = function () { return 1; }; }
        var stream = Object.create(WritableStream.prototype);
        InitializeWritableStream(stream);
        var controller = Object.create(WritableStreamDefaultController.prototype);
        SetUpWritableStreamDefaultController(stream, controller, startAlgorithm, writeAlgorithm, closeAlgorithm, abortAlgorithm, highWaterMark, sizeAlgorithm);
        return stream;
    }
    function InitializeWritableStream(stream) {
        stream._state = 'writable';
        // The error that will be reported by new method calls once the state becomes errored. Only set when [[state]] is
        // 'erroring' or 'errored'. May be set to an undefined value.
        stream._storedError = undefined;
        stream._writer = undefined;
        // Initialize to undefined first because the constructor of the controller checks this
        // variable to validate the caller.
        stream._writableStreamController = undefined;
        // This queue is placed here instead of the writer class in order to allow for passing a writer to the next data
        // producer without waiting for the queued writes to finish.
        stream._writeRequests = new SimpleQueue();
        // Write requests are removed from _writeRequests when write() is called on the underlying sink. This prevents
        // them from being erroneously rejected on error. If a write() call is in-flight, the request is stored here.
        stream._inFlightWriteRequest = undefined;
        // The promise that was returned from writer.close(). Stored here because it may be fulfilled after the writer
        // has been detached.
        stream._closeRequest = undefined;
        // Close request is removed from _closeRequest when close() is called on the underlying sink. This prevents it
        // from being erroneously rejected on error. If a close() call is in-flight, the request is stored here.
        stream._inFlightCloseRequest = undefined;
        // The promise that was returned from writer.abort(). This may also be fulfilled after the writer has detached.
        stream._pendingAbortRequest = undefined;
        // The backpressure signal set by the controller.
        stream._backpressure = false;
    }
    function IsWritableStream(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_writableStreamController')) {
            return false;
        }
        return x instanceof WritableStream;
    }
    function IsWritableStreamLocked(stream) {
        if (stream._writer === undefined) {
            return false;
        }
        return true;
    }
    function WritableStreamAbort(stream, reason) {
        var _a;
        if (stream._state === 'closed' || stream._state === 'errored') {
            return promiseResolvedWith(undefined);
        }
        stream._writableStreamController._abortReason = reason;
        (_a = stream._writableStreamController._abortController) === null || _a === void 0 ? void 0 : _a.abort();
        // TypeScript narrows the type of `stream._state` down to 'writable' | 'erroring',
        // but it doesn't know that signaling abort runs author code that might have changed the state.
        // Widen the type again by casting to WritableStreamState.
        var state = stream._state;
        if (state === 'closed' || state === 'errored') {
            return promiseResolvedWith(undefined);
        }
        if (stream._pendingAbortRequest !== undefined) {
            return stream._pendingAbortRequest._promise;
        }
        var wasAlreadyErroring = false;
        if (state === 'erroring') {
            wasAlreadyErroring = true;
            // reason will not be used, so don't keep a reference to it.
            reason = undefined;
        }
        var promise = newPromise(function (resolve, reject) {
            stream._pendingAbortRequest = {
                _promise: undefined,
                _resolve: resolve,
                _reject: reject,
                _reason: reason,
                _wasAlreadyErroring: wasAlreadyErroring
            };
        });
        stream._pendingAbortRequest._promise = promise;
        if (!wasAlreadyErroring) {
            WritableStreamStartErroring(stream, reason);
        }
        return promise;
    }
    function WritableStreamClose(stream) {
        var state = stream._state;
        if (state === 'closed' || state === 'errored') {
            return promiseRejectedWith(new TypeError("The stream (in " + state + " state) is not in the writable state and cannot be closed"));
        }
        var promise = newPromise(function (resolve, reject) {
            var closeRequest = {
                _resolve: resolve,
                _reject: reject
            };
            stream._closeRequest = closeRequest;
        });
        var writer = stream._writer;
        if (writer !== undefined && stream._backpressure && state === 'writable') {
            defaultWriterReadyPromiseResolve(writer);
        }
        WritableStreamDefaultControllerClose(stream._writableStreamController);
        return promise;
    }
    // WritableStream API exposed for controllers.
    function WritableStreamAddWriteRequest(stream) {
        var promise = newPromise(function (resolve, reject) {
            var writeRequest = {
                _resolve: resolve,
                _reject: reject
            };
            stream._writeRequests.push(writeRequest);
        });
        return promise;
    }
    function WritableStreamDealWithRejection(stream, error) {
        var state = stream._state;
        if (state === 'writable') {
            WritableStreamStartErroring(stream, error);
            return;
        }
        WritableStreamFinishErroring(stream);
    }
    function WritableStreamStartErroring(stream, reason) {
        var controller = stream._writableStreamController;
        stream._state = 'erroring';
        stream._storedError = reason;
        var writer = stream._writer;
        if (writer !== undefined) {
            WritableStreamDefaultWriterEnsureReadyPromiseRejected(writer, reason);
        }
        if (!WritableStreamHasOperationMarkedInFlight(stream) && controller._started) {
            WritableStreamFinishErroring(stream);
        }
    }
    function WritableStreamFinishErroring(stream) {
        stream._state = 'errored';
        stream._writableStreamController[ErrorSteps]();
        var storedError = stream._storedError;
        stream._writeRequests.forEach(function (writeRequest) {
            writeRequest._reject(storedError);
        });
        stream._writeRequests = new SimpleQueue();
        if (stream._pendingAbortRequest === undefined) {
            WritableStreamRejectCloseAndClosedPromiseIfNeeded(stream);
            return;
        }
        var abortRequest = stream._pendingAbortRequest;
        stream._pendingAbortRequest = undefined;
        if (abortRequest._wasAlreadyErroring) {
            abortRequest._reject(storedError);
            WritableStreamRejectCloseAndClosedPromiseIfNeeded(stream);
            return;
        }
        var promise = stream._writableStreamController[AbortSteps](abortRequest._reason);
        uponPromise(promise, function () {
            abortRequest._resolve();
            WritableStreamRejectCloseAndClosedPromiseIfNeeded(stream);
        }, function (reason) {
            abortRequest._reject(reason);
            WritableStreamRejectCloseAndClosedPromiseIfNeeded(stream);
        });
    }
    function WritableStreamFinishInFlightWrite(stream) {
        stream._inFlightWriteRequest._resolve(undefined);
        stream._inFlightWriteRequest = undefined;
    }
    function WritableStreamFinishInFlightWriteWithError(stream, error) {
        stream._inFlightWriteRequest._reject(error);
        stream._inFlightWriteRequest = undefined;
        WritableStreamDealWithRejection(stream, error);
    }
    function WritableStreamFinishInFlightClose(stream) {
        stream._inFlightCloseRequest._resolve(undefined);
        stream._inFlightCloseRequest = undefined;
        var state = stream._state;
        if (state === 'erroring') {
            // The error was too late to do anything, so it is ignored.
            stream._storedError = undefined;
            if (stream._pendingAbortRequest !== undefined) {
                stream._pendingAbortRequest._resolve();
                stream._pendingAbortRequest = undefined;
            }
        }
        stream._state = 'closed';
        var writer = stream._writer;
        if (writer !== undefined) {
            defaultWriterClosedPromiseResolve(writer);
        }
    }
    function WritableStreamFinishInFlightCloseWithError(stream, error) {
        stream._inFlightCloseRequest._reject(error);
        stream._inFlightCloseRequest = undefined;
        // Never execute sink abort() after sink close().
        if (stream._pendingAbortRequest !== undefined) {
            stream._pendingAbortRequest._reject(error);
            stream._pendingAbortRequest = undefined;
        }
        WritableStreamDealWithRejection(stream, error);
    }
    // TODO(ricea): Fix alphabetical order.
    function WritableStreamCloseQueuedOrInFlight(stream) {
        if (stream._closeRequest === undefined && stream._inFlightCloseRequest === undefined) {
            return false;
        }
        return true;
    }
    function WritableStreamHasOperationMarkedInFlight(stream) {
        if (stream._inFlightWriteRequest === undefined && stream._inFlightCloseRequest === undefined) {
            return false;
        }
        return true;
    }
    function WritableStreamMarkCloseRequestInFlight(stream) {
        stream._inFlightCloseRequest = stream._closeRequest;
        stream._closeRequest = undefined;
    }
    function WritableStreamMarkFirstWriteRequestInFlight(stream) {
        stream._inFlightWriteRequest = stream._writeRequests.shift();
    }
    function WritableStreamRejectCloseAndClosedPromiseIfNeeded(stream) {
        if (stream._closeRequest !== undefined) {
            stream._closeRequest._reject(stream._storedError);
            stream._closeRequest = undefined;
        }
        var writer = stream._writer;
        if (writer !== undefined) {
            defaultWriterClosedPromiseReject(writer, stream._storedError);
        }
    }
    function WritableStreamUpdateBackpressure(stream, backpressure) {
        var writer = stream._writer;
        if (writer !== undefined && backpressure !== stream._backpressure) {
            if (backpressure) {
                defaultWriterReadyPromiseReset(writer);
            }
            else {
                defaultWriterReadyPromiseResolve(writer);
            }
        }
        stream._backpressure = backpressure;
    }
    /**
     * A default writer vended by a {@link WritableStream}.
     *
     * @public
     */
    var WritableStreamDefaultWriter = /** @class */ (function () {
        function WritableStreamDefaultWriter(stream) {
            assertRequiredArgument(stream, 1, 'WritableStreamDefaultWriter');
            assertWritableStream(stream, 'First parameter');
            if (IsWritableStreamLocked(stream)) {
                throw new TypeError('This stream has already been locked for exclusive writing by another writer');
            }
            this._ownerWritableStream = stream;
            stream._writer = this;
            var state = stream._state;
            if (state === 'writable') {
                if (!WritableStreamCloseQueuedOrInFlight(stream) && stream._backpressure) {
                    defaultWriterReadyPromiseInitialize(this);
                }
                else {
                    defaultWriterReadyPromiseInitializeAsResolved(this);
                }
                defaultWriterClosedPromiseInitialize(this);
            }
            else if (state === 'erroring') {
                defaultWriterReadyPromiseInitializeAsRejected(this, stream._storedError);
                defaultWriterClosedPromiseInitialize(this);
            }
            else if (state === 'closed') {
                defaultWriterReadyPromiseInitializeAsResolved(this);
                defaultWriterClosedPromiseInitializeAsResolved(this);
            }
            else {
                var storedError = stream._storedError;
                defaultWriterReadyPromiseInitializeAsRejected(this, storedError);
                defaultWriterClosedPromiseInitializeAsRejected(this, storedError);
            }
        }
        Object.defineProperty(WritableStreamDefaultWriter.prototype, "closed", {
            /**
             * Returns a promise that will be fulfilled when the stream becomes closed, or rejected if the stream ever errors or
             * the writer’s lock is released before the stream finishes closing.
             */
            get: function () {
                if (!IsWritableStreamDefaultWriter(this)) {
                    return promiseRejectedWith(defaultWriterBrandCheckException('closed'));
                }
                return this._closedPromise;
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(WritableStreamDefaultWriter.prototype, "desiredSize", {
            /**
             * Returns the desired size to fill the stream’s internal queue. It can be negative, if the queue is over-full.
             * A producer can use this information to determine the right amount of data to write.
             *
             * It will be `null` if the stream cannot be successfully written to (due to either being errored, or having an abort
             * queued up). It will return zero if the stream is closed. And the getter will throw an exception if invoked when
             * the writer’s lock is released.
             */
            get: function () {
                if (!IsWritableStreamDefaultWriter(this)) {
                    throw defaultWriterBrandCheckException('desiredSize');
                }
                if (this._ownerWritableStream === undefined) {
                    throw defaultWriterLockException('desiredSize');
                }
                return WritableStreamDefaultWriterGetDesiredSize(this);
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(WritableStreamDefaultWriter.prototype, "ready", {
            /**
             * Returns a promise that will be fulfilled when the desired size to fill the stream’s internal queue transitions
             * from non-positive to positive, signaling that it is no longer applying backpressure. Once the desired size dips
             * back to zero or below, the getter will return a new promise that stays pending until the next transition.
             *
             * If the stream becomes errored or aborted, or the writer’s lock is released, the returned promise will become
             * rejected.
             */
            get: function () {
                if (!IsWritableStreamDefaultWriter(this)) {
                    return promiseRejectedWith(defaultWriterBrandCheckException('ready'));
                }
                return this._readyPromise;
            },
            enumerable: false,
            configurable: true
        });
        /**
         * If the reader is active, behaves the same as {@link WritableStream.abort | stream.abort(reason)}.
         */
        WritableStreamDefaultWriter.prototype.abort = function (reason) {
            if (reason === void 0) { reason = undefined; }
            if (!IsWritableStreamDefaultWriter(this)) {
                return promiseRejectedWith(defaultWriterBrandCheckException('abort'));
            }
            if (this._ownerWritableStream === undefined) {
                return promiseRejectedWith(defaultWriterLockException('abort'));
            }
            return WritableStreamDefaultWriterAbort(this, reason);
        };
        /**
         * If the reader is active, behaves the same as {@link WritableStream.close | stream.close()}.
         */
        WritableStreamDefaultWriter.prototype.close = function () {
            if (!IsWritableStreamDefaultWriter(this)) {
                return promiseRejectedWith(defaultWriterBrandCheckException('close'));
            }
            var stream = this._ownerWritableStream;
            if (stream === undefined) {
                return promiseRejectedWith(defaultWriterLockException('close'));
            }
            if (WritableStreamCloseQueuedOrInFlight(stream)) {
                return promiseRejectedWith(new TypeError('Cannot close an already-closing stream'));
            }
            return WritableStreamDefaultWriterClose(this);
        };
        /**
         * Releases the writer’s lock on the corresponding stream. After the lock is released, the writer is no longer active.
         * If the associated stream is errored when the lock is released, the writer will appear errored in the same way from
         * now on; otherwise, the writer will appear closed.
         *
         * Note that the lock can still be released even if some ongoing writes have not yet finished (i.e. even if the
         * promises returned from previous calls to {@link WritableStreamDefaultWriter.write | write()} have not yet settled).
         * It’s not necessary to hold the lock on the writer for the duration of the write; the lock instead simply prevents
         * other producers from writing in an interleaved manner.
         */
        WritableStreamDefaultWriter.prototype.releaseLock = function () {
            if (!IsWritableStreamDefaultWriter(this)) {
                throw defaultWriterBrandCheckException('releaseLock');
            }
            var stream = this._ownerWritableStream;
            if (stream === undefined) {
                return;
            }
            WritableStreamDefaultWriterRelease(this);
        };
        WritableStreamDefaultWriter.prototype.write = function (chunk) {
            if (chunk === void 0) { chunk = undefined; }
            if (!IsWritableStreamDefaultWriter(this)) {
                return promiseRejectedWith(defaultWriterBrandCheckException('write'));
            }
            if (this._ownerWritableStream === undefined) {
                return promiseRejectedWith(defaultWriterLockException('write to'));
            }
            return WritableStreamDefaultWriterWrite(this, chunk);
        };
        return WritableStreamDefaultWriter;
    }());
    Object.defineProperties(WritableStreamDefaultWriter.prototype, {
        abort: { enumerable: true },
        close: { enumerable: true },
        releaseLock: { enumerable: true },
        write: { enumerable: true },
        closed: { enumerable: true },
        desiredSize: { enumerable: true },
        ready: { enumerable: true }
    });
    if (typeof SymbolPolyfill.toStringTag === 'symbol') {
        Object.defineProperty(WritableStreamDefaultWriter.prototype, SymbolPolyfill.toStringTag, {
            value: 'WritableStreamDefaultWriter',
            configurable: true
        });
    }
    // Abstract operations for the WritableStreamDefaultWriter.
    function IsWritableStreamDefaultWriter(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_ownerWritableStream')) {
            return false;
        }
        return x instanceof WritableStreamDefaultWriter;
    }
    // A client of WritableStreamDefaultWriter may use these functions directly to bypass state check.
    function WritableStreamDefaultWriterAbort(writer, reason) {
        var stream = writer._ownerWritableStream;
        return WritableStreamAbort(stream, reason);
    }
    function WritableStreamDefaultWriterClose(writer) {
        var stream = writer._ownerWritableStream;
        return WritableStreamClose(stream);
    }
    function WritableStreamDefaultWriterCloseWithErrorPropagation(writer) {
        var stream = writer._ownerWritableStream;
        var state = stream._state;
        if (WritableStreamCloseQueuedOrInFlight(stream) || state === 'closed') {
            return promiseResolvedWith(undefined);
        }
        if (state === 'errored') {
            return promiseRejectedWith(stream._storedError);
        }
        return WritableStreamDefaultWriterClose(writer);
    }
    function WritableStreamDefaultWriterEnsureClosedPromiseRejected(writer, error) {
        if (writer._closedPromiseState === 'pending') {
            defaultWriterClosedPromiseReject(writer, error);
        }
        else {
            defaultWriterClosedPromiseResetToRejected(writer, error);
        }
    }
    function WritableStreamDefaultWriterEnsureReadyPromiseRejected(writer, error) {
        if (writer._readyPromiseState === 'pending') {
            defaultWriterReadyPromiseReject(writer, error);
        }
        else {
            defaultWriterReadyPromiseResetToRejected(writer, error);
        }
    }
    function WritableStreamDefaultWriterGetDesiredSize(writer) {
        var stream = writer._ownerWritableStream;
        var state = stream._state;
        if (state === 'errored' || state === 'erroring') {
            return null;
        }
        if (state === 'closed') {
            return 0;
        }
        return WritableStreamDefaultControllerGetDesiredSize(stream._writableStreamController);
    }
    function WritableStreamDefaultWriterRelease(writer) {
        var stream = writer._ownerWritableStream;
        var releasedError = new TypeError("Writer was released and can no longer be used to monitor the stream's closedness");
        WritableStreamDefaultWriterEnsureReadyPromiseRejected(writer, releasedError);
        // The state transitions to "errored" before the sink abort() method runs, but the writer.closed promise is not
        // rejected until afterwards. This means that simply testing state will not work.
        WritableStreamDefaultWriterEnsureClosedPromiseRejected(writer, releasedError);
        stream._writer = undefined;
        writer._ownerWritableStream = undefined;
    }
    function WritableStreamDefaultWriterWrite(writer, chunk) {
        var stream = writer._ownerWritableStream;
        var controller = stream._writableStreamController;
        var chunkSize = WritableStreamDefaultControllerGetChunkSize(controller, chunk);
        if (stream !== writer._ownerWritableStream) {
            return promiseRejectedWith(defaultWriterLockException('write to'));
        }
        var state = stream._state;
        if (state === 'errored') {
            return promiseRejectedWith(stream._storedError);
        }
        if (WritableStreamCloseQueuedOrInFlight(stream) || state === 'closed') {
            return promiseRejectedWith(new TypeError('The stream is closing or closed and cannot be written to'));
        }
        if (state === 'erroring') {
            return promiseRejectedWith(stream._storedError);
        }
        var promise = WritableStreamAddWriteRequest(stream);
        WritableStreamDefaultControllerWrite(controller, chunk, chunkSize);
        return promise;
    }
    var closeSentinel = {};
    /**
     * Allows control of a {@link WritableStream | writable stream}'s state and internal queue.
     *
     * @public
     */
    var WritableStreamDefaultController = /** @class */ (function () {
        function WritableStreamDefaultController() {
            throw new TypeError('Illegal constructor');
        }
        Object.defineProperty(WritableStreamDefaultController.prototype, "abortReason", {
            /**
             * The reason which was passed to `WritableStream.abort(reason)` when the stream was aborted.
             *
             * @deprecated
             *  This property has been removed from the specification, see https://github.com/whatwg/streams/pull/1177.
             *  Use {@link WritableStreamDefaultController.signal}'s `reason` instead.
             */
            get: function () {
                if (!IsWritableStreamDefaultController(this)) {
                    throw defaultControllerBrandCheckException$2('abortReason');
                }
                return this._abortReason;
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(WritableStreamDefaultController.prototype, "signal", {
            /**
             * An `AbortSignal` that can be used to abort the pending write or close operation when the stream is aborted.
             */
            get: function () {
                if (!IsWritableStreamDefaultController(this)) {
                    throw defaultControllerBrandCheckException$2('signal');
                }
                if (this._abortController === undefined) {
                    // Older browsers or older Node versions may not support `AbortController` or `AbortSignal`.
                    // We don't want to bundle and ship an `AbortController` polyfill together with our polyfill,
                    // so instead we only implement support for `signal` if we find a global `AbortController` constructor.
                    throw new TypeError('WritableStreamDefaultController.prototype.signal is not supported');
                }
                return this._abortController.signal;
            },
            enumerable: false,
            configurable: true
        });
        /**
         * Closes the controlled writable stream, making all future interactions with it fail with the given error `e`.
         *
         * This method is rarely used, since usually it suffices to return a rejected promise from one of the underlying
         * sink's methods. However, it can be useful for suddenly shutting down a stream in response to an event outside the
         * normal lifecycle of interactions with the underlying sink.
         */
        WritableStreamDefaultController.prototype.error = function (e) {
            if (e === void 0) { e = undefined; }
            if (!IsWritableStreamDefaultController(this)) {
                throw defaultControllerBrandCheckException$2('error');
            }
            var state = this._controlledWritableStream._state;
            if (state !== 'writable') {
                // The stream is closed, errored or will be soon. The sink can't do anything useful if it gets an error here, so
                // just treat it as a no-op.
                return;
            }
            WritableStreamDefaultControllerError(this, e);
        };
        /** @internal */
        WritableStreamDefaultController.prototype[AbortSteps] = function (reason) {
            var result = this._abortAlgorithm(reason);
            WritableStreamDefaultControllerClearAlgorithms(this);
            return result;
        };
        /** @internal */
        WritableStreamDefaultController.prototype[ErrorSteps] = function () {
            ResetQueue(this);
        };
        return WritableStreamDefaultController;
    }());
    Object.defineProperties(WritableStreamDefaultController.prototype, {
        abortReason: { enumerable: true },
        signal: { enumerable: true },
        error: { enumerable: true }
    });
    if (typeof SymbolPolyfill.toStringTag === 'symbol') {
        Object.defineProperty(WritableStreamDefaultController.prototype, SymbolPolyfill.toStringTag, {
            value: 'WritableStreamDefaultController',
            configurable: true
        });
    }
    // Abstract operations implementing interface required by the WritableStream.
    function IsWritableStreamDefaultController(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_controlledWritableStream')) {
            return false;
        }
        return x instanceof WritableStreamDefaultController;
    }
    function SetUpWritableStreamDefaultController(stream, controller, startAlgorithm, writeAlgorithm, closeAlgorithm, abortAlgorithm, highWaterMark, sizeAlgorithm) {
        controller._controlledWritableStream = stream;
        stream._writableStreamController = controller;
        // Need to set the slots so that the assert doesn't fire. In the spec the slots already exist implicitly.
        controller._queue = undefined;
        controller._queueTotalSize = undefined;
        ResetQueue(controller);
        controller._abortReason = undefined;
        controller._abortController = createAbortController();
        controller._started = false;
        controller._strategySizeAlgorithm = sizeAlgorithm;
        controller._strategyHWM = highWaterMark;
        controller._writeAlgorithm = writeAlgorithm;
        controller._closeAlgorithm = closeAlgorithm;
        controller._abortAlgorithm = abortAlgorithm;
        var backpressure = WritableStreamDefaultControllerGetBackpressure(controller);
        WritableStreamUpdateBackpressure(stream, backpressure);
        var startResult = startAlgorithm();
        var startPromise = promiseResolvedWith(startResult);
        uponPromise(startPromise, function () {
            controller._started = true;
            WritableStreamDefaultControllerAdvanceQueueIfNeeded(controller);
        }, function (r) {
            controller._started = true;
            WritableStreamDealWithRejection(stream, r);
        });
    }
    function SetUpWritableStreamDefaultControllerFromUnderlyingSink(stream, underlyingSink, highWaterMark, sizeAlgorithm) {
        var controller = Object.create(WritableStreamDefaultController.prototype);
        var startAlgorithm = function () { return undefined; };
        var writeAlgorithm = function () { return promiseResolvedWith(undefined); };
        var closeAlgorithm = function () { return promiseResolvedWith(undefined); };
        var abortAlgorithm = function () { return promiseResolvedWith(undefined); };
        if (underlyingSink.start !== undefined) {
            startAlgorithm = function () { return underlyingSink.start(controller); };
        }
        if (underlyingSink.write !== undefined) {
            writeAlgorithm = function (chunk) { return underlyingSink.write(chunk, controller); };
        }
        if (underlyingSink.close !== undefined) {
            closeAlgorithm = function () { return underlyingSink.close(); };
        }
        if (underlyingSink.abort !== undefined) {
            abortAlgorithm = function (reason) { return underlyingSink.abort(reason); };
        }
        SetUpWritableStreamDefaultController(stream, controller, startAlgorithm, writeAlgorithm, closeAlgorithm, abortAlgorithm, highWaterMark, sizeAlgorithm);
    }
    // ClearAlgorithms may be called twice. Erroring the same stream in multiple ways will often result in redundant calls.
    function WritableStreamDefaultControllerClearAlgorithms(controller) {
        controller._writeAlgorithm = undefined;
        controller._closeAlgorithm = undefined;
        controller._abortAlgorithm = undefined;
        controller._strategySizeAlgorithm = undefined;
    }
    function WritableStreamDefaultControllerClose(controller) {
        EnqueueValueWithSize(controller, closeSentinel, 0);
        WritableStreamDefaultControllerAdvanceQueueIfNeeded(controller);
    }
    function WritableStreamDefaultControllerGetChunkSize(controller, chunk) {
        try {
            return controller._strategySizeAlgorithm(chunk);
        }
        catch (chunkSizeE) {
            WritableStreamDefaultControllerErrorIfNeeded(controller, chunkSizeE);
            return 1;
        }
    }
    function WritableStreamDefaultControllerGetDesiredSize(controller) {
        return controller._strategyHWM - controller._queueTotalSize;
    }
    function WritableStreamDefaultControllerWrite(controller, chunk, chunkSize) {
        try {
            EnqueueValueWithSize(controller, chunk, chunkSize);
        }
        catch (enqueueE) {
            WritableStreamDefaultControllerErrorIfNeeded(controller, enqueueE);
            return;
        }
        var stream = controller._controlledWritableStream;
        if (!WritableStreamCloseQueuedOrInFlight(stream) && stream._state === 'writable') {
            var backpressure = WritableStreamDefaultControllerGetBackpressure(controller);
            WritableStreamUpdateBackpressure(stream, backpressure);
        }
        WritableStreamDefaultControllerAdvanceQueueIfNeeded(controller);
    }
    // Abstract operations for the WritableStreamDefaultController.
    function WritableStreamDefaultControllerAdvanceQueueIfNeeded(controller) {
        var stream = controller._controlledWritableStream;
        if (!controller._started) {
            return;
        }
        if (stream._inFlightWriteRequest !== undefined) {
            return;
        }
        var state = stream._state;
        if (state === 'erroring') {
            WritableStreamFinishErroring(stream);
            return;
        }
        if (controller._queue.length === 0) {
            return;
        }
        var value = PeekQueueValue(controller);
        if (value === closeSentinel) {
            WritableStreamDefaultControllerProcessClose(controller);
        }
        else {
            WritableStreamDefaultControllerProcessWrite(controller, value);
        }
    }
    function WritableStreamDefaultControllerErrorIfNeeded(controller, error) {
        if (controller._controlledWritableStream._state === 'writable') {
            WritableStreamDefaultControllerError(controller, error);
        }
    }
    function WritableStreamDefaultControllerProcessClose(controller) {
        var stream = controller._controlledWritableStream;
        WritableStreamMarkCloseRequestInFlight(stream);
        DequeueValue(controller);
        var sinkClosePromise = controller._closeAlgorithm();
        WritableStreamDefaultControllerClearAlgorithms(controller);
        uponPromise(sinkClosePromise, function () {
            WritableStreamFinishInFlightClose(stream);
        }, function (reason) {
            WritableStreamFinishInFlightCloseWithError(stream, reason);
        });
    }
    function WritableStreamDefaultControllerProcessWrite(controller, chunk) {
        var stream = controller._controlledWritableStream;
        WritableStreamMarkFirstWriteRequestInFlight(stream);
        var sinkWritePromise = controller._writeAlgorithm(chunk);
        uponPromise(sinkWritePromise, function () {
            WritableStreamFinishInFlightWrite(stream);
            var state = stream._state;
            DequeueValue(controller);
            if (!WritableStreamCloseQueuedOrInFlight(stream) && state === 'writable') {
                var backpressure = WritableStreamDefaultControllerGetBackpressure(controller);
                WritableStreamUpdateBackpressure(stream, backpressure);
            }
            WritableStreamDefaultControllerAdvanceQueueIfNeeded(controller);
        }, function (reason) {
            if (stream._state === 'writable') {
                WritableStreamDefaultControllerClearAlgorithms(controller);
            }
            WritableStreamFinishInFlightWriteWithError(stream, reason);
        });
    }
    function WritableStreamDefaultControllerGetBackpressure(controller) {
        var desiredSize = WritableStreamDefaultControllerGetDesiredSize(controller);
        return desiredSize <= 0;
    }
    // A client of WritableStreamDefaultController may use these functions directly to bypass state check.
    function WritableStreamDefaultControllerError(controller, error) {
        var stream = controller._controlledWritableStream;
        WritableStreamDefaultControllerClearAlgorithms(controller);
        WritableStreamStartErroring(stream, error);
    }
    // Helper functions for the WritableStream.
    function streamBrandCheckException$2(name) {
        return new TypeError("WritableStream.prototype." + name + " can only be used on a WritableStream");
    }
    // Helper functions for the WritableStreamDefaultController.
    function defaultControllerBrandCheckException$2(name) {
        return new TypeError("WritableStreamDefaultController.prototype." + name + " can only be used on a WritableStreamDefaultController");
    }
    // Helper functions for the WritableStreamDefaultWriter.
    function defaultWriterBrandCheckException(name) {
        return new TypeError("WritableStreamDefaultWriter.prototype." + name + " can only be used on a WritableStreamDefaultWriter");
    }
    function defaultWriterLockException(name) {
        return new TypeError('Cannot ' + name + ' a stream using a released writer');
    }
    function defaultWriterClosedPromiseInitialize(writer) {
        writer._closedPromise = newPromise(function (resolve, reject) {
            writer._closedPromise_resolve = resolve;
            writer._closedPromise_reject = reject;
            writer._closedPromiseState = 'pending';
        });
    }
    function defaultWriterClosedPromiseInitializeAsRejected(writer, reason) {
        defaultWriterClosedPromiseInitialize(writer);
        defaultWriterClosedPromiseReject(writer, reason);
    }
    function defaultWriterClosedPromiseInitializeAsResolved(writer) {
        defaultWriterClosedPromiseInitialize(writer);
        defaultWriterClosedPromiseResolve(writer);
    }
    function defaultWriterClosedPromiseReject(writer, reason) {
        if (writer._closedPromise_reject === undefined) {
            return;
        }
        setPromiseIsHandledToTrue(writer._closedPromise);
        writer._closedPromise_reject(reason);
        writer._closedPromise_resolve = undefined;
        writer._closedPromise_reject = undefined;
        writer._closedPromiseState = 'rejected';
    }
    function defaultWriterClosedPromiseResetToRejected(writer, reason) {
        defaultWriterClosedPromiseInitializeAsRejected(writer, reason);
    }
    function defaultWriterClosedPromiseResolve(writer) {
        if (writer._closedPromise_resolve === undefined) {
            return;
        }
        writer._closedPromise_resolve(undefined);
        writer._closedPromise_resolve = undefined;
        writer._closedPromise_reject = undefined;
        writer._closedPromiseState = 'resolved';
    }
    function defaultWriterReadyPromiseInitialize(writer) {
        writer._readyPromise = newPromise(function (resolve, reject) {
            writer._readyPromise_resolve = resolve;
            writer._readyPromise_reject = reject;
        });
        writer._readyPromiseState = 'pending';
    }
    function defaultWriterReadyPromiseInitializeAsRejected(writer, reason) {
        defaultWriterReadyPromiseInitialize(writer);
        defaultWriterReadyPromiseReject(writer, reason);
    }
    function defaultWriterReadyPromiseInitializeAsResolved(writer) {
        defaultWriterReadyPromiseInitialize(writer);
        defaultWriterReadyPromiseResolve(writer);
    }
    function defaultWriterReadyPromiseReject(writer, reason) {
        if (writer._readyPromise_reject === undefined) {
            return;
        }
        setPromiseIsHandledToTrue(writer._readyPromise);
        writer._readyPromise_reject(reason);
        writer._readyPromise_resolve = undefined;
        writer._readyPromise_reject = undefined;
        writer._readyPromiseState = 'rejected';
    }
    function defaultWriterReadyPromiseReset(writer) {
        defaultWriterReadyPromiseInitialize(writer);
    }
    function defaultWriterReadyPromiseResetToRejected(writer, reason) {
        defaultWriterReadyPromiseInitializeAsRejected(writer, reason);
    }
    function defaultWriterReadyPromiseResolve(writer) {
        if (writer._readyPromise_resolve === undefined) {
            return;
        }
        writer._readyPromise_resolve(undefined);
        writer._readyPromise_resolve = undefined;
        writer._readyPromise_reject = undefined;
        writer._readyPromiseState = 'fulfilled';
    }

    /// <reference lib="dom" />
    var NativeDOMException = typeof DOMException !== 'undefined' ? DOMException : undefined;

    /// <reference types="node" />
    function isDOMExceptionConstructor(ctor) {
        if (!(typeof ctor === 'function' || typeof ctor === 'object')) {
            return false;
        }
        try {
            new ctor();
            return true;
        }
        catch (_a) {
            return false;
        }
    }
    function createDOMExceptionPolyfill() {
        // eslint-disable-next-line no-shadow
        var ctor = function DOMException(message, name) {
            this.message = message || '';
            this.name = name || 'Error';
            if (Error.captureStackTrace) {
                Error.captureStackTrace(this, this.constructor);
            }
        };
        ctor.prototype = Object.create(Error.prototype);
        Object.defineProperty(ctor.prototype, 'constructor', { value: ctor, writable: true, configurable: true });
        return ctor;
    }
    // eslint-disable-next-line no-redeclare
    var DOMException$1 = isDOMExceptionConstructor(NativeDOMException) ? NativeDOMException : createDOMExceptionPolyfill();

    function ReadableStreamPipeTo(source, dest, preventClose, preventAbort, preventCancel, signal) {
        var reader = AcquireReadableStreamDefaultReader(source);
        var writer = AcquireWritableStreamDefaultWriter(dest);
        source._disturbed = true;
        var shuttingDown = false;
        // This is used to keep track of the spec's requirement that we wait for ongoing writes during shutdown.
        var currentWrite = promiseResolvedWith(undefined);
        return newPromise(function (resolve, reject) {
            var abortAlgorithm;
            if (signal !== undefined) {
                abortAlgorithm = function () {
                    var error = new DOMException$1('Aborted', 'AbortError');
                    var actions = [];
                    if (!preventAbort) {
                        actions.push(function () {
                            if (dest._state === 'writable') {
                                return WritableStreamAbort(dest, error);
                            }
                            return promiseResolvedWith(undefined);
                        });
                    }
                    if (!preventCancel) {
                        actions.push(function () {
                            if (source._state === 'readable') {
                                return ReadableStreamCancel(source, error);
                            }
                            return promiseResolvedWith(undefined);
                        });
                    }
                    shutdownWithAction(function () { return Promise.all(actions.map(function (action) { return action(); })); }, true, error);
                };
                if (signal.aborted) {
                    abortAlgorithm();
                    return;
                }
                signal.addEventListener('abort', abortAlgorithm);
            }
            // Using reader and writer, read all chunks from this and write them to dest
            // - Backpressure must be enforced
            // - Shutdown must stop all activity
            function pipeLoop() {
                return newPromise(function (resolveLoop, rejectLoop) {
                    function next(done) {
                        if (done) {
                            resolveLoop();
                        }
                        else {
                            // Use `PerformPromiseThen` instead of `uponPromise` to avoid
                            // adding unnecessary `.catch(rethrowAssertionErrorRejection)` handlers
                            PerformPromiseThen(pipeStep(), next, rejectLoop);
                        }
                    }
                    next(false);
                });
            }
            function pipeStep() {
                if (shuttingDown) {
                    return promiseResolvedWith(true);
                }
                return PerformPromiseThen(writer._readyPromise, function () {
                    return newPromise(function (resolveRead, rejectRead) {
                        ReadableStreamDefaultReaderRead(reader, {
                            _chunkSteps: function (chunk) {
                                currentWrite = PerformPromiseThen(WritableStreamDefaultWriterWrite(writer, chunk), undefined, noop);
                                resolveRead(false);
                            },
                            _closeSteps: function () { return resolveRead(true); },
                            _errorSteps: rejectRead
                        });
                    });
                });
            }
            // Errors must be propagated forward
            isOrBecomesErrored(source, reader._closedPromise, function (storedError) {
                if (!preventAbort) {
                    shutdownWithAction(function () { return WritableStreamAbort(dest, storedError); }, true, storedError);
                }
                else {
                    shutdown(true, storedError);
                }
            });
            // Errors must be propagated backward
            isOrBecomesErrored(dest, writer._closedPromise, function (storedError) {
                if (!preventCancel) {
                    shutdownWithAction(function () { return ReadableStreamCancel(source, storedError); }, true, storedError);
                }
                else {
                    shutdown(true, storedError);
                }
            });
            // Closing must be propagated forward
            isOrBecomesClosed(source, reader._closedPromise, function () {
                if (!preventClose) {
                    shutdownWithAction(function () { return WritableStreamDefaultWriterCloseWithErrorPropagation(writer); });
                }
                else {
                    shutdown();
                }
            });
            // Closing must be propagated backward
            if (WritableStreamCloseQueuedOrInFlight(dest) || dest._state === 'closed') {
                var destClosed_1 = new TypeError('the destination writable stream closed before all data could be piped to it');
                if (!preventCancel) {
                    shutdownWithAction(function () { return ReadableStreamCancel(source, destClosed_1); }, true, destClosed_1);
                }
                else {
                    shutdown(true, destClosed_1);
                }
            }
            setPromiseIsHandledToTrue(pipeLoop());
            function waitForWritesToFinish() {
                // Another write may have started while we were waiting on this currentWrite, so we have to be sure to wait
                // for that too.
                var oldCurrentWrite = currentWrite;
                return PerformPromiseThen(currentWrite, function () { return oldCurrentWrite !== currentWrite ? waitForWritesToFinish() : undefined; });
            }
            function isOrBecomesErrored(stream, promise, action) {
                if (stream._state === 'errored') {
                    action(stream._storedError);
                }
                else {
                    uponRejection(promise, action);
                }
            }
            function isOrBecomesClosed(stream, promise, action) {
                if (stream._state === 'closed') {
                    action();
                }
                else {
                    uponFulfillment(promise, action);
                }
            }
            function shutdownWithAction(action, originalIsError, originalError) {
                if (shuttingDown) {
                    return;
                }
                shuttingDown = true;
                if (dest._state === 'writable' && !WritableStreamCloseQueuedOrInFlight(dest)) {
                    uponFulfillment(waitForWritesToFinish(), doTheRest);
                }
                else {
                    doTheRest();
                }
                function doTheRest() {
                    uponPromise(action(), function () { return finalize(originalIsError, originalError); }, function (newError) { return finalize(true, newError); });
                }
            }
            function shutdown(isError, error) {
                if (shuttingDown) {
                    return;
                }
                shuttingDown = true;
                if (dest._state === 'writable' && !WritableStreamCloseQueuedOrInFlight(dest)) {
                    uponFulfillment(waitForWritesToFinish(), function () { return finalize(isError, error); });
                }
                else {
                    finalize(isError, error);
                }
            }
            function finalize(isError, error) {
                WritableStreamDefaultWriterRelease(writer);
                ReadableStreamReaderGenericRelease(reader);
                if (signal !== undefined) {
                    signal.removeEventListener('abort', abortAlgorithm);
                }
                if (isError) {
                    reject(error);
                }
                else {
                    resolve(undefined);
                }
            }
        });
    }

    /**
     * Allows control of a {@link ReadableStream | readable stream}'s state and internal queue.
     *
     * @public
     */
    var ReadableStreamDefaultController = /** @class */ (function () {
        function ReadableStreamDefaultController() {
            throw new TypeError('Illegal constructor');
        }
        Object.defineProperty(ReadableStreamDefaultController.prototype, "desiredSize", {
            /**
             * Returns the desired size to fill the controlled stream's internal queue. It can be negative, if the queue is
             * over-full. An underlying source ought to use this information to determine when and how to apply backpressure.
             */
            get: function () {
                if (!IsReadableStreamDefaultController(this)) {
                    throw defaultControllerBrandCheckException$1('desiredSize');
                }
                return ReadableStreamDefaultControllerGetDesiredSize(this);
            },
            enumerable: false,
            configurable: true
        });
        /**
         * Closes the controlled readable stream. Consumers will still be able to read any previously-enqueued chunks from
         * the stream, but once those are read, the stream will become closed.
         */
        ReadableStreamDefaultController.prototype.close = function () {
            if (!IsReadableStreamDefaultController(this)) {
                throw defaultControllerBrandCheckException$1('close');
            }
            if (!ReadableStreamDefaultControllerCanCloseOrEnqueue(this)) {
                throw new TypeError('The stream is not in a state that permits close');
            }
            ReadableStreamDefaultControllerClose(this);
        };
        ReadableStreamDefaultController.prototype.enqueue = function (chunk) {
            if (chunk === void 0) { chunk = undefined; }
            if (!IsReadableStreamDefaultController(this)) {
                throw defaultControllerBrandCheckException$1('enqueue');
            }
            if (!ReadableStreamDefaultControllerCanCloseOrEnqueue(this)) {
                throw new TypeError('The stream is not in a state that permits enqueue');
            }
            return ReadableStreamDefaultControllerEnqueue(this, chunk);
        };
        /**
         * Errors the controlled readable stream, making all future interactions with it fail with the given error `e`.
         */
        ReadableStreamDefaultController.prototype.error = function (e) {
            if (e === void 0) { e = undefined; }
            if (!IsReadableStreamDefaultController(this)) {
                throw defaultControllerBrandCheckException$1('error');
            }
            ReadableStreamDefaultControllerError(this, e);
        };
        /** @internal */
        ReadableStreamDefaultController.prototype[CancelSteps] = function (reason) {
            ResetQueue(this);
            var result = this._cancelAlgorithm(reason);
            ReadableStreamDefaultControllerClearAlgorithms(this);
            return result;
        };
        /** @internal */
        ReadableStreamDefaultController.prototype[PullSteps] = function (readRequest) {
            var stream = this._controlledReadableStream;
            if (this._queue.length > 0) {
                var chunk = DequeueValue(this);
                if (this._closeRequested && this._queue.length === 0) {
                    ReadableStreamDefaultControllerClearAlgorithms(this);
                    ReadableStreamClose(stream);
                }
                else {
                    ReadableStreamDefaultControllerCallPullIfNeeded(this);
                }
                readRequest._chunkSteps(chunk);
            }
            else {
                ReadableStreamAddReadRequest(stream, readRequest);
                ReadableStreamDefaultControllerCallPullIfNeeded(this);
            }
        };
        return ReadableStreamDefaultController;
    }());
    Object.defineProperties(ReadableStreamDefaultController.prototype, {
        close: { enumerable: true },
        enqueue: { enumerable: true },
        error: { enumerable: true },
        desiredSize: { enumerable: true }
    });
    if (typeof SymbolPolyfill.toStringTag === 'symbol') {
        Object.defineProperty(ReadableStreamDefaultController.prototype, SymbolPolyfill.toStringTag, {
            value: 'ReadableStreamDefaultController',
            configurable: true
        });
    }
    // Abstract operations for the ReadableStreamDefaultController.
    function IsReadableStreamDefaultController(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_controlledReadableStream')) {
            return false;
        }
        return x instanceof ReadableStreamDefaultController;
    }
    function ReadableStreamDefaultControllerCallPullIfNeeded(controller) {
        var shouldPull = ReadableStreamDefaultControllerShouldCallPull(controller);
        if (!shouldPull) {
            return;
        }
        if (controller._pulling) {
            controller._pullAgain = true;
            return;
        }
        controller._pulling = true;
        var pullPromise = controller._pullAlgorithm();
        uponPromise(pullPromise, function () {
            controller._pulling = false;
            if (controller._pullAgain) {
                controller._pullAgain = false;
                ReadableStreamDefaultControllerCallPullIfNeeded(controller);
            }
        }, function (e) {
            ReadableStreamDefaultControllerError(controller, e);
        });
    }
    function ReadableStreamDefaultControllerShouldCallPull(controller) {
        var stream = controller._controlledReadableStream;
        if (!ReadableStreamDefaultControllerCanCloseOrEnqueue(controller)) {
            return false;
        }
        if (!controller._started) {
            return false;
        }
        if (IsReadableStreamLocked(stream) && ReadableStreamGetNumReadRequests(stream) > 0) {
            return true;
        }
        var desiredSize = ReadableStreamDefaultControllerGetDesiredSize(controller);
        if (desiredSize > 0) {
            return true;
        }
        return false;
    }
    function ReadableStreamDefaultControllerClearAlgorithms(controller) {
        controller._pullAlgorithm = undefined;
        controller._cancelAlgorithm = undefined;
        controller._strategySizeAlgorithm = undefined;
    }
    // A client of ReadableStreamDefaultController may use these functions directly to bypass state check.
    function ReadableStreamDefaultControllerClose(controller) {
        if (!ReadableStreamDefaultControllerCanCloseOrEnqueue(controller)) {
            return;
        }
        var stream = controller._controlledReadableStream;
        controller._closeRequested = true;
        if (controller._queue.length === 0) {
            ReadableStreamDefaultControllerClearAlgorithms(controller);
            ReadableStreamClose(stream);
        }
    }
    function ReadableStreamDefaultControllerEnqueue(controller, chunk) {
        if (!ReadableStreamDefaultControllerCanCloseOrEnqueue(controller)) {
            return;
        }
        var stream = controller._controlledReadableStream;
        if (IsReadableStreamLocked(stream) && ReadableStreamGetNumReadRequests(stream) > 0) {
            ReadableStreamFulfillReadRequest(stream, chunk, false);
        }
        else {
            var chunkSize = void 0;
            try {
                chunkSize = controller._strategySizeAlgorithm(chunk);
            }
            catch (chunkSizeE) {
                ReadableStreamDefaultControllerError(controller, chunkSizeE);
                throw chunkSizeE;
            }
            try {
                EnqueueValueWithSize(controller, chunk, chunkSize);
            }
            catch (enqueueE) {
                ReadableStreamDefaultControllerError(controller, enqueueE);
                throw enqueueE;
            }
        }
        ReadableStreamDefaultControllerCallPullIfNeeded(controller);
    }
    function ReadableStreamDefaultControllerError(controller, e) {
        var stream = controller._controlledReadableStream;
        if (stream._state !== 'readable') {
            return;
        }
        ResetQueue(controller);
        ReadableStreamDefaultControllerClearAlgorithms(controller);
        ReadableStreamError(stream, e);
    }
    function ReadableStreamDefaultControllerGetDesiredSize(controller) {
        var state = controller._controlledReadableStream._state;
        if (state === 'errored') {
            return null;
        }
        if (state === 'closed') {
            return 0;
        }
        return controller._strategyHWM - controller._queueTotalSize;
    }
    // This is used in the implementation of TransformStream.
    function ReadableStreamDefaultControllerHasBackpressure(controller) {
        if (ReadableStreamDefaultControllerShouldCallPull(controller)) {
            return false;
        }
        return true;
    }
    function ReadableStreamDefaultControllerCanCloseOrEnqueue(controller) {
        var state = controller._controlledReadableStream._state;
        if (!controller._closeRequested && state === 'readable') {
            return true;
        }
        return false;
    }
    function SetUpReadableStreamDefaultController(stream, controller, startAlgorithm, pullAlgorithm, cancelAlgorithm, highWaterMark, sizeAlgorithm) {
        controller._controlledReadableStream = stream;
        controller._queue = undefined;
        controller._queueTotalSize = undefined;
        ResetQueue(controller);
        controller._started = false;
        controller._closeRequested = false;
        controller._pullAgain = false;
        controller._pulling = false;
        controller._strategySizeAlgorithm = sizeAlgorithm;
        controller._strategyHWM = highWaterMark;
        controller._pullAlgorithm = pullAlgorithm;
        controller._cancelAlgorithm = cancelAlgorithm;
        stream._readableStreamController = controller;
        var startResult = startAlgorithm();
        uponPromise(promiseResolvedWith(startResult), function () {
            controller._started = true;
            ReadableStreamDefaultControllerCallPullIfNeeded(controller);
        }, function (r) {
            ReadableStreamDefaultControllerError(controller, r);
        });
    }
    function SetUpReadableStreamDefaultControllerFromUnderlyingSource(stream, underlyingSource, highWaterMark, sizeAlgorithm) {
        var controller = Object.create(ReadableStreamDefaultController.prototype);
        var startAlgorithm = function () { return undefined; };
        var pullAlgorithm = function () { return promiseResolvedWith(undefined); };
        var cancelAlgorithm = function () { return promiseResolvedWith(undefined); };
        if (underlyingSource.start !== undefined) {
            startAlgorithm = function () { return underlyingSource.start(controller); };
        }
        if (underlyingSource.pull !== undefined) {
            pullAlgorithm = function () { return underlyingSource.pull(controller); };
        }
        if (underlyingSource.cancel !== undefined) {
            cancelAlgorithm = function (reason) { return underlyingSource.cancel(reason); };
        }
        SetUpReadableStreamDefaultController(stream, controller, startAlgorithm, pullAlgorithm, cancelAlgorithm, highWaterMark, sizeAlgorithm);
    }
    // Helper functions for the ReadableStreamDefaultController.
    function defaultControllerBrandCheckException$1(name) {
        return new TypeError("ReadableStreamDefaultController.prototype." + name + " can only be used on a ReadableStreamDefaultController");
    }

    function ReadableStreamTee(stream, cloneForBranch2) {
        if (IsReadableByteStreamController(stream._readableStreamController)) {
            return ReadableByteStreamTee(stream);
        }
        return ReadableStreamDefaultTee(stream);
    }
    function ReadableStreamDefaultTee(stream, cloneForBranch2) {
        var reader = AcquireReadableStreamDefaultReader(stream);
        var reading = false;
        var readAgain = false;
        var canceled1 = false;
        var canceled2 = false;
        var reason1;
        var reason2;
        var branch1;
        var branch2;
        var resolveCancelPromise;
        var cancelPromise = newPromise(function (resolve) {
            resolveCancelPromise = resolve;
        });
        function pullAlgorithm() {
            if (reading) {
                readAgain = true;
                return promiseResolvedWith(undefined);
            }
            reading = true;
            var readRequest = {
                _chunkSteps: function (chunk) {
                    // This needs to be delayed a microtask because it takes at least a microtask to detect errors (using
                    // reader._closedPromise below), and we want errors in stream to error both branches immediately. We cannot let
                    // successful synchronously-available reads get ahead of asynchronously-available errors.
                    queueMicrotask(function () {
                        readAgain = false;
                        var chunk1 = chunk;
                        var chunk2 = chunk;
                        // There is no way to access the cloning code right now in the reference implementation.
                        // If we add one then we'll need an implementation for serializable objects.
                        // if (!canceled2 && cloneForBranch2) {
                        //   chunk2 = StructuredDeserialize(StructuredSerialize(chunk2));
                        // }
                        if (!canceled1) {
                            ReadableStreamDefaultControllerEnqueue(branch1._readableStreamController, chunk1);
                        }
                        if (!canceled2) {
                            ReadableStreamDefaultControllerEnqueue(branch2._readableStreamController, chunk2);
                        }
                        reading = false;
                        if (readAgain) {
                            pullAlgorithm();
                        }
                    });
                },
                _closeSteps: function () {
                    reading = false;
                    if (!canceled1) {
                        ReadableStreamDefaultControllerClose(branch1._readableStreamController);
                    }
                    if (!canceled2) {
                        ReadableStreamDefaultControllerClose(branch2._readableStreamController);
                    }
                    if (!canceled1 || !canceled2) {
                        resolveCancelPromise(undefined);
                    }
                },
                _errorSteps: function () {
                    reading = false;
                }
            };
            ReadableStreamDefaultReaderRead(reader, readRequest);
            return promiseResolvedWith(undefined);
        }
        function cancel1Algorithm(reason) {
            canceled1 = true;
            reason1 = reason;
            if (canceled2) {
                var compositeReason = CreateArrayFromList([reason1, reason2]);
                var cancelResult = ReadableStreamCancel(stream, compositeReason);
                resolveCancelPromise(cancelResult);
            }
            return cancelPromise;
        }
        function cancel2Algorithm(reason) {
            canceled2 = true;
            reason2 = reason;
            if (canceled1) {
                var compositeReason = CreateArrayFromList([reason1, reason2]);
                var cancelResult = ReadableStreamCancel(stream, compositeReason);
                resolveCancelPromise(cancelResult);
            }
            return cancelPromise;
        }
        function startAlgorithm() {
            // do nothing
        }
        branch1 = CreateReadableStream(startAlgorithm, pullAlgorithm, cancel1Algorithm);
        branch2 = CreateReadableStream(startAlgorithm, pullAlgorithm, cancel2Algorithm);
        uponRejection(reader._closedPromise, function (r) {
            ReadableStreamDefaultControllerError(branch1._readableStreamController, r);
            ReadableStreamDefaultControllerError(branch2._readableStreamController, r);
            if (!canceled1 || !canceled2) {
                resolveCancelPromise(undefined);
            }
        });
        return [branch1, branch2];
    }
    function ReadableByteStreamTee(stream) {
        var reader = AcquireReadableStreamDefaultReader(stream);
        var reading = false;
        var readAgainForBranch1 = false;
        var readAgainForBranch2 = false;
        var canceled1 = false;
        var canceled2 = false;
        var reason1;
        var reason2;
        var branch1;
        var branch2;
        var resolveCancelPromise;
        var cancelPromise = newPromise(function (resolve) {
            resolveCancelPromise = resolve;
        });
        function forwardReaderError(thisReader) {
            uponRejection(thisReader._closedPromise, function (r) {
                if (thisReader !== reader) {
                    return;
                }
                ReadableByteStreamControllerError(branch1._readableStreamController, r);
                ReadableByteStreamControllerError(branch2._readableStreamController, r);
                if (!canceled1 || !canceled2) {
                    resolveCancelPromise(undefined);
                }
            });
        }
        function pullWithDefaultReader() {
            if (IsReadableStreamBYOBReader(reader)) {
                ReadableStreamReaderGenericRelease(reader);
                reader = AcquireReadableStreamDefaultReader(stream);
                forwardReaderError(reader);
            }
            var readRequest = {
                _chunkSteps: function (chunk) {
                    // This needs to be delayed a microtask because it takes at least a microtask to detect errors (using
                    // reader._closedPromise below), and we want errors in stream to error both branches immediately. We cannot let
                    // successful synchronously-available reads get ahead of asynchronously-available errors.
                    queueMicrotask(function () {
                        readAgainForBranch1 = false;
                        readAgainForBranch2 = false;
                        var chunk1 = chunk;
                        var chunk2 = chunk;
                        if (!canceled1 && !canceled2) {
                            try {
                                chunk2 = CloneAsUint8Array(chunk);
                            }
                            catch (cloneE) {
                                ReadableByteStreamControllerError(branch1._readableStreamController, cloneE);
                                ReadableByteStreamControllerError(branch2._readableStreamController, cloneE);
                                resolveCancelPromise(ReadableStreamCancel(stream, cloneE));
                                return;
                            }
                        }
                        if (!canceled1) {
                            ReadableByteStreamControllerEnqueue(branch1._readableStreamController, chunk1);
                        }
                        if (!canceled2) {
                            ReadableByteStreamControllerEnqueue(branch2._readableStreamController, chunk2);
                        }
                        reading = false;
                        if (readAgainForBranch1) {
                            pull1Algorithm();
                        }
                        else if (readAgainForBranch2) {
                            pull2Algorithm();
                        }
                    });
                },
                _closeSteps: function () {
                    reading = false;
                    if (!canceled1) {
                        ReadableByteStreamControllerClose(branch1._readableStreamController);
                    }
                    if (!canceled2) {
                        ReadableByteStreamControllerClose(branch2._readableStreamController);
                    }
                    if (branch1._readableStreamController._pendingPullIntos.length > 0) {
                        ReadableByteStreamControllerRespond(branch1._readableStreamController, 0);
                    }
                    if (branch2._readableStreamController._pendingPullIntos.length > 0) {
                        ReadableByteStreamControllerRespond(branch2._readableStreamController, 0);
                    }
                    if (!canceled1 || !canceled2) {
                        resolveCancelPromise(undefined);
                    }
                },
                _errorSteps: function () {
                    reading = false;
                }
            };
            ReadableStreamDefaultReaderRead(reader, readRequest);
        }
        function pullWithBYOBReader(view, forBranch2) {
            if (IsReadableStreamDefaultReader(reader)) {
                ReadableStreamReaderGenericRelease(reader);
                reader = AcquireReadableStreamBYOBReader(stream);
                forwardReaderError(reader);
            }
            var byobBranch = forBranch2 ? branch2 : branch1;
            var otherBranch = forBranch2 ? branch1 : branch2;
            var readIntoRequest = {
                _chunkSteps: function (chunk) {
                    // This needs to be delayed a microtask because it takes at least a microtask to detect errors (using
                    // reader._closedPromise below), and we want errors in stream to error both branches immediately. We cannot let
                    // successful synchronously-available reads get ahead of asynchronously-available errors.
                    queueMicrotask(function () {
                        readAgainForBranch1 = false;
                        readAgainForBranch2 = false;
                        var byobCanceled = forBranch2 ? canceled2 : canceled1;
                        var otherCanceled = forBranch2 ? canceled1 : canceled2;
                        if (!otherCanceled) {
                            var clonedChunk = void 0;
                            try {
                                clonedChunk = CloneAsUint8Array(chunk);
                            }
                            catch (cloneE) {
                                ReadableByteStreamControllerError(byobBranch._readableStreamController, cloneE);
                                ReadableByteStreamControllerError(otherBranch._readableStreamController, cloneE);
                                resolveCancelPromise(ReadableStreamCancel(stream, cloneE));
                                return;
                            }
                            if (!byobCanceled) {
                                ReadableByteStreamControllerRespondWithNewView(byobBranch._readableStreamController, chunk);
                            }
                            ReadableByteStreamControllerEnqueue(otherBranch._readableStreamController, clonedChunk);
                        }
                        else if (!byobCanceled) {
                            ReadableByteStreamControllerRespondWithNewView(byobBranch._readableStreamController, chunk);
                        }
                        reading = false;
                        if (readAgainForBranch1) {
                            pull1Algorithm();
                        }
                        else if (readAgainForBranch2) {
                            pull2Algorithm();
                        }
                    });
                },
                _closeSteps: function (chunk) {
                    reading = false;
                    var byobCanceled = forBranch2 ? canceled2 : canceled1;
                    var otherCanceled = forBranch2 ? canceled1 : canceled2;
                    if (!byobCanceled) {
                        ReadableByteStreamControllerClose(byobBranch._readableStreamController);
                    }
                    if (!otherCanceled) {
                        ReadableByteStreamControllerClose(otherBranch._readableStreamController);
                    }
                    if (chunk !== undefined) {
                        if (!byobCanceled) {
                            ReadableByteStreamControllerRespondWithNewView(byobBranch._readableStreamController, chunk);
                        }
                        if (!otherCanceled && otherBranch._readableStreamController._pendingPullIntos.length > 0) {
                            ReadableByteStreamControllerRespond(otherBranch._readableStreamController, 0);
                        }
                    }
                    if (!byobCanceled || !otherCanceled) {
                        resolveCancelPromise(undefined);
                    }
                },
                _errorSteps: function () {
                    reading = false;
                }
            };
            ReadableStreamBYOBReaderRead(reader, view, readIntoRequest);
        }
        function pull1Algorithm() {
            if (reading) {
                readAgainForBranch1 = true;
                return promiseResolvedWith(undefined);
            }
            reading = true;
            var byobRequest = ReadableByteStreamControllerGetBYOBRequest(branch1._readableStreamController);
            if (byobRequest === null) {
                pullWithDefaultReader();
            }
            else {
                pullWithBYOBReader(byobRequest._view, false);
            }
            return promiseResolvedWith(undefined);
        }
        function pull2Algorithm() {
            if (reading) {
                readAgainForBranch2 = true;
                return promiseResolvedWith(undefined);
            }
            reading = true;
            var byobRequest = ReadableByteStreamControllerGetBYOBRequest(branch2._readableStreamController);
            if (byobRequest === null) {
                pullWithDefaultReader();
            }
            else {
                pullWithBYOBReader(byobRequest._view, true);
            }
            return promiseResolvedWith(undefined);
        }
        function cancel1Algorithm(reason) {
            canceled1 = true;
            reason1 = reason;
            if (canceled2) {
                var compositeReason = CreateArrayFromList([reason1, reason2]);
                var cancelResult = ReadableStreamCancel(stream, compositeReason);
                resolveCancelPromise(cancelResult);
            }
            return cancelPromise;
        }
        function cancel2Algorithm(reason) {
            canceled2 = true;
            reason2 = reason;
            if (canceled1) {
                var compositeReason = CreateArrayFromList([reason1, reason2]);
                var cancelResult = ReadableStreamCancel(stream, compositeReason);
                resolveCancelPromise(cancelResult);
            }
            return cancelPromise;
        }
        function startAlgorithm() {
            return;
        }
        branch1 = CreateReadableByteStream(startAlgorithm, pull1Algorithm, cancel1Algorithm);
        branch2 = CreateReadableByteStream(startAlgorithm, pull2Algorithm, cancel2Algorithm);
        forwardReaderError(reader);
        return [branch1, branch2];
    }

    function convertUnderlyingDefaultOrByteSource(source, context) {
        assertDictionary(source, context);
        var original = source;
        var autoAllocateChunkSize = original === null || original === void 0 ? void 0 : original.autoAllocateChunkSize;
        var cancel = original === null || original === void 0 ? void 0 : original.cancel;
        var pull = original === null || original === void 0 ? void 0 : original.pull;
        var start = original === null || original === void 0 ? void 0 : original.start;
        var type = original === null || original === void 0 ? void 0 : original.type;
        return {
            autoAllocateChunkSize: autoAllocateChunkSize === undefined ?
                undefined :
                convertUnsignedLongLongWithEnforceRange(autoAllocateChunkSize, context + " has member 'autoAllocateChunkSize' that"),
            cancel: cancel === undefined ?
                undefined :
                convertUnderlyingSourceCancelCallback(cancel, original, context + " has member 'cancel' that"),
            pull: pull === undefined ?
                undefined :
                convertUnderlyingSourcePullCallback(pull, original, context + " has member 'pull' that"),
            start: start === undefined ?
                undefined :
                convertUnderlyingSourceStartCallback(start, original, context + " has member 'start' that"),
            type: type === undefined ? undefined : convertReadableStreamType(type, context + " has member 'type' that")
        };
    }
    function convertUnderlyingSourceCancelCallback(fn, original, context) {
        assertFunction(fn, context);
        return function (reason) { return promiseCall(fn, original, [reason]); };
    }
    function convertUnderlyingSourcePullCallback(fn, original, context) {
        assertFunction(fn, context);
        return function (controller) { return promiseCall(fn, original, [controller]); };
    }
    function convertUnderlyingSourceStartCallback(fn, original, context) {
        assertFunction(fn, context);
        return function (controller) { return reflectCall(fn, original, [controller]); };
    }
    function convertReadableStreamType(type, context) {
        type = "" + type;
        if (type !== 'bytes') {
            throw new TypeError(context + " '" + type + "' is not a valid enumeration value for ReadableStreamType");
        }
        return type;
    }

    function convertReaderOptions(options, context) {
        assertDictionary(options, context);
        var mode = options === null || options === void 0 ? void 0 : options.mode;
        return {
            mode: mode === undefined ? undefined : convertReadableStreamReaderMode(mode, context + " has member 'mode' that")
        };
    }
    function convertReadableStreamReaderMode(mode, context) {
        mode = "" + mode;
        if (mode !== 'byob') {
            throw new TypeError(context + " '" + mode + "' is not a valid enumeration value for ReadableStreamReaderMode");
        }
        return mode;
    }

    function convertIteratorOptions(options, context) {
        assertDictionary(options, context);
        var preventCancel = options === null || options === void 0 ? void 0 : options.preventCancel;
        return { preventCancel: Boolean(preventCancel) };
    }

    function convertPipeOptions(options, context) {
        assertDictionary(options, context);
        var preventAbort = options === null || options === void 0 ? void 0 : options.preventAbort;
        var preventCancel = options === null || options === void 0 ? void 0 : options.preventCancel;
        var preventClose = options === null || options === void 0 ? void 0 : options.preventClose;
        var signal = options === null || options === void 0 ? void 0 : options.signal;
        if (signal !== undefined) {
            assertAbortSignal(signal, context + " has member 'signal' that");
        }
        return {
            preventAbort: Boolean(preventAbort),
            preventCancel: Boolean(preventCancel),
            preventClose: Boolean(preventClose),
            signal: signal
        };
    }
    function assertAbortSignal(signal, context) {
        if (!isAbortSignal(signal)) {
            throw new TypeError(context + " is not an AbortSignal.");
        }
    }

    function convertReadableWritablePair(pair, context) {
        assertDictionary(pair, context);
        var readable = pair === null || pair === void 0 ? void 0 : pair.readable;
        assertRequiredField(readable, 'readable', 'ReadableWritablePair');
        assertReadableStream(readable, context + " has member 'readable' that");
        var writable = pair === null || pair === void 0 ? void 0 : pair.writable;
        assertRequiredField(writable, 'writable', 'ReadableWritablePair');
        assertWritableStream(writable, context + " has member 'writable' that");
        return { readable: readable, writable: writable };
    }

    /**
     * A readable stream represents a source of data, from which you can read.
     *
     * @public
     */
    var ReadableStream = /** @class */ (function () {
        function ReadableStream(rawUnderlyingSource, rawStrategy) {
            if (rawUnderlyingSource === void 0) { rawUnderlyingSource = {}; }
            if (rawStrategy === void 0) { rawStrategy = {}; }
            if (rawUnderlyingSource === undefined) {
                rawUnderlyingSource = null;
            }
            else {
                assertObject(rawUnderlyingSource, 'First parameter');
            }
            var strategy = convertQueuingStrategy(rawStrategy, 'Second parameter');
            var underlyingSource = convertUnderlyingDefaultOrByteSource(rawUnderlyingSource, 'First parameter');
            InitializeReadableStream(this);
            if (underlyingSource.type === 'bytes') {
                if (strategy.size !== undefined) {
                    throw new RangeError('The strategy for a byte stream cannot have a size function');
                }
                var highWaterMark = ExtractHighWaterMark(strategy, 0);
                SetUpReadableByteStreamControllerFromUnderlyingSource(this, underlyingSource, highWaterMark);
            }
            else {
                var sizeAlgorithm = ExtractSizeAlgorithm(strategy);
                var highWaterMark = ExtractHighWaterMark(strategy, 1);
                SetUpReadableStreamDefaultControllerFromUnderlyingSource(this, underlyingSource, highWaterMark, sizeAlgorithm);
            }
        }
        Object.defineProperty(ReadableStream.prototype, "locked", {
            /**
             * Whether or not the readable stream is locked to a {@link ReadableStreamDefaultReader | reader}.
             */
            get: function () {
                if (!IsReadableStream(this)) {
                    throw streamBrandCheckException$1('locked');
                }
                return IsReadableStreamLocked(this);
            },
            enumerable: false,
            configurable: true
        });
        /**
         * Cancels the stream, signaling a loss of interest in the stream by a consumer.
         *
         * The supplied `reason` argument will be given to the underlying source's {@link UnderlyingSource.cancel | cancel()}
         * method, which might or might not use it.
         */
        ReadableStream.prototype.cancel = function (reason) {
            if (reason === void 0) { reason = undefined; }
            if (!IsReadableStream(this)) {
                return promiseRejectedWith(streamBrandCheckException$1('cancel'));
            }
            if (IsReadableStreamLocked(this)) {
                return promiseRejectedWith(new TypeError('Cannot cancel a stream that already has a reader'));
            }
            return ReadableStreamCancel(this, reason);
        };
        ReadableStream.prototype.getReader = function (rawOptions) {
            if (rawOptions === void 0) { rawOptions = undefined; }
            if (!IsReadableStream(this)) {
                throw streamBrandCheckException$1('getReader');
            }
            var options = convertReaderOptions(rawOptions, 'First parameter');
            if (options.mode === undefined) {
                return AcquireReadableStreamDefaultReader(this);
            }
            return AcquireReadableStreamBYOBReader(this);
        };
        ReadableStream.prototype.pipeThrough = function (rawTransform, rawOptions) {
            if (rawOptions === void 0) { rawOptions = {}; }
            if (!IsReadableStream(this)) {
                throw streamBrandCheckException$1('pipeThrough');
            }
            assertRequiredArgument(rawTransform, 1, 'pipeThrough');
            var transform = convertReadableWritablePair(rawTransform, 'First parameter');
            var options = convertPipeOptions(rawOptions, 'Second parameter');
            if (IsReadableStreamLocked(this)) {
                throw new TypeError('ReadableStream.prototype.pipeThrough cannot be used on a locked ReadableStream');
            }
            if (IsWritableStreamLocked(transform.writable)) {
                throw new TypeError('ReadableStream.prototype.pipeThrough cannot be used on a locked WritableStream');
            }
            var promise = ReadableStreamPipeTo(this, transform.writable, options.preventClose, options.preventAbort, options.preventCancel, options.signal);
            setPromiseIsHandledToTrue(promise);
            return transform.readable;
        };
        ReadableStream.prototype.pipeTo = function (destination, rawOptions) {
            if (rawOptions === void 0) { rawOptions = {}; }
            if (!IsReadableStream(this)) {
                return promiseRejectedWith(streamBrandCheckException$1('pipeTo'));
            }
            if (destination === undefined) {
                return promiseRejectedWith("Parameter 1 is required in 'pipeTo'.");
            }
            if (!IsWritableStream(destination)) {
                return promiseRejectedWith(new TypeError("ReadableStream.prototype.pipeTo's first argument must be a WritableStream"));
            }
            var options;
            try {
                options = convertPipeOptions(rawOptions, 'Second parameter');
            }
            catch (e) {
                return promiseRejectedWith(e);
            }
            if (IsReadableStreamLocked(this)) {
                return promiseRejectedWith(new TypeError('ReadableStream.prototype.pipeTo cannot be used on a locked ReadableStream'));
            }
            if (IsWritableStreamLocked(destination)) {
                return promiseRejectedWith(new TypeError('ReadableStream.prototype.pipeTo cannot be used on a locked WritableStream'));
            }
            return ReadableStreamPipeTo(this, destination, options.preventClose, options.preventAbort, options.preventCancel, options.signal);
        };
        /**
         * Tees this readable stream, returning a two-element array containing the two resulting branches as
         * new {@link ReadableStream} instances.
         *
         * Teeing a stream will lock it, preventing any other consumer from acquiring a reader.
         * To cancel the stream, cancel both of the resulting branches; a composite cancellation reason will then be
         * propagated to the stream's underlying source.
         *
         * Note that the chunks seen in each branch will be the same object. If the chunks are not immutable,
         * this could allow interference between the two branches.
         */
        ReadableStream.prototype.tee = function () {
            if (!IsReadableStream(this)) {
                throw streamBrandCheckException$1('tee');
            }
            var branches = ReadableStreamTee(this);
            return CreateArrayFromList(branches);
        };
        ReadableStream.prototype.values = function (rawOptions) {
            if (rawOptions === void 0) { rawOptions = undefined; }
            if (!IsReadableStream(this)) {
                throw streamBrandCheckException$1('values');
            }
            var options = convertIteratorOptions(rawOptions, 'First parameter');
            return AcquireReadableStreamAsyncIterator(this, options.preventCancel);
        };
        return ReadableStream;
    }());
    Object.defineProperties(ReadableStream.prototype, {
        cancel: { enumerable: true },
        getReader: { enumerable: true },
        pipeThrough: { enumerable: true },
        pipeTo: { enumerable: true },
        tee: { enumerable: true },
        values: { enumerable: true },
        locked: { enumerable: true }
    });
    if (typeof SymbolPolyfill.toStringTag === 'symbol') {
        Object.defineProperty(ReadableStream.prototype, SymbolPolyfill.toStringTag, {
            value: 'ReadableStream',
            configurable: true
        });
    }
    if (typeof SymbolPolyfill.asyncIterator === 'symbol') {
        Object.defineProperty(ReadableStream.prototype, SymbolPolyfill.asyncIterator, {
            value: ReadableStream.prototype.values,
            writable: true,
            configurable: true
        });
    }
    // Abstract operations for the ReadableStream.
    // Throws if and only if startAlgorithm throws.
    function CreateReadableStream(startAlgorithm, pullAlgorithm, cancelAlgorithm, highWaterMark, sizeAlgorithm) {
        if (highWaterMark === void 0) { highWaterMark = 1; }
        if (sizeAlgorithm === void 0) { sizeAlgorithm = function () { return 1; }; }
        var stream = Object.create(ReadableStream.prototype);
        InitializeReadableStream(stream);
        var controller = Object.create(ReadableStreamDefaultController.prototype);
        SetUpReadableStreamDefaultController(stream, controller, startAlgorithm, pullAlgorithm, cancelAlgorithm, highWaterMark, sizeAlgorithm);
        return stream;
    }
    // Throws if and only if startAlgorithm throws.
    function CreateReadableByteStream(startAlgorithm, pullAlgorithm, cancelAlgorithm) {
        var stream = Object.create(ReadableStream.prototype);
        InitializeReadableStream(stream);
        var controller = Object.create(ReadableByteStreamController.prototype);
        SetUpReadableByteStreamController(stream, controller, startAlgorithm, pullAlgorithm, cancelAlgorithm, 0, undefined);
        return stream;
    }
    function InitializeReadableStream(stream) {
        stream._state = 'readable';
        stream._reader = undefined;
        stream._storedError = undefined;
        stream._disturbed = false;
    }
    function IsReadableStream(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_readableStreamController')) {
            return false;
        }
        return x instanceof ReadableStream;
    }
    function IsReadableStreamLocked(stream) {
        if (stream._reader === undefined) {
            return false;
        }
        return true;
    }
    // ReadableStream API exposed for controllers.
    function ReadableStreamCancel(stream, reason) {
        stream._disturbed = true;
        if (stream._state === 'closed') {
            return promiseResolvedWith(undefined);
        }
        if (stream._state === 'errored') {
            return promiseRejectedWith(stream._storedError);
        }
        ReadableStreamClose(stream);
        var reader = stream._reader;
        if (reader !== undefined && IsReadableStreamBYOBReader(reader)) {
            reader._readIntoRequests.forEach(function (readIntoRequest) {
                readIntoRequest._closeSteps(undefined);
            });
            reader._readIntoRequests = new SimpleQueue();
        }
        var sourceCancelPromise = stream._readableStreamController[CancelSteps](reason);
        return transformPromiseWith(sourceCancelPromise, noop);
    }
    function ReadableStreamClose(stream) {
        stream._state = 'closed';
        var reader = stream._reader;
        if (reader === undefined) {
            return;
        }
        defaultReaderClosedPromiseResolve(reader);
        if (IsReadableStreamDefaultReader(reader)) {
            reader._readRequests.forEach(function (readRequest) {
                readRequest._closeSteps();
            });
            reader._readRequests = new SimpleQueue();
        }
    }
    function ReadableStreamError(stream, e) {
        stream._state = 'errored';
        stream._storedError = e;
        var reader = stream._reader;
        if (reader === undefined) {
            return;
        }
        defaultReaderClosedPromiseReject(reader, e);
        if (IsReadableStreamDefaultReader(reader)) {
            reader._readRequests.forEach(function (readRequest) {
                readRequest._errorSteps(e);
            });
            reader._readRequests = new SimpleQueue();
        }
        else {
            reader._readIntoRequests.forEach(function (readIntoRequest) {
                readIntoRequest._errorSteps(e);
            });
            reader._readIntoRequests = new SimpleQueue();
        }
    }
    // Helper functions for the ReadableStream.
    function streamBrandCheckException$1(name) {
        return new TypeError("ReadableStream.prototype." + name + " can only be used on a ReadableStream");
    }

    function convertQueuingStrategyInit(init, context) {
        assertDictionary(init, context);
        var highWaterMark = init === null || init === void 0 ? void 0 : init.highWaterMark;
        assertRequiredField(highWaterMark, 'highWaterMark', 'QueuingStrategyInit');
        return {
            highWaterMark: convertUnrestrictedDouble(highWaterMark)
        };
    }

    // The size function must not have a prototype property nor be a constructor
    var byteLengthSizeFunction = function (chunk) {
        return chunk.byteLength;
    };
    try {
        Object.defineProperty(byteLengthSizeFunction, 'name', {
            value: 'size',
            configurable: true
        });
    }
    catch (_a) {
        // This property is non-configurable in older browsers, so ignore if this throws.
        // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/name#browser_compatibility
    }
    /**
     * A queuing strategy that counts the number of bytes in each chunk.
     *
     * @public
     */
    var ByteLengthQueuingStrategy = /** @class */ (function () {
        function ByteLengthQueuingStrategy(options) {
            assertRequiredArgument(options, 1, 'ByteLengthQueuingStrategy');
            options = convertQueuingStrategyInit(options, 'First parameter');
            this._byteLengthQueuingStrategyHighWaterMark = options.highWaterMark;
        }
        Object.defineProperty(ByteLengthQueuingStrategy.prototype, "highWaterMark", {
            /**
             * Returns the high water mark provided to the constructor.
             */
            get: function () {
                if (!IsByteLengthQueuingStrategy(this)) {
                    throw byteLengthBrandCheckException('highWaterMark');
                }
                return this._byteLengthQueuingStrategyHighWaterMark;
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(ByteLengthQueuingStrategy.prototype, "size", {
            /**
             * Measures the size of `chunk` by returning the value of its `byteLength` property.
             */
            get: function () {
                if (!IsByteLengthQueuingStrategy(this)) {
                    throw byteLengthBrandCheckException('size');
                }
                return byteLengthSizeFunction;
            },
            enumerable: false,
            configurable: true
        });
        return ByteLengthQueuingStrategy;
    }());
    Object.defineProperties(ByteLengthQueuingStrategy.prototype, {
        highWaterMark: { enumerable: true },
        size: { enumerable: true }
    });
    if (typeof SymbolPolyfill.toStringTag === 'symbol') {
        Object.defineProperty(ByteLengthQueuingStrategy.prototype, SymbolPolyfill.toStringTag, {
            value: 'ByteLengthQueuingStrategy',
            configurable: true
        });
    }
    // Helper functions for the ByteLengthQueuingStrategy.
    function byteLengthBrandCheckException(name) {
        return new TypeError("ByteLengthQueuingStrategy.prototype." + name + " can only be used on a ByteLengthQueuingStrategy");
    }
    function IsByteLengthQueuingStrategy(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_byteLengthQueuingStrategyHighWaterMark')) {
            return false;
        }
        return x instanceof ByteLengthQueuingStrategy;
    }

    // The size function must not have a prototype property nor be a constructor
    var countSizeFunction = function () {
        return 1;
    };
    try {
        Object.defineProperty(countSizeFunction, 'name', {
            value: 'size',
            configurable: true
        });
    }
    catch (_a) {
        // This property is non-configurable in older browsers, so ignore if this throws.
        // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/name#browser_compatibility
    }
    /**
     * A queuing strategy that counts the number of chunks.
     *
     * @public
     */
    var CountQueuingStrategy = /** @class */ (function () {
        function CountQueuingStrategy(options) {
            assertRequiredArgument(options, 1, 'CountQueuingStrategy');
            options = convertQueuingStrategyInit(options, 'First parameter');
            this._countQueuingStrategyHighWaterMark = options.highWaterMark;
        }
        Object.defineProperty(CountQueuingStrategy.prototype, "highWaterMark", {
            /**
             * Returns the high water mark provided to the constructor.
             */
            get: function () {
                if (!IsCountQueuingStrategy(this)) {
                    throw countBrandCheckException('highWaterMark');
                }
                return this._countQueuingStrategyHighWaterMark;
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(CountQueuingStrategy.prototype, "size", {
            /**
             * Measures the size of `chunk` by always returning 1.
             * This ensures that the total queue size is a count of the number of chunks in the queue.
             */
            get: function () {
                if (!IsCountQueuingStrategy(this)) {
                    throw countBrandCheckException('size');
                }
                return countSizeFunction;
            },
            enumerable: false,
            configurable: true
        });
        return CountQueuingStrategy;
    }());
    Object.defineProperties(CountQueuingStrategy.prototype, {
        highWaterMark: { enumerable: true },
        size: { enumerable: true }
    });
    if (typeof SymbolPolyfill.toStringTag === 'symbol') {
        Object.defineProperty(CountQueuingStrategy.prototype, SymbolPolyfill.toStringTag, {
            value: 'CountQueuingStrategy',
            configurable: true
        });
    }
    // Helper functions for the CountQueuingStrategy.
    function countBrandCheckException(name) {
        return new TypeError("CountQueuingStrategy.prototype." + name + " can only be used on a CountQueuingStrategy");
    }
    function IsCountQueuingStrategy(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_countQueuingStrategyHighWaterMark')) {
            return false;
        }
        return x instanceof CountQueuingStrategy;
    }

    function convertTransformer(original, context) {
        assertDictionary(original, context);
        var flush = original === null || original === void 0 ? void 0 : original.flush;
        var readableType = original === null || original === void 0 ? void 0 : original.readableType;
        var start = original === null || original === void 0 ? void 0 : original.start;
        var transform = original === null || original === void 0 ? void 0 : original.transform;
        var writableType = original === null || original === void 0 ? void 0 : original.writableType;
        return {
            flush: flush === undefined ?
                undefined :
                convertTransformerFlushCallback(flush, original, context + " has member 'flush' that"),
            readableType: readableType,
            start: start === undefined ?
                undefined :
                convertTransformerStartCallback(start, original, context + " has member 'start' that"),
            transform: transform === undefined ?
                undefined :
                convertTransformerTransformCallback(transform, original, context + " has member 'transform' that"),
            writableType: writableType
        };
    }
    function convertTransformerFlushCallback(fn, original, context) {
        assertFunction(fn, context);
        return function (controller) { return promiseCall(fn, original, [controller]); };
    }
    function convertTransformerStartCallback(fn, original, context) {
        assertFunction(fn, context);
        return function (controller) { return reflectCall(fn, original, [controller]); };
    }
    function convertTransformerTransformCallback(fn, original, context) {
        assertFunction(fn, context);
        return function (chunk, controller) { return promiseCall(fn, original, [chunk, controller]); };
    }

    // Class TransformStream
    /**
     * A transform stream consists of a pair of streams: a {@link WritableStream | writable stream},
     * known as its writable side, and a {@link ReadableStream | readable stream}, known as its readable side.
     * In a manner specific to the transform stream in question, writes to the writable side result in new data being
     * made available for reading from the readable side.
     *
     * @public
     */
    var TransformStream = /** @class */ (function () {
        function TransformStream(rawTransformer, rawWritableStrategy, rawReadableStrategy) {
            if (rawTransformer === void 0) { rawTransformer = {}; }
            if (rawWritableStrategy === void 0) { rawWritableStrategy = {}; }
            if (rawReadableStrategy === void 0) { rawReadableStrategy = {}; }
            if (rawTransformer === undefined) {
                rawTransformer = null;
            }
            var writableStrategy = convertQueuingStrategy(rawWritableStrategy, 'Second parameter');
            var readableStrategy = convertQueuingStrategy(rawReadableStrategy, 'Third parameter');
            var transformer = convertTransformer(rawTransformer, 'First parameter');
            if (transformer.readableType !== undefined) {
                throw new RangeError('Invalid readableType specified');
            }
            if (transformer.writableType !== undefined) {
                throw new RangeError('Invalid writableType specified');
            }
            var readableHighWaterMark = ExtractHighWaterMark(readableStrategy, 0);
            var readableSizeAlgorithm = ExtractSizeAlgorithm(readableStrategy);
            var writableHighWaterMark = ExtractHighWaterMark(writableStrategy, 1);
            var writableSizeAlgorithm = ExtractSizeAlgorithm(writableStrategy);
            var startPromise_resolve;
            var startPromise = newPromise(function (resolve) {
                startPromise_resolve = resolve;
            });
            InitializeTransformStream(this, startPromise, writableHighWaterMark, writableSizeAlgorithm, readableHighWaterMark, readableSizeAlgorithm);
            SetUpTransformStreamDefaultControllerFromTransformer(this, transformer);
            if (transformer.start !== undefined) {
                startPromise_resolve(transformer.start(this._transformStreamController));
            }
            else {
                startPromise_resolve(undefined);
            }
        }
        Object.defineProperty(TransformStream.prototype, "readable", {
            /**
             * The readable side of the transform stream.
             */
            get: function () {
                if (!IsTransformStream(this)) {
                    throw streamBrandCheckException('readable');
                }
                return this._readable;
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(TransformStream.prototype, "writable", {
            /**
             * The writable side of the transform stream.
             */
            get: function () {
                if (!IsTransformStream(this)) {
                    throw streamBrandCheckException('writable');
                }
                return this._writable;
            },
            enumerable: false,
            configurable: true
        });
        return TransformStream;
    }());
    Object.defineProperties(TransformStream.prototype, {
        readable: { enumerable: true },
        writable: { enumerable: true }
    });
    if (typeof SymbolPolyfill.toStringTag === 'symbol') {
        Object.defineProperty(TransformStream.prototype, SymbolPolyfill.toStringTag, {
            value: 'TransformStream',
            configurable: true
        });
    }
    function InitializeTransformStream(stream, startPromise, writableHighWaterMark, writableSizeAlgorithm, readableHighWaterMark, readableSizeAlgorithm) {
        function startAlgorithm() {
            return startPromise;
        }
        function writeAlgorithm(chunk) {
            return TransformStreamDefaultSinkWriteAlgorithm(stream, chunk);
        }
        function abortAlgorithm(reason) {
            return TransformStreamDefaultSinkAbortAlgorithm(stream, reason);
        }
        function closeAlgorithm() {
            return TransformStreamDefaultSinkCloseAlgorithm(stream);
        }
        stream._writable = CreateWritableStream(startAlgorithm, writeAlgorithm, closeAlgorithm, abortAlgorithm, writableHighWaterMark, writableSizeAlgorithm);
        function pullAlgorithm() {
            return TransformStreamDefaultSourcePullAlgorithm(stream);
        }
        function cancelAlgorithm(reason) {
            TransformStreamErrorWritableAndUnblockWrite(stream, reason);
            return promiseResolvedWith(undefined);
        }
        stream._readable = CreateReadableStream(startAlgorithm, pullAlgorithm, cancelAlgorithm, readableHighWaterMark, readableSizeAlgorithm);
        // The [[backpressure]] slot is set to undefined so that it can be initialised by TransformStreamSetBackpressure.
        stream._backpressure = undefined;
        stream._backpressureChangePromise = undefined;
        stream._backpressureChangePromise_resolve = undefined;
        TransformStreamSetBackpressure(stream, true);
        stream._transformStreamController = undefined;
    }
    function IsTransformStream(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_transformStreamController')) {
            return false;
        }
        return x instanceof TransformStream;
    }
    // This is a no-op if both sides are already errored.
    function TransformStreamError(stream, e) {
        ReadableStreamDefaultControllerError(stream._readable._readableStreamController, e);
        TransformStreamErrorWritableAndUnblockWrite(stream, e);
    }
    function TransformStreamErrorWritableAndUnblockWrite(stream, e) {
        TransformStreamDefaultControllerClearAlgorithms(stream._transformStreamController);
        WritableStreamDefaultControllerErrorIfNeeded(stream._writable._writableStreamController, e);
        if (stream._backpressure) {
            // Pretend that pull() was called to permit any pending write() calls to complete. TransformStreamSetBackpressure()
            // cannot be called from enqueue() or pull() once the ReadableStream is errored, so this will will be the final time
            // _backpressure is set.
            TransformStreamSetBackpressure(stream, false);
        }
    }
    function TransformStreamSetBackpressure(stream, backpressure) {
        // Passes also when called during construction.
        if (stream._backpressureChangePromise !== undefined) {
            stream._backpressureChangePromise_resolve();
        }
        stream._backpressureChangePromise = newPromise(function (resolve) {
            stream._backpressureChangePromise_resolve = resolve;
        });
        stream._backpressure = backpressure;
    }
    // Class TransformStreamDefaultController
    /**
     * Allows control of the {@link ReadableStream} and {@link WritableStream} of the associated {@link TransformStream}.
     *
     * @public
     */
    var TransformStreamDefaultController = /** @class */ (function () {
        function TransformStreamDefaultController() {
            throw new TypeError('Illegal constructor');
        }
        Object.defineProperty(TransformStreamDefaultController.prototype, "desiredSize", {
            /**
             * Returns the desired size to fill the readable side’s internal queue. It can be negative, if the queue is over-full.
             */
            get: function () {
                if (!IsTransformStreamDefaultController(this)) {
                    throw defaultControllerBrandCheckException('desiredSize');
                }
                var readableController = this._controlledTransformStream._readable._readableStreamController;
                return ReadableStreamDefaultControllerGetDesiredSize(readableController);
            },
            enumerable: false,
            configurable: true
        });
        TransformStreamDefaultController.prototype.enqueue = function (chunk) {
            if (chunk === void 0) { chunk = undefined; }
            if (!IsTransformStreamDefaultController(this)) {
                throw defaultControllerBrandCheckException('enqueue');
            }
            TransformStreamDefaultControllerEnqueue(this, chunk);
        };
        /**
         * Errors both the readable side and the writable side of the controlled transform stream, making all future
         * interactions with it fail with the given error `e`. Any chunks queued for transformation will be discarded.
         */
        TransformStreamDefaultController.prototype.error = function (reason) {
            if (reason === void 0) { reason = undefined; }
            if (!IsTransformStreamDefaultController(this)) {
                throw defaultControllerBrandCheckException('error');
            }
            TransformStreamDefaultControllerError(this, reason);
        };
        /**
         * Closes the readable side and errors the writable side of the controlled transform stream. This is useful when the
         * transformer only needs to consume a portion of the chunks written to the writable side.
         */
        TransformStreamDefaultController.prototype.terminate = function () {
            if (!IsTransformStreamDefaultController(this)) {
                throw defaultControllerBrandCheckException('terminate');
            }
            TransformStreamDefaultControllerTerminate(this);
        };
        return TransformStreamDefaultController;
    }());
    Object.defineProperties(TransformStreamDefaultController.prototype, {
        enqueue: { enumerable: true },
        error: { enumerable: true },
        terminate: { enumerable: true },
        desiredSize: { enumerable: true }
    });
    if (typeof SymbolPolyfill.toStringTag === 'symbol') {
        Object.defineProperty(TransformStreamDefaultController.prototype, SymbolPolyfill.toStringTag, {
            value: 'TransformStreamDefaultController',
            configurable: true
        });
    }
    // Transform Stream Default Controller Abstract Operations
    function IsTransformStreamDefaultController(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_controlledTransformStream')) {
            return false;
        }
        return x instanceof TransformStreamDefaultController;
    }
    function SetUpTransformStreamDefaultController(stream, controller, transformAlgorithm, flushAlgorithm) {
        controller._controlledTransformStream = stream;
        stream._transformStreamController = controller;
        controller._transformAlgorithm = transformAlgorithm;
        controller._flushAlgorithm = flushAlgorithm;
    }
    function SetUpTransformStreamDefaultControllerFromTransformer(stream, transformer) {
        var controller = Object.create(TransformStreamDefaultController.prototype);
        var transformAlgorithm = function (chunk) {
            try {
                TransformStreamDefaultControllerEnqueue(controller, chunk);
                return promiseResolvedWith(undefined);
            }
            catch (transformResultE) {
                return promiseRejectedWith(transformResultE);
            }
        };
        var flushAlgorithm = function () { return promiseResolvedWith(undefined); };
        if (transformer.transform !== undefined) {
            transformAlgorithm = function (chunk) { return transformer.transform(chunk, controller); };
        }
        if (transformer.flush !== undefined) {
            flushAlgorithm = function () { return transformer.flush(controller); };
        }
        SetUpTransformStreamDefaultController(stream, controller, transformAlgorithm, flushAlgorithm);
    }
    function TransformStreamDefaultControllerClearAlgorithms(controller) {
        controller._transformAlgorithm = undefined;
        controller._flushAlgorithm = undefined;
    }
    function TransformStreamDefaultControllerEnqueue(controller, chunk) {
        var stream = controller._controlledTransformStream;
        var readableController = stream._readable._readableStreamController;
        if (!ReadableStreamDefaultControllerCanCloseOrEnqueue(readableController)) {
            throw new TypeError('Readable side is not in a state that permits enqueue');
        }
        // We throttle transform invocations based on the backpressure of the ReadableStream, but we still
        // accept TransformStreamDefaultControllerEnqueue() calls.
        try {
            ReadableStreamDefaultControllerEnqueue(readableController, chunk);
        }
        catch (e) {
            // This happens when readableStrategy.size() throws.
            TransformStreamErrorWritableAndUnblockWrite(stream, e);
            throw stream._readable._storedError;
        }
        var backpressure = ReadableStreamDefaultControllerHasBackpressure(readableController);
        if (backpressure !== stream._backpressure) {
            TransformStreamSetBackpressure(stream, true);
        }
    }
    function TransformStreamDefaultControllerError(controller, e) {
        TransformStreamError(controller._controlledTransformStream, e);
    }
    function TransformStreamDefaultControllerPerformTransform(controller, chunk) {
        var transformPromise = controller._transformAlgorithm(chunk);
        return transformPromiseWith(transformPromise, undefined, function (r) {
            TransformStreamError(controller._controlledTransformStream, r);
            throw r;
        });
    }
    function TransformStreamDefaultControllerTerminate(controller) {
        var stream = controller._controlledTransformStream;
        var readableController = stream._readable._readableStreamController;
        ReadableStreamDefaultControllerClose(readableController);
        var error = new TypeError('TransformStream terminated');
        TransformStreamErrorWritableAndUnblockWrite(stream, error);
    }
    // TransformStreamDefaultSink Algorithms
    function TransformStreamDefaultSinkWriteAlgorithm(stream, chunk) {
        var controller = stream._transformStreamController;
        if (stream._backpressure) {
            var backpressureChangePromise = stream._backpressureChangePromise;
            return transformPromiseWith(backpressureChangePromise, function () {
                var writable = stream._writable;
                var state = writable._state;
                if (state === 'erroring') {
                    throw writable._storedError;
                }
                return TransformStreamDefaultControllerPerformTransform(controller, chunk);
            });
        }
        return TransformStreamDefaultControllerPerformTransform(controller, chunk);
    }
    function TransformStreamDefaultSinkAbortAlgorithm(stream, reason) {
        // abort() is not called synchronously, so it is possible for abort() to be called when the stream is already
        // errored.
        TransformStreamError(stream, reason);
        return promiseResolvedWith(undefined);
    }
    function TransformStreamDefaultSinkCloseAlgorithm(stream) {
        // stream._readable cannot change after construction, so caching it across a call to user code is safe.
        var readable = stream._readable;
        var controller = stream._transformStreamController;
        var flushPromise = controller._flushAlgorithm();
        TransformStreamDefaultControllerClearAlgorithms(controller);
        // Return a promise that is fulfilled with undefined on success.
        return transformPromiseWith(flushPromise, function () {
            if (readable._state === 'errored') {
                throw readable._storedError;
            }
            ReadableStreamDefaultControllerClose(readable._readableStreamController);
        }, function (r) {
            TransformStreamError(stream, r);
            throw readable._storedError;
        });
    }
    // TransformStreamDefaultSource Algorithms
    function TransformStreamDefaultSourcePullAlgorithm(stream) {
        // Invariant. Enforced by the promises returned by start() and pull().
        TransformStreamSetBackpressure(stream, false);
        // Prevent the next pull() call until there is backpressure.
        return stream._backpressureChangePromise;
    }
    // Helper functions for the TransformStreamDefaultController.
    function defaultControllerBrandCheckException(name) {
        return new TypeError("TransformStreamDefaultController.prototype." + name + " can only be used on a TransformStreamDefaultController");
    }
    // Helper functions for the TransformStream.
    function streamBrandCheckException(name) {
        return new TypeError("TransformStream.prototype." + name + " can only be used on a TransformStream");
    }

    exports.ByteLengthQueuingStrategy = ByteLengthQueuingStrategy;
    exports.CountQueuingStrategy = CountQueuingStrategy;
    exports.ReadableByteStreamController = ReadableByteStreamController;
    exports.ReadableStream = ReadableStream;
    exports.ReadableStreamBYOBReader = ReadableStreamBYOBReader;
    exports.ReadableStreamBYOBRequest = ReadableStreamBYOBRequest;
    exports.ReadableStreamDefaultController = ReadableStreamDefaultController;
    exports.ReadableStreamDefaultReader = ReadableStreamDefaultReader;
    exports.TransformStream = TransformStream;
    exports.TransformStreamDefaultController = TransformStreamDefaultController;
    exports.WritableStream = WritableStream;
    exports.WritableStreamDefaultController = WritableStreamDefaultController;
    exports.WritableStreamDefaultWriter = WritableStreamDefaultWriter;

    Object.defineProperty(exports, '__esModule', { value: true });

})));
//# sourceMappingURL=ponyfill.js.map


/***/ }),

/***/ 29375:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

try {
  module.exports = __webpack_require__(35356)
} catch (error) {
  module.exports = __webpack_require__(7856)
}


/***/ }),

/***/ 96219:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";

// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  j3: () => (/* binding */ NFTStorage)
});

// UNUSED EXPORTS: Blob, File, FormData, Token, createRateLimiter, toAsyncIterable, toGatewayURL

// NAMESPACE OBJECT: ./node_modules/multiformats/esm/src/bases/base58.js
var base58_namespaceObject = {};
__webpack_require__.r(base58_namespaceObject);
__webpack_require__.d(base58_namespaceObject, {
  base58btc: () => (base58btc),
  base58flickr: () => (base58flickr)
});

// NAMESPACE OBJECT: ./node_modules/multiformats/esm/src/bases/base32.js
var base32_namespaceObject = {};
__webpack_require__.r(base32_namespaceObject);
__webpack_require__.d(base32_namespaceObject, {
  base32: () => (base32_base32),
  base32hex: () => (base32hex),
  base32hexpad: () => (base32hexpad),
  base32hexpadupper: () => (base32hexpadupper),
  base32hexupper: () => (base32hexupper),
  base32pad: () => (base32pad),
  base32padupper: () => (base32padupper),
  base32upper: () => (base32upper),
  base32z: () => (base32z)
});

// NAMESPACE OBJECT: ./node_modules/multiformats/esm/src/codecs/raw.js
var raw_namespaceObject = {};
__webpack_require__.r(raw_namespaceObject);
__webpack_require__.d(raw_namespaceObject, {
  code: () => (raw_code),
  decode: () => (raw_decode),
  encode: () => (raw_encode),
  name: () => (raw_name)
});

// NAMESPACE OBJECT: ./node_modules/@ipld/dag-cbor/esm/index.js
var dag_cbor_esm_namespaceObject = {};
__webpack_require__.r(dag_cbor_esm_namespaceObject);
__webpack_require__.d(dag_cbor_esm_namespaceObject, {
  code: () => (esm_code),
  decode: () => (dag_cbor_esm_decode),
  encode: () => (dag_cbor_esm_encode),
  name: () => (dag_cbor_esm_name)
});

// NAMESPACE OBJECT: ./node_modules/@ipld/dag-pb/esm/src/index.js
var esm_src_namespaceObject = {};
__webpack_require__.r(esm_src_namespaceObject);
__webpack_require__.d(esm_src_namespaceObject, {
  code: () => (src_code),
  createLink: () => (createLink),
  createNode: () => (createNode),
  decode: () => (src_decode),
  encode: () => (src_encode),
  name: () => (src_name),
  prepare: () => (prepare),
  validate: () => (validate)
});

// NAMESPACE OBJECT: ./node_modules/multiformats/esm/src/hashes/sha2.js
var sha2_namespaceObject = {};
__webpack_require__.r(sha2_namespaceObject);
__webpack_require__.d(sha2_namespaceObject, {
  sha256: () => (sha256),
  sha512: () => (sha512)
});

// NAMESPACE OBJECT: ./node_modules/multiformats/esm/src/bases/identity.js
var identity_namespaceObject = {};
__webpack_require__.r(identity_namespaceObject);
__webpack_require__.d(identity_namespaceObject, {
  identity: () => (identity)
});

// NAMESPACE OBJECT: ./node_modules/multiformats/esm/src/bases/base2.js
var base2_namespaceObject = {};
__webpack_require__.r(base2_namespaceObject);
__webpack_require__.d(base2_namespaceObject, {
  base2: () => (base2)
});

// NAMESPACE OBJECT: ./node_modules/multiformats/esm/src/bases/base8.js
var base8_namespaceObject = {};
__webpack_require__.r(base8_namespaceObject);
__webpack_require__.d(base8_namespaceObject, {
  base8: () => (base8)
});

// NAMESPACE OBJECT: ./node_modules/multiformats/esm/src/bases/base10.js
var base10_namespaceObject = {};
__webpack_require__.r(base10_namespaceObject);
__webpack_require__.d(base10_namespaceObject, {
  base10: () => (base10)
});

// NAMESPACE OBJECT: ./node_modules/multiformats/esm/src/bases/base16.js
var base16_namespaceObject = {};
__webpack_require__.r(base16_namespaceObject);
__webpack_require__.d(base16_namespaceObject, {
  base16: () => (base16),
  base16upper: () => (base16upper)
});

// NAMESPACE OBJECT: ./node_modules/multiformats/esm/src/bases/base36.js
var base36_namespaceObject = {};
__webpack_require__.r(base36_namespaceObject);
__webpack_require__.d(base36_namespaceObject, {
  base36: () => (base36),
  base36upper: () => (base36upper)
});

// NAMESPACE OBJECT: ./node_modules/multiformats/esm/src/bases/base64.js
var base64_namespaceObject = {};
__webpack_require__.r(base64_namespaceObject);
__webpack_require__.d(base64_namespaceObject, {
  base64: () => (base64),
  base64pad: () => (base64pad),
  base64url: () => (base64url),
  base64urlpad: () => (base64urlpad)
});

// NAMESPACE OBJECT: ./node_modules/multiformats/esm/src/bases/base256emoji.js
var base256emoji_namespaceObject = {};
__webpack_require__.r(base256emoji_namespaceObject);
__webpack_require__.d(base256emoji_namespaceObject, {
  base256emoji: () => (base256emoji)
});

// NAMESPACE OBJECT: ./node_modules/multiformats/esm/src/hashes/identity.js
var hashes_identity_namespaceObject = {};
__webpack_require__.r(hashes_identity_namespaceObject);
__webpack_require__.d(hashes_identity_namespaceObject, {
  identity: () => (identity_identity)
});

// NAMESPACE OBJECT: ./node_modules/multiformats/esm/src/codecs/json.js
var json_namespaceObject = {};
__webpack_require__.r(json_namespaceObject);
__webpack_require__.d(json_namespaceObject, {
  code: () => (json_code),
  decode: () => (json_decode),
  encode: () => (json_encode),
  name: () => (json_name)
});

// NAMESPACE OBJECT: ./node_modules/blockstore-core/esm/src/errors.js
var errors_namespaceObject = {};
__webpack_require__.r(errors_namespaceObject);
__webpack_require__.d(errors_namespaceObject, {
  abortedError: () => (abortedError),
  notFoundError: () => (notFoundError)
});

;// CONCATENATED MODULE: ./node_modules/streaming-iterables/dist/index.mjs
async function* _batch(size, iterable) {
    let dataBatch = [];
    for await (const data of iterable) {
        dataBatch.push(data);
        if (dataBatch.length === size) {
            yield dataBatch;
            dataBatch = [];
        }
    }
    if (dataBatch.length > 0) {
        yield dataBatch;
    }
}
function* _syncBatch(size, iterable) {
    let dataBatch = [];
    for (const data of iterable) {
        dataBatch.push(data);
        if (dataBatch.length === size) {
            yield dataBatch;
            dataBatch = [];
        }
    }
    if (dataBatch.length > 0) {
        yield dataBatch;
    }
}
function batch(size, iterable) {
    if (iterable === undefined) {
        return curriedIterable => batch(size, curriedIterable);
    }
    if (iterable[Symbol.asyncIterator]) {
        return _batch(size, iterable);
    }
    return _syncBatch(size, iterable);
}

const TIMEOUT = Symbol('TIMEOUT');
const createTimer = (duration) => {
    let timeoutId;
    return [
        new Promise(resolve => {
            timeoutId = setTimeout(() => resolve(TIMEOUT), duration);
        }),
        () => {
            clearTimeout(timeoutId);
        },
    ];
};
// Like `batch` but flushes early if the `timeout` is reached
// NOTE: The strategy is to only hold onto a single item for a maximum of `timeout` ms.
async function* _batchWithTimeout(size, timeout, iterable) {
    const iterator = iterable[Symbol.asyncIterator]();
    let pendingData;
    let batchData = [];
    let timer;
    let clearTimer;
    const startTimer = () => {
        deleteTimer();
        [timer, clearTimer] = createTimer(timeout);
    };
    const deleteTimer = () => {
        if (clearTimer) {
            clearTimer();
        }
        timer = undefined;
    };
    pendingData = iterator.next();
    while (true) {
        const res = await (timer ? Promise.race([pendingData, timer]) : pendingData);
        if (res === TIMEOUT || res.done) {
            // Flush early (before we reach the batch size)
            if (batchData.length) {
                yield batchData;
                batchData = [];
            }
            deleteTimer();
            // And exit appropriately
            if (res !== TIMEOUT) {
                // done
                break;
            }
            continue;
        }
        // Fetch next item early doors (before we potentially yield)
        pendingData = iterator.next();
        // Then handle the value
        batchData.push(res.value);
        if (batchData.length === 1) {
            // Start timer once we have at least 1 item ready to go
            startTimer();
        }
        if (batchData.length === size) {
            yield batchData;
            batchData = [];
            deleteTimer();
            continue;
        }
    }
}
function batchWithTimeout(size, timeout, iterable) {
    if (iterable === undefined) {
        return curriedIterable => batchWithTimeout(size, timeout, curriedIterable);
    }
    if (iterable[Symbol.asyncIterator] && timeout !== Infinity) {
        return _batchWithTimeout(size, timeout, iterable);
    }
    // For sync iterables or an infinite timeout, the timeout is irrelevant so just fallback to regular `batch`.
    return batch(size, iterable);
}

function getIterator(iterable) {
    if (typeof iterable.next === 'function') {
        return iterable;
    }
    if (typeof iterable[Symbol.iterator] === 'function') {
        return iterable[Symbol.iterator]();
    }
    if (typeof iterable[Symbol.asyncIterator] === 'function') {
        return iterable[Symbol.asyncIterator]();
    }
    throw new TypeError('"values" does not to conform to any of the iterator or iterable protocols');
}

function defer() {
    let reject;
    let resolve;
    const promise = new Promise((resolveFunc, rejectFunc) => {
        resolve = resolveFunc;
        reject = rejectFunc;
    });
    return {
        promise,
        reject,
        resolve,
    };
}

function _buffer(size, iterable) {
    const iterator = getIterator(iterable);
    const resultQueue = [];
    const readQueue = [];
    let reading = false;
    let ended = false;
    function fulfillReadQueue() {
        while (readQueue.length > 0 && resultQueue.length > 0) {
            const readDeferred = readQueue.shift();
            const { error, value } = resultQueue.shift();
            if (error) {
                readDeferred.reject(error);
            }
            else {
                readDeferred.resolve({ done: false, value });
            }
        }
        while (readQueue.length > 0 && ended) {
            const { resolve } = readQueue.shift();
            resolve({ done: true, value: undefined });
        }
    }
    async function fillQueue() {
        if (ended) {
            return;
        }
        if (reading) {
            return;
        }
        if (resultQueue.length >= size) {
            return;
        }
        reading = true;
        try {
            const { done, value } = await iterator.next();
            if (done) {
                ended = true;
            }
            else {
                resultQueue.push({ value });
            }
        }
        catch (error) {
            ended = true;
            resultQueue.push({ error });
        }
        fulfillReadQueue();
        reading = false;
        fillQueue();
    }
    async function next() {
        if (resultQueue.length > 0) {
            const { error, value } = resultQueue.shift();
            if (error) {
                throw error;
            }
            fillQueue();
            return { done: false, value };
        }
        if (ended) {
            return { done: true, value: undefined }; // stupid ts
        }
        const deferred = defer();
        readQueue.push(deferred);
        fillQueue();
        return deferred.promise;
    }
    const asyncIterableIterator = {
        next,
        [Symbol.asyncIterator]: () => asyncIterableIterator,
    };
    return asyncIterableIterator;
}
function* syncBuffer(size, iterable) {
    const valueQueue = [];
    let e;
    try {
        for (const value of iterable) {
            valueQueue.push(value);
            if (valueQueue.length <= size) {
                continue;
            }
            yield valueQueue.shift();
        }
    }
    catch (error) {
        e = error;
    }
    for (const value of valueQueue) {
        yield value;
    }
    if (e) {
        throw e;
    }
}
function buffer(size, iterable) {
    if (iterable === undefined) {
        return curriedIterable => buffer(size, curriedIterable);
    }
    if (size === 0) {
        return iterable;
    }
    if (iterable[Symbol.asyncIterator]) {
        return _buffer(size, iterable);
    }
    return syncBuffer(size, iterable);
}

async function _collect(iterable) {
    const values = [];
    for await (const value of iterable) {
        values.push(value);
    }
    return values;
}
function collect(iterable) {
    if (iterable[Symbol.asyncIterator]) {
        return _collect(iterable);
    }
    return Array.from(iterable);
}

async function* _concat(iterables) {
    for await (const iterable of iterables) {
        yield* iterable;
    }
}
function* _syncConcat(iterables) {
    for (const iterable of iterables) {
        yield* iterable;
    }
}
function concat(...iterables) {
    const hasAnyAsync = iterables.find(itr => itr[Symbol.asyncIterator] !== undefined);
    if (hasAnyAsync) {
        return _concat(iterables);
    }
    else {
        return _syncConcat(iterables);
    }
}

async function _consume(iterable) {
    for await (const val of iterable) {
        // do nothing
    }
}
function consume(iterable) {
    if (iterable[Symbol.asyncIterator]) {
        return _consume(iterable);
    }
    for (const val of iterable) {
        // do nothing
    }
}

async function* _filter(filterFunc, iterable) {
    for await (const data of iterable) {
        if (await filterFunc(data)) {
            yield data;
        }
    }
}
function filter(filterFunc, iterable) {
    if (iterable === undefined) {
        return (curriedIterable) => _filter(filterFunc, curriedIterable);
    }
    return _filter(filterFunc, iterable);
}

async function* flatten(iterable) {
    for await (const maybeItr of iterable) {
        if (maybeItr && typeof maybeItr !== 'string' && (maybeItr[Symbol.iterator] || maybeItr[Symbol.asyncIterator])) {
            yield* flatten(maybeItr);
        }
        else {
            yield maybeItr;
        }
    }
}

async function* _map(func, iterable) {
    for await (const val of iterable) {
        yield await func(val);
    }
}
function map(func, iterable) {
    if (iterable === undefined) {
        return curriedIterable => _map(func, curriedIterable);
    }
    return _map(func, iterable);
}

function flatMap(func, iterable) {
    if (iterable === undefined) {
        return curriedIterable => flatMap(func, curriedIterable);
    }
    return filter(i => i !== undefined && i !== null, flatten(map(func, iterable)));
}

function _flatTransform(concurrency, func, iterable) {
    const iterator = getIterator(iterable);
    const resultQueue = [];
    const readQueue = [];
    let ended = false;
    let reading = false;
    let inflightCount = 0;
    let lastError = null;
    function fulfillReadQueue() {
        while (readQueue.length > 0 && resultQueue.length > 0) {
            const { resolve } = readQueue.shift();
            const value = resultQueue.shift();
            resolve({ done: false, value });
        }
        while (readQueue.length > 0 && inflightCount === 0 && ended) {
            const { resolve, reject } = readQueue.shift();
            if (lastError) {
                reject(lastError);
                lastError = null;
            }
            else {
                resolve({ done: true, value: undefined });
            }
        }
    }
    async function fillQueue() {
        if (ended) {
            fulfillReadQueue();
            return;
        }
        if (reading) {
            return;
        }
        if (inflightCount + resultQueue.length >= concurrency) {
            return;
        }
        reading = true;
        inflightCount++;
        try {
            const { done, value } = await iterator.next();
            if (done) {
                ended = true;
                inflightCount--;
                fulfillReadQueue();
            }
            else {
                mapAndQueue(value);
            }
        }
        catch (error) {
            ended = true;
            inflightCount--;
            lastError = error;
            fulfillReadQueue();
        }
        reading = false;
        fillQueue();
    }
    async function mapAndQueue(itrValue) {
        try {
            const value = await func(itrValue);
            if (value && value[Symbol.asyncIterator]) {
                for await (const asyncVal of value) {
                    resultQueue.push(asyncVal);
                }
            }
            else {
                resultQueue.push(value);
            }
        }
        catch (error) {
            ended = true;
            lastError = error;
        }
        inflightCount--;
        fulfillReadQueue();
        fillQueue();
    }
    async function next() {
        if (resultQueue.length === 0) {
            const deferred = defer();
            readQueue.push(deferred);
            fillQueue();
            return deferred.promise;
        }
        const value = resultQueue.shift();
        fillQueue();
        return { done: false, value };
    }
    const asyncIterableIterator = {
        next,
        [Symbol.asyncIterator]: () => asyncIterableIterator,
    };
    return asyncIterableIterator;
}
function flatTransform(concurrency, func, iterable) {
    if (func === undefined) {
        return (curriedFunc, curriedIterable) => curriedIterable
            ? flatTransform(concurrency, curriedFunc, curriedIterable)
            : flatTransform(concurrency, curriedFunc);
    }
    if (iterable === undefined) {
        return (curriedIterable) => flatTransform(concurrency, func, curriedIterable);
    }
    return filter(i => i !== undefined && i !== null, flatten(_flatTransform(concurrency, func, iterable)));
}

async function onceReadable(stream) {
    return new Promise(resolve => {
        stream.once('readable', () => {
            resolve();
        });
    });
}
async function* _fromStream(stream) {
    while (true) {
        const data = stream.read();
        if (data !== null) {
            yield data;
            continue;
        }
        if (stream._readableState.ended) {
            break;
        }
        await onceReadable(stream);
    }
}
function fromStream(stream) {
    if (typeof stream[Symbol.asyncIterator] === 'function') {
        return stream;
    }
    return _fromStream(stream);
}

async function* merge(...iterables) {
    const sources = new Set(iterables.map(getIterator));
    while (sources.size > 0) {
        for (const iterator of sources) {
            const nextVal = await iterator.next();
            if (nextVal.done) {
                sources.delete(iterator);
            }
            else {
                yield nextVal.value;
            }
        }
    }
}

function pipeline(firstFn, ...fns) {
    let previousFn = firstFn();
    for (const func of fns) {
        previousFn = func(previousFn);
    }
    return previousFn;
}

async function* _parallelMap(concurrency, func, iterable) {
    let transformError = null;
    const wrapFunc = value => ({
        value: func(value),
    });
    const stopOnError = async function* (source) {
        for await (const value of source) {
            if (transformError) {
                return;
            }
            yield value;
        }
    };
    const output = pipeline(() => iterable, buffer(1), stopOnError, map(wrapFunc), buffer(concurrency - 1));
    const itr = getIterator(output);
    while (true) {
        const { value, done } = await itr.next();
        if (done) {
            break;
        }
        try {
            const val = await value.value;
            if (!transformError) {
                yield val;
            }
        }
        catch (error) {
            transformError = error;
        }
    }
    if (transformError) {
        throw transformError;
    }
}
function parallelMap(concurrency, func, iterable) {
    if (func === undefined) {
        return (curriedFunc, curriedIterable) => parallelMap(concurrency, curriedFunc, curriedIterable);
    }
    if (iterable === undefined) {
        return curriedIterable => parallelMap(concurrency, func, curriedIterable);
    }
    if (concurrency === 1) {
        return map(func, iterable);
    }
    return _parallelMap(concurrency, func, iterable);
}

function parallelFlatMap(concurrency, func, iterable) {
    if (func === undefined) {
        return (curriedFunc, curriedIterable) => curriedIterable
            ? parallelFlatMap(concurrency, curriedFunc, curriedIterable)
            : parallelFlatMap(concurrency, curriedFunc);
    }
    if (iterable === undefined) {
        return (curriedIterable) => parallelFlatMap(concurrency, func, curriedIterable);
    }
    return filter(i => i !== undefined && i !== null, flatten(parallelMap(concurrency, func, iterable)));
}

async function* parallelMerge(...iterables) {
    const inputs = iterables.map(getIterator);
    const concurrentWork = new Set();
    const values = new Map();
    let lastError = null;
    let errCb = null;
    let valueCb = null;
    const notifyError = err => {
        lastError = err;
        if (errCb) {
            errCb(err);
        }
    };
    const notifyDone = value => {
        if (valueCb) {
            valueCb(value);
        }
    };
    const waitForQueue = () => new Promise((resolve, reject) => {
        if (lastError) {
            reject(lastError);
        }
        if (values.size > 0) {
            return resolve();
        }
        valueCb = resolve;
        errCb = reject;
    });
    const queueNext = input => {
        const nextVal = Promise.resolve(input.next()).then(async ({ done, value }) => {
            if (!done) {
                values.set(input, value);
            }
            concurrentWork.delete(nextVal);
        });
        concurrentWork.add(nextVal);
        nextVal.then(notifyDone, notifyError);
    };
    for (const input of inputs) {
        queueNext(input);
    }
    while (true) {
        // We technically don't have to check `values.size` as the for loop should have emptied it
        // However I haven't yet found specs verifying that behavior, only tests
        // the guard in waitForQueue() checking for values is in place for the same reason
        if (concurrentWork.size === 0 && values.size === 0) {
            return;
        }
        await waitForQueue();
        for (const [input, value] of values) {
            values.delete(input);
            yield value;
            queueNext(input);
        }
    }
}

async function _reduce(func, start, iterable) {
    let value = start;
    for await (const nextItem of iterable) {
        value = await func(value, nextItem);
    }
    return value;
}
function reduce(func, start, iterable) {
    if (start === undefined) {
        return (curriedStart, curriedIterable) => curriedIterable ? _reduce(func, curriedStart, curriedIterable) : reduce(func, curriedStart);
    }
    if (iterable === undefined) {
        return (curriedIterable) => reduce(func, start, curriedIterable);
    }
    return _reduce(func, start, iterable);
}

async function* _take(count, iterable) {
    let taken = 0;
    for await (const val of iterable) {
        yield await val;
        taken++;
        if (taken >= count) {
            break;
        }
    }
}
function* _syncTake(count, iterable) {
    let taken = 0;
    for (const val of iterable) {
        yield val;
        taken++;
        if (taken >= count) {
            break;
        }
    }
}
function take(count, iterable) {
    if (iterable === undefined) {
        return curriedIterable => take(count, curriedIterable);
    }
    if (iterable[Symbol.asyncIterator]) {
        return _take(count, iterable);
    }
    return _syncTake(count, iterable);
}

async function* _asyncTap(func, iterable) {
    for await (const val of iterable) {
        await func(val);
        yield val;
    }
}
function tap(func, iterable) {
    if (iterable === undefined) {
        return (curriedIterable) => _asyncTap(func, curriedIterable);
    }
    return _asyncTap(func, iterable);
}

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
function _throttle(limit, interval, iterable) {
    if (!Number.isFinite(limit)) {
        throw new TypeError('Expected `limit` to be a finite number');
    }
    if (limit <= 0) {
        throw new TypeError('Expected `limit` to be greater than 0');
    }
    if (!Number.isFinite(interval)) {
        throw new TypeError('Expected `interval` to be a finite number');
    }
    return (async function* __throttle() {
        let sent = 0;
        let time;
        for await (const val of iterable) {
            if (sent < limit) {
                if (typeof time === 'undefined') {
                    time = Date.now();
                }
                sent++;
                yield val;
                continue;
            }
            // Only wait if the interval hasn't already passed while we were
            // yielding the previous values.
            const elapsedMs = Date.now() - time;
            const waitFor = interval - elapsedMs;
            if (waitFor > 0) {
                await sleep(waitFor);
            }
            time = Date.now();
            sent = 1;
            yield val;
        }
    })();
}
function throttle(limit, interval, iterable) {
    if (iterable === undefined) {
        return (curriedIterable) => _throttle(limit, interval, curriedIterable);
    }
    return _throttle(limit, interval, iterable);
}

function addTime(a, b) {
    let seconds = a[0] + b[0];
    let nanoseconds = a[1] + b[1];
    if (nanoseconds >= 1000000000) {
        const remainder = nanoseconds % 1000000000;
        seconds += (nanoseconds - remainder) / 1000000000;
        nanoseconds = remainder;
    }
    return [seconds, nanoseconds];
}
async function* _asyncTime(config, iterable) {
    const itr = iterable[Symbol.asyncIterator]();
    let total = [0, 0];
    while (true) {
        const start = process.hrtime();
        const { value, done } = await itr.next();
        const delta = process.hrtime(start);
        total = addTime(total, delta);
        if (config.progress) {
            config.progress(delta, total);
        }
        if (done) {
            if (config.total) {
                config.total(total);
            }
            return value;
        }
        yield value;
    }
}
function* _syncTime(config, iterable) {
    const itr = iterable[Symbol.iterator]();
    let total = [0, 0];
    while (true) {
        const start = process.hrtime();
        const { value, done } = itr.next();
        const delta = process.hrtime(start);
        total = addTime(total, delta);
        if (config.progress) {
            config.progress(delta, total);
        }
        if (done) {
            if (config.total) {
                config.total(total);
            }
            return value;
        }
        yield value;
    }
}
function time(config = {}, iterable) {
    if (iterable === undefined) {
        return curriedIterable => time(config, curriedIterable);
    }
    if (iterable[Symbol.asyncIterator] !== undefined) {
        return _asyncTime(config, iterable);
    }
    else {
        return _syncTime(config, iterable);
    }
}

function _transform(concurrency, func, iterable) {
    const iterator = getIterator(iterable);
    const resultQueue = [];
    const readQueue = [];
    let ended = false;
    let reading = false;
    let inflightCount = 0;
    let lastError = null;
    function fulfillReadQueue() {
        while (readQueue.length > 0 && resultQueue.length > 0) {
            const { resolve } = readQueue.shift();
            const value = resultQueue.shift();
            resolve({ done: false, value });
        }
        while (readQueue.length > 0 && inflightCount === 0 && ended) {
            const { resolve, reject } = readQueue.shift();
            if (lastError) {
                reject(lastError);
                lastError = null;
            }
            else {
                resolve({ done: true, value: undefined });
            }
        }
    }
    async function fillQueue() {
        if (ended) {
            fulfillReadQueue();
            return;
        }
        if (reading) {
            return;
        }
        if (inflightCount + resultQueue.length >= concurrency) {
            return;
        }
        reading = true;
        inflightCount++;
        try {
            const { done, value } = await iterator.next();
            if (done) {
                ended = true;
                inflightCount--;
                fulfillReadQueue();
            }
            else {
                mapAndQueue(value);
            }
        }
        catch (error) {
            ended = true;
            inflightCount--;
            lastError = error;
            fulfillReadQueue();
        }
        reading = false;
        fillQueue();
    }
    async function mapAndQueue(itrValue) {
        try {
            const value = await func(itrValue);
            resultQueue.push(value);
        }
        catch (error) {
            ended = true;
            lastError = error;
        }
        inflightCount--;
        fulfillReadQueue();
        fillQueue();
    }
    async function next() {
        if (resultQueue.length === 0) {
            const deferred = defer();
            readQueue.push(deferred);
            fillQueue();
            return deferred.promise;
        }
        const value = resultQueue.shift();
        fillQueue();
        return { done: false, value };
    }
    const asyncIterableIterator = {
        next,
        [Symbol.asyncIterator]: () => asyncIterableIterator,
    };
    return asyncIterableIterator;
}
function transform(concurrency, func, iterable) {
    if (func === undefined) {
        return (curriedFunc, curriedIterable) => curriedIterable
            ? transform(concurrency, curriedFunc, curriedIterable)
            : transform(concurrency, curriedFunc);
    }
    if (iterable === undefined) {
        return (curriedIterable) => transform(concurrency, func, curriedIterable);
    }
    return _transform(concurrency, func, iterable);
}

async function _writeToStream(stream, iterable) {
    let lastError = null;
    let errCb = null;
    let drainCb = null;
    const notifyError = err => {
        lastError = err;
        if (errCb) {
            errCb(err);
        }
    };
    const notifyDrain = () => {
        if (drainCb) {
            drainCb();
        }
    };
    const cleanup = () => {
        stream.removeListener('error', notifyError);
        stream.removeListener('drain', notifyDrain);
    };
    stream.once('error', notifyError);
    const waitForDrain = () => new Promise((resolve, reject) => {
        if (lastError) {
            return reject(lastError);
        }
        stream.once('drain', notifyDrain);
        drainCb = resolve;
        errCb = reject;
    });
    for await (const value of iterable) {
        if (stream.write(value) === false) {
            await waitForDrain();
        }
        if (lastError) {
            break;
        }
    }
    cleanup();
    if (lastError) {
        throw lastError;
    }
}
function writeToStream(stream, iterable) {
    if (iterable === undefined) {
        return (curriedIterable) => _writeToStream(stream, curriedIterable);
    }
    return _writeToStream(stream, iterable);
}



// EXTERNAL MODULE: ./node_modules/p-retry/index.js
var p_retry = __webpack_require__(71856);
// EXTERNAL MODULE: external "fs"
var external_fs_ = __webpack_require__(57147);
// EXTERNAL MODULE: external "util"
var external_util_ = __webpack_require__(73837);
// EXTERNAL MODULE: ./node_modules/varint/index.js
var varint = __webpack_require__(22782);
;// CONCATENATED MODULE: ./node_modules/multiformats/esm/vendor/varint.js
var encode_1 = encode;
var MSB = 128, REST = 127, MSBALL = ~REST, INT = Math.pow(2, 31);
function encode(num, out, offset) {
  out = out || [];
  offset = offset || 0;
  var oldOffset = offset;
  while (num >= INT) {
    out[offset++] = num & 255 | MSB;
    num /= 128;
  }
  while (num & MSBALL) {
    out[offset++] = num & 255 | MSB;
    num >>>= 7;
  }
  out[offset] = num | 0;
  encode.bytes = offset - oldOffset + 1;
  return out;
}
var decode = read;
var MSB$1 = 128, REST$1 = 127;
function read(buf, offset) {
  var res = 0, offset = offset || 0, shift = 0, counter = offset, b, l = buf.length;
  do {
    if (counter >= l) {
      read.bytes = 0;
      throw new RangeError('Could not decode varint');
    }
    b = buf[counter++];
    res += shift < 28 ? (b & REST$1) << shift : (b & REST$1) * Math.pow(2, shift);
    shift += 7;
  } while (b >= MSB$1);
  read.bytes = counter - offset;
  return res;
}
var N1 = Math.pow(2, 7);
var N2 = Math.pow(2, 14);
var N3 = Math.pow(2, 21);
var N4 = Math.pow(2, 28);
var N5 = Math.pow(2, 35);
var N6 = Math.pow(2, 42);
var N7 = Math.pow(2, 49);
var N8 = Math.pow(2, 56);
var N9 = Math.pow(2, 63);
var varint_length = function (value) {
  return value < N1 ? 1 : value < N2 ? 2 : value < N3 ? 3 : value < N4 ? 4 : value < N5 ? 5 : value < N6 ? 6 : value < N7 ? 7 : value < N8 ? 8 : value < N9 ? 9 : 10;
};
var varint_varint = {
  encode: encode_1,
  decode: decode,
  encodingLength: varint_length
};
var _brrp_varint = varint_varint;
/* harmony default export */ const vendor_varint = (_brrp_varint);
;// CONCATENATED MODULE: ./node_modules/multiformats/esm/src/varint.js

const varint_decode = (data, offset = 0) => {
  const code = vendor_varint.decode(data, offset);
  return [
    code,
    vendor_varint.decode.bytes
  ];
};
const encodeTo = (int, target, offset = 0) => {
  vendor_varint.encode(int, target, offset);
  return target;
};
const encodingLength = int => {
  return vendor_varint.encodingLength(int);
};
;// CONCATENATED MODULE: ./node_modules/multiformats/esm/src/bytes.js
const empty = new Uint8Array(0);
const toHex = d => d.reduce((hex, byte) => hex + byte.toString(16).padStart(2, '0'), '');
const fromHex = hex => {
  const hexes = hex.match(/../g);
  return hexes ? new Uint8Array(hexes.map(b => parseInt(b, 16))) : empty;
};
const equals = (aa, bb) => {
  if (aa === bb)
    return true;
  if (aa.byteLength !== bb.byteLength) {
    return false;
  }
  for (let ii = 0; ii < aa.byteLength; ii++) {
    if (aa[ii] !== bb[ii]) {
      return false;
    }
  }
  return true;
};
const coerce = o => {
  if (o instanceof Uint8Array && o.constructor.name === 'Uint8Array')
    return o;
  if (o instanceof ArrayBuffer)
    return new Uint8Array(o);
  if (ArrayBuffer.isView(o)) {
    return new Uint8Array(o.buffer, o.byteOffset, o.byteLength);
  }
  throw new Error('Unknown type, must be binary type');
};
const isBinary = o => o instanceof ArrayBuffer || ArrayBuffer.isView(o);
const fromString = str => new TextEncoder().encode(str);
const bytes_toString = b => new TextDecoder().decode(b);

;// CONCATENATED MODULE: ./node_modules/multiformats/esm/src/hashes/digest.js


const create = (code, digest) => {
  const size = digest.byteLength;
  const sizeOffset = encodingLength(code);
  const digestOffset = sizeOffset + encodingLength(size);
  const bytes = new Uint8Array(digestOffset + size);
  encodeTo(code, bytes, 0);
  encodeTo(size, bytes, sizeOffset);
  bytes.set(digest, digestOffset);
  return new digest_Digest(code, size, digest, bytes);
};
const digest_decode = multihash => {
  const bytes = coerce(multihash);
  const [code, sizeOffset] = varint_decode(bytes);
  const [size, digestOffset] = varint_decode(bytes.subarray(sizeOffset));
  const digest = bytes.subarray(sizeOffset + digestOffset);
  if (digest.byteLength !== size) {
    throw new Error('Incorrect length');
  }
  return new digest_Digest(code, size, digest, bytes);
};
const digest_equals = (a, b) => {
  if (a === b) {
    return true;
  } else {
    return a.code === b.code && a.size === b.size && equals(a.bytes, b.bytes);
  }
};
class digest_Digest {
  constructor(code, size, digest, bytes) {
    this.code = code;
    this.size = size;
    this.digest = digest;
    this.bytes = bytes;
  }
}
;// CONCATENATED MODULE: ./node_modules/multiformats/esm/vendor/base-x.js
function base(ALPHABET, name) {
  if (ALPHABET.length >= 255) {
    throw new TypeError('Alphabet too long');
  }
  var BASE_MAP = new Uint8Array(256);
  for (var j = 0; j < BASE_MAP.length; j++) {
    BASE_MAP[j] = 255;
  }
  for (var i = 0; i < ALPHABET.length; i++) {
    var x = ALPHABET.charAt(i);
    var xc = x.charCodeAt(0);
    if (BASE_MAP[xc] !== 255) {
      throw new TypeError(x + ' is ambiguous');
    }
    BASE_MAP[xc] = i;
  }
  var BASE = ALPHABET.length;
  var LEADER = ALPHABET.charAt(0);
  var FACTOR = Math.log(BASE) / Math.log(256);
  var iFACTOR = Math.log(256) / Math.log(BASE);
  function encode(source) {
    if (source instanceof Uint8Array);
    else if (ArrayBuffer.isView(source)) {
      source = new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
    } else if (Array.isArray(source)) {
      source = Uint8Array.from(source);
    }
    if (!(source instanceof Uint8Array)) {
      throw new TypeError('Expected Uint8Array');
    }
    if (source.length === 0) {
      return '';
    }
    var zeroes = 0;
    var length = 0;
    var pbegin = 0;
    var pend = source.length;
    while (pbegin !== pend && source[pbegin] === 0) {
      pbegin++;
      zeroes++;
    }
    var size = (pend - pbegin) * iFACTOR + 1 >>> 0;
    var b58 = new Uint8Array(size);
    while (pbegin !== pend) {
      var carry = source[pbegin];
      var i = 0;
      for (var it1 = size - 1; (carry !== 0 || i < length) && it1 !== -1; it1--, i++) {
        carry += 256 * b58[it1] >>> 0;
        b58[it1] = carry % BASE >>> 0;
        carry = carry / BASE >>> 0;
      }
      if (carry !== 0) {
        throw new Error('Non-zero carry');
      }
      length = i;
      pbegin++;
    }
    var it2 = size - length;
    while (it2 !== size && b58[it2] === 0) {
      it2++;
    }
    var str = LEADER.repeat(zeroes);
    for (; it2 < size; ++it2) {
      str += ALPHABET.charAt(b58[it2]);
    }
    return str;
  }
  function decodeUnsafe(source) {
    if (typeof source !== 'string') {
      throw new TypeError('Expected String');
    }
    if (source.length === 0) {
      return new Uint8Array();
    }
    var psz = 0;
    if (source[psz] === ' ') {
      return;
    }
    var zeroes = 0;
    var length = 0;
    while (source[psz] === LEADER) {
      zeroes++;
      psz++;
    }
    var size = (source.length - psz) * FACTOR + 1 >>> 0;
    var b256 = new Uint8Array(size);
    while (source[psz]) {
      var carry = BASE_MAP[source.charCodeAt(psz)];
      if (carry === 255) {
        return;
      }
      var i = 0;
      for (var it3 = size - 1; (carry !== 0 || i < length) && it3 !== -1; it3--, i++) {
        carry += BASE * b256[it3] >>> 0;
        b256[it3] = carry % 256 >>> 0;
        carry = carry / 256 >>> 0;
      }
      if (carry !== 0) {
        throw new Error('Non-zero carry');
      }
      length = i;
      psz++;
    }
    if (source[psz] === ' ') {
      return;
    }
    var it4 = size - length;
    while (it4 !== size && b256[it4] === 0) {
      it4++;
    }
    var vch = new Uint8Array(zeroes + (size - it4));
    var j = zeroes;
    while (it4 !== size) {
      vch[j++] = b256[it4++];
    }
    return vch;
  }
  function decode(string) {
    var buffer = decodeUnsafe(string);
    if (buffer) {
      return buffer;
    }
    throw new Error(`Non-${ name } character`);
  }
  return {
    encode: encode,
    decodeUnsafe: decodeUnsafe,
    decode: decode
  };
}
var src = base;
var _brrp__multiformats_scope_baseX = src;
/* harmony default export */ const base_x = (_brrp__multiformats_scope_baseX);
;// CONCATENATED MODULE: ./node_modules/multiformats/esm/src/bases/base.js


class Encoder {
  constructor(name, prefix, baseEncode) {
    this.name = name;
    this.prefix = prefix;
    this.baseEncode = baseEncode;
  }
  encode(bytes) {
    if (bytes instanceof Uint8Array) {
      return `${ this.prefix }${ this.baseEncode(bytes) }`;
    } else {
      throw Error('Unknown type, must be binary type');
    }
  }
}
class Decoder {
  constructor(name, prefix, baseDecode) {
    this.name = name;
    this.prefix = prefix;
    if (prefix.codePointAt(0) === undefined) {
      throw new Error('Invalid prefix character');
    }
    this.prefixCodePoint = prefix.codePointAt(0);
    this.baseDecode = baseDecode;
  }
  decode(text) {
    if (typeof text === 'string') {
      if (text.codePointAt(0) !== this.prefixCodePoint) {
        throw Error(`Unable to decode multibase string ${ JSON.stringify(text) }, ${ this.name } decoder only supports inputs prefixed with ${ this.prefix }`);
      }
      return this.baseDecode(text.slice(this.prefix.length));
    } else {
      throw Error('Can only multibase decode strings');
    }
  }
  or(decoder) {
    return or(this, decoder);
  }
}
class ComposedDecoder {
  constructor(decoders) {
    this.decoders = decoders;
  }
  or(decoder) {
    return or(this, decoder);
  }
  decode(input) {
    const prefix = input[0];
    const decoder = this.decoders[prefix];
    if (decoder) {
      return decoder.decode(input);
    } else {
      throw RangeError(`Unable to decode multibase string ${ JSON.stringify(input) }, only inputs prefixed with ${ Object.keys(this.decoders) } are supported`);
    }
  }
}
const or = (left, right) => new ComposedDecoder({
  ...left.decoders || { [left.prefix]: left },
  ...right.decoders || { [right.prefix]: right }
});
class Codec {
  constructor(name, prefix, baseEncode, baseDecode) {
    this.name = name;
    this.prefix = prefix;
    this.baseEncode = baseEncode;
    this.baseDecode = baseDecode;
    this.encoder = new Encoder(name, prefix, baseEncode);
    this.decoder = new Decoder(name, prefix, baseDecode);
  }
  encode(input) {
    return this.encoder.encode(input);
  }
  decode(input) {
    return this.decoder.decode(input);
  }
}
const from = ({name, prefix, encode, decode}) => new Codec(name, prefix, encode, decode);
const baseX = ({prefix, name, alphabet}) => {
  const {encode, decode} = base_x(alphabet, name);
  return from({
    prefix,
    name,
    encode,
    decode: text => coerce(decode(text))
  });
};
const base_decode = (string, alphabet, bitsPerChar, name) => {
  const codes = {};
  for (let i = 0; i < alphabet.length; ++i) {
    codes[alphabet[i]] = i;
  }
  let end = string.length;
  while (string[end - 1] === '=') {
    --end;
  }
  const out = new Uint8Array(end * bitsPerChar / 8 | 0);
  let bits = 0;
  let buffer = 0;
  let written = 0;
  for (let i = 0; i < end; ++i) {
    const value = codes[string[i]];
    if (value === undefined) {
      throw new SyntaxError(`Non-${ name } character`);
    }
    buffer = buffer << bitsPerChar | value;
    bits += bitsPerChar;
    if (bits >= 8) {
      bits -= 8;
      out[written++] = 255 & buffer >> bits;
    }
  }
  if (bits >= bitsPerChar || 255 & buffer << 8 - bits) {
    throw new SyntaxError('Unexpected end of data');
  }
  return out;
};
const base_encode = (data, alphabet, bitsPerChar) => {
  const pad = alphabet[alphabet.length - 1] === '=';
  const mask = (1 << bitsPerChar) - 1;
  let out = '';
  let bits = 0;
  let buffer = 0;
  for (let i = 0; i < data.length; ++i) {
    buffer = buffer << 8 | data[i];
    bits += 8;
    while (bits > bitsPerChar) {
      bits -= bitsPerChar;
      out += alphabet[mask & buffer >> bits];
    }
  }
  if (bits) {
    out += alphabet[mask & buffer << bitsPerChar - bits];
  }
  if (pad) {
    while (out.length * bitsPerChar & 7) {
      out += '=';
    }
  }
  return out;
};
const rfc4648 = ({name, prefix, bitsPerChar, alphabet}) => {
  return from({
    prefix,
    name,
    encode(input) {
      return base_encode(input, alphabet, bitsPerChar);
    },
    decode(input) {
      return base_decode(input, alphabet, bitsPerChar, name);
    }
  });
};
;// CONCATENATED MODULE: ./node_modules/multiformats/esm/src/bases/base58.js

const base58btc = baseX({
  name: 'base58btc',
  prefix: 'z',
  alphabet: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
});
const base58flickr = baseX({
  name: 'base58flickr',
  prefix: 'Z',
  alphabet: '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ'
});
;// CONCATENATED MODULE: ./node_modules/multiformats/esm/src/bases/base32.js

const base32_base32 = rfc4648({
  prefix: 'b',
  name: 'base32',
  alphabet: 'abcdefghijklmnopqrstuvwxyz234567',
  bitsPerChar: 5
});
const base32upper = rfc4648({
  prefix: 'B',
  name: 'base32upper',
  alphabet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
  bitsPerChar: 5
});
const base32pad = rfc4648({
  prefix: 'c',
  name: 'base32pad',
  alphabet: 'abcdefghijklmnopqrstuvwxyz234567=',
  bitsPerChar: 5
});
const base32padupper = rfc4648({
  prefix: 'C',
  name: 'base32padupper',
  alphabet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=',
  bitsPerChar: 5
});
const base32hex = rfc4648({
  prefix: 'v',
  name: 'base32hex',
  alphabet: '0123456789abcdefghijklmnopqrstuv',
  bitsPerChar: 5
});
const base32hexupper = rfc4648({
  prefix: 'V',
  name: 'base32hexupper',
  alphabet: '0123456789ABCDEFGHIJKLMNOPQRSTUV',
  bitsPerChar: 5
});
const base32hexpad = rfc4648({
  prefix: 't',
  name: 'base32hexpad',
  alphabet: '0123456789abcdefghijklmnopqrstuv=',
  bitsPerChar: 5
});
const base32hexpadupper = rfc4648({
  prefix: 'T',
  name: 'base32hexpadupper',
  alphabet: '0123456789ABCDEFGHIJKLMNOPQRSTUV=',
  bitsPerChar: 5
});
const base32z = rfc4648({
  prefix: 'h',
  name: 'base32z',
  alphabet: 'ybndrfg8ejkmcpqxot1uwisza345h769',
  bitsPerChar: 5
});
;// CONCATENATED MODULE: ./node_modules/multiformats/esm/src/cid.js





class cid_CID {
  constructor(version, code, multihash, bytes) {
    this.code = code;
    this.version = version;
    this.multihash = multihash;
    this.bytes = bytes;
    this.byteOffset = bytes.byteOffset;
    this.byteLength = bytes.byteLength;
    this.asCID = this;
    this._baseCache = new Map();
    Object.defineProperties(this, {
      byteOffset: cid_hidden,
      byteLength: cid_hidden,
      code: readonly,
      version: readonly,
      multihash: readonly,
      bytes: readonly,
      _baseCache: cid_hidden,
      asCID: cid_hidden
    });
  }
  toV0() {
    switch (this.version) {
    case 0: {
        return this;
      }
    default: {
        const {code, multihash} = this;
        if (code !== DAG_PB_CODE) {
          throw new Error('Cannot convert a non dag-pb CID to CIDv0');
        }
        if (multihash.code !== SHA_256_CODE) {
          throw new Error('Cannot convert non sha2-256 multihash CID to CIDv0');
        }
        return cid_CID.createV0(multihash);
      }
    }
  }
  toV1() {
    switch (this.version) {
    case 0: {
        const {code, digest} = this.multihash;
        const multihash = create(code, digest);
        return cid_CID.createV1(this.code, multihash);
      }
    case 1: {
        return this;
      }
    default: {
        throw Error(`Can not convert CID version ${ this.version } to version 0. This is a bug please report`);
      }
    }
  }
  equals(other) {
    return other && this.code === other.code && this.version === other.version && digest_equals(this.multihash, other.multihash);
  }
  toString(base) {
    const {bytes, version, _baseCache} = this;
    switch (version) {
    case 0:
      return toStringV0(bytes, _baseCache, base || base58btc.encoder);
    default:
      return toStringV1(bytes, _baseCache, base || base32_base32.encoder);
    }
  }
  toJSON() {
    return {
      code: this.code,
      version: this.version,
      hash: this.multihash.bytes
    };
  }
  get [Symbol.toStringTag]() {
    return 'CID';
  }
  [Symbol.for('nodejs.util.inspect.custom')]() {
    return 'CID(' + this.toString() + ')';
  }
  static isCID(value) {
    deprecate(/^0\.0/, IS_CID_DEPRECATION);
    return !!(value && (value[cidSymbol] || value.asCID === value));
  }
  get toBaseEncodedString() {
    throw new Error('Deprecated, use .toString()');
  }
  get codec() {
    throw new Error('"codec" property is deprecated, use integer "code" property instead');
  }
  get buffer() {
    throw new Error('Deprecated .buffer property, use .bytes to get Uint8Array instead');
  }
  get multibaseName() {
    throw new Error('"multibaseName" property is deprecated');
  }
  get prefix() {
    throw new Error('"prefix" property is deprecated');
  }
  static asCID(value) {
    if (value instanceof cid_CID) {
      return value;
    } else if (value != null && value.asCID === value) {
      const {version, code, multihash, bytes} = value;
      return new cid_CID(version, code, multihash, bytes || encodeCID(version, code, multihash.bytes));
    } else if (value != null && value[cidSymbol] === true) {
      const {version, multihash, code} = value;
      const digest = digest_decode(multihash);
      return cid_CID.create(version, code, digest);
    } else {
      return null;
    }
  }
  static create(version, code, digest) {
    if (typeof code !== 'number') {
      throw new Error('String codecs are no longer supported');
    }
    switch (version) {
    case 0: {
        if (code !== DAG_PB_CODE) {
          throw new Error(`Version 0 CID must use dag-pb (code: ${ DAG_PB_CODE }) block encoding`);
        } else {
          return new cid_CID(version, code, digest, digest.bytes);
        }
      }
    case 1: {
        const bytes = encodeCID(version, code, digest.bytes);
        return new cid_CID(version, code, digest, bytes);
      }
    default: {
        throw new Error('Invalid version');
      }
    }
  }
  static createV0(digest) {
    return cid_CID.create(0, DAG_PB_CODE, digest);
  }
  static createV1(code, digest) {
    return cid_CID.create(1, code, digest);
  }
  static decode(bytes) {
    const [cid, remainder] = cid_CID.decodeFirst(bytes);
    if (remainder.length) {
      throw new Error('Incorrect length');
    }
    return cid;
  }
  static decodeFirst(bytes) {
    const specs = cid_CID.inspectBytes(bytes);
    const prefixSize = specs.size - specs.multihashSize;
    const multihashBytes = coerce(bytes.subarray(prefixSize, prefixSize + specs.multihashSize));
    if (multihashBytes.byteLength !== specs.multihashSize) {
      throw new Error('Incorrect length');
    }
    const digestBytes = multihashBytes.subarray(specs.multihashSize - specs.digestSize);
    const digest = new digest_Digest(specs.multihashCode, specs.digestSize, digestBytes, multihashBytes);
    const cid = specs.version === 0 ? cid_CID.createV0(digest) : cid_CID.createV1(specs.codec, digest);
    return [
      cid,
      bytes.subarray(specs.size)
    ];
  }
  static inspectBytes(initialBytes) {
    let offset = 0;
    const next = () => {
      const [i, length] = varint_decode(initialBytes.subarray(offset));
      offset += length;
      return i;
    };
    let version = next();
    let codec = DAG_PB_CODE;
    if (version === 18) {
      version = 0;
      offset = 0;
    } else if (version === 1) {
      codec = next();
    }
    if (version !== 0 && version !== 1) {
      throw new RangeError(`Invalid CID version ${ version }`);
    }
    const prefixSize = offset;
    const multihashCode = next();
    const digestSize = next();
    const size = offset + digestSize;
    const multihashSize = size - prefixSize;
    return {
      version,
      codec,
      multihashCode,
      digestSize,
      multihashSize,
      size
    };
  }
  static parse(source, base) {
    const [prefix, bytes] = parseCIDtoBytes(source, base);
    const cid = cid_CID.decode(bytes);
    cid._baseCache.set(prefix, source);
    return cid;
  }
}
const parseCIDtoBytes = (source, base) => {
  switch (source[0]) {
  case 'Q': {
      const decoder = base || base58btc;
      return [
        base58btc.prefix,
        decoder.decode(`${ base58btc.prefix }${ source }`)
      ];
    }
  case base58btc.prefix: {
      const decoder = base || base58btc;
      return [
        base58btc.prefix,
        decoder.decode(source)
      ];
    }
  case base32_base32.prefix: {
      const decoder = base || base32_base32;
      return [
        base32_base32.prefix,
        decoder.decode(source)
      ];
    }
  default: {
      if (base == null) {
        throw Error('To parse non base32 or base58btc encoded CID multibase decoder must be provided');
      }
      return [
        source[0],
        base.decode(source)
      ];
    }
  }
};
const toStringV0 = (bytes, cache, base) => {
  const {prefix} = base;
  if (prefix !== base58btc.prefix) {
    throw Error(`Cannot string encode V0 in ${ base.name } encoding`);
  }
  const cid = cache.get(prefix);
  if (cid == null) {
    const cid = base.encode(bytes).slice(1);
    cache.set(prefix, cid);
    return cid;
  } else {
    return cid;
  }
};
const toStringV1 = (bytes, cache, base) => {
  const {prefix} = base;
  const cid = cache.get(prefix);
  if (cid == null) {
    const cid = base.encode(bytes);
    cache.set(prefix, cid);
    return cid;
  } else {
    return cid;
  }
};
const DAG_PB_CODE = 112;
const SHA_256_CODE = 18;
const encodeCID = (version, code, multihash) => {
  const codeOffset = encodingLength(version);
  const hashOffset = codeOffset + encodingLength(code);
  const bytes = new Uint8Array(hashOffset + multihash.byteLength);
  encodeTo(version, bytes, 0);
  encodeTo(code, bytes, codeOffset);
  bytes.set(multihash, hashOffset);
  return bytes;
};
const cidSymbol = Symbol.for('@ipld/js-cid/CID');
const readonly = {
  writable: false,
  configurable: false,
  enumerable: true
};
const cid_hidden = {
  writable: false,
  enumerable: false,
  configurable: false
};
const version = '0.0.0-dev';
const deprecate = (range, message) => {
  if (range.test(version)) {
    console.warn(message);
  } else {
    throw new Error(message);
  }
};
const IS_CID_DEPRECATION = `CID.isCID(v) is deprecated and will be removed in the next major release.
Following code pattern:

if (CID.isCID(value)) {
  doSomethingWithCID(value)
}

Is replaced with:

const cid = CID.asCID(value)
if (cid) {
  // Make sure to use cid instead of value
  doSomethingWithCID(cid)
}
`;
;// CONCATENATED MODULE: ./node_modules/cborg/esm/lib/is.js
const typeofs = [
  'string',
  'number',
  'bigint',
  'symbol'
];
const objectTypeNames = [
  'Function',
  'Generator',
  'AsyncGenerator',
  'GeneratorFunction',
  'AsyncGeneratorFunction',
  'AsyncFunction',
  'Observable',
  'Array',
  'Buffer',
  'Object',
  'RegExp',
  'Date',
  'Error',
  'Map',
  'Set',
  'WeakMap',
  'WeakSet',
  'ArrayBuffer',
  'SharedArrayBuffer',
  'DataView',
  'Promise',
  'URL',
  'HTMLElement',
  'Int8Array',
  'Uint8Array',
  'Uint8ClampedArray',
  'Int16Array',
  'Uint16Array',
  'Int32Array',
  'Uint32Array',
  'Float32Array',
  'Float64Array',
  'BigInt64Array',
  'BigUint64Array'
];
function is(value) {
  if (value === null) {
    return 'null';
  }
  if (value === undefined) {
    return 'undefined';
  }
  if (value === true || value === false) {
    return 'boolean';
  }
  const typeOf = typeof value;
  if (typeofs.includes(typeOf)) {
    return typeOf;
  }
  if (typeOf === 'function') {
    return 'Function';
  }
  if (Array.isArray(value)) {
    return 'Array';
  }
  if (isBuffer(value)) {
    return 'Buffer';
  }
  const objectType = getObjectType(value);
  if (objectType) {
    return objectType;
  }
  return 'Object';
}
function isBuffer(value) {
  return value && value.constructor && value.constructor.isBuffer && value.constructor.isBuffer.call(null, value);
}
function getObjectType(value) {
  const objectTypeName = Object.prototype.toString.call(value).slice(8, -1);
  if (objectTypeNames.includes(objectTypeName)) {
    return objectTypeName;
  }
  return undefined;
}
;// CONCATENATED MODULE: ./node_modules/cborg/esm/lib/token.js
class Type {
  constructor(major, name, terminal) {
    this.major = major;
    this.majorEncoded = major << 5;
    this.name = name;
    this.terminal = terminal;
  }
  toString() {
    return `Type[${ this.major }].${ this.name }`;
  }
  compare(typ) {
    return this.major < typ.major ? -1 : this.major > typ.major ? 1 : 0;
  }
}
Type.uint = new Type(0, 'uint', true);
Type.negint = new Type(1, 'negint', true);
Type.bytes = new Type(2, 'bytes', true);
Type.string = new Type(3, 'string', true);
Type.array = new Type(4, 'array', false);
Type.map = new Type(5, 'map', false);
Type.tag = new Type(6, 'tag', false);
Type.float = new Type(7, 'float', true);
Type.false = new Type(7, 'false', true);
Type.true = new Type(7, 'true', true);
Type.null = new Type(7, 'null', true);
Type.undefined = new Type(7, 'undefined', true);
Type.break = new Type(7, 'break', true);
class Token {
  constructor(type, value, encodedLength) {
    this.type = type;
    this.value = value;
    this.encodedLength = encodedLength;
    this.encodedBytes = undefined;
    this.byteValue = undefined;
  }
  toString() {
    return `Token[${ this.type }].${ this.value }`;
  }
}

;// CONCATENATED MODULE: ./node_modules/cborg/esm/lib/byte-utils.js
const useBuffer = globalThis.process && !globalThis.process.browser && globalThis.Buffer && typeof globalThis.Buffer.isBuffer === 'function';
const textDecoder = new TextDecoder();
const textEncoder = new TextEncoder();
function byte_utils_isBuffer(buf) {
  return useBuffer && globalThis.Buffer.isBuffer(buf);
}
function asU8A(buf) {
  if (!(buf instanceof Uint8Array)) {
    return Uint8Array.from(buf);
  }
  return byte_utils_isBuffer(buf) ? new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength) : buf;
}
const byte_utils_toString = useBuffer ? (bytes, start, end) => {
  return end - start > 64 ? globalThis.Buffer.from(bytes.subarray(start, end)).toString('utf8') : utf8Slice(bytes, start, end);
} : (bytes, start, end) => {
  return end - start > 64 ? textDecoder.decode(bytes.subarray(start, end)) : utf8Slice(bytes, start, end);
};
const byte_utils_fromString = useBuffer ? string => {
  return string.length > 64 ? globalThis.Buffer.from(string) : utf8ToBytes(string);
} : string => {
  return string.length > 64 ? textEncoder.encode(string) : utf8ToBytes(string);
};
const fromArray = arr => {
  return Uint8Array.from(arr);
};
const slice = useBuffer ? (bytes, start, end) => {
  if (byte_utils_isBuffer(bytes)) {
    return new Uint8Array(bytes.subarray(start, end));
  }
  return bytes.slice(start, end);
} : (bytes, start, end) => {
  return bytes.slice(start, end);
};
const byte_utils_concat = useBuffer ? (chunks, length) => {
  chunks = chunks.map(c => c instanceof Uint8Array ? c : globalThis.Buffer.from(c));
  return asU8A(globalThis.Buffer.concat(chunks, length));
} : (chunks, length) => {
  const out = new Uint8Array(length);
  let off = 0;
  for (let b of chunks) {
    if (off + b.length > out.length) {
      b = b.subarray(0, out.length - off);
    }
    out.set(b, off);
    off += b.length;
  }
  return out;
};
const alloc = useBuffer ? size => {
  return globalThis.Buffer.allocUnsafe(size);
} : size => {
  return new Uint8Array(size);
};
const byte_utils_toHex = (/* unused pure expression or super */ null && (useBuffer ? d => {
  if (typeof d === 'string') {
    return d;
  }
  return globalThis.Buffer.from(toBytes(d)).toString('hex');
} : d => {
  if (typeof d === 'string') {
    return d;
  }
  return Array.prototype.reduce.call(toBytes(d), (p, c) => `${ p }${ c.toString(16).padStart(2, '0') }`, '');
}));
const byte_utils_fromHex = (/* unused pure expression or super */ null && (useBuffer ? hex => {
  if (hex instanceof Uint8Array) {
    return hex;
  }
  return globalThis.Buffer.from(hex, 'hex');
} : hex => {
  if (hex instanceof Uint8Array) {
    return hex;
  }
  if (!hex.length) {
    return new Uint8Array(0);
  }
  return new Uint8Array(hex.split('').map((c, i, d) => i % 2 === 0 ? `0x${ c }${ d[i + 1] }` : '').filter(Boolean).map(e => parseInt(e, 16)));
}));
function toBytes(obj) {
  if (obj instanceof Uint8Array && obj.constructor.name === 'Uint8Array') {
    return obj;
  }
  if (obj instanceof ArrayBuffer) {
    return new Uint8Array(obj);
  }
  if (ArrayBuffer.isView(obj)) {
    return new Uint8Array(obj.buffer, obj.byteOffset, obj.byteLength);
  }
  throw new Error('Unknown type, must be binary type');
}
function compare(b1, b2) {
  if (byte_utils_isBuffer(b1) && byte_utils_isBuffer(b2)) {
    return b1.compare(b2);
  }
  for (let i = 0; i < b1.length; i++) {
    if (b1[i] === b2[i]) {
      continue;
    }
    return b1[i] < b2[i] ? -1 : 1;
  }
  return 0;
}
function utf8ToBytes(string, units = Infinity) {
  let codePoint;
  const length = string.length;
  let leadSurrogate = null;
  const bytes = [];
  for (let i = 0; i < length; ++i) {
    codePoint = string.charCodeAt(i);
    if (codePoint > 55295 && codePoint < 57344) {
      if (!leadSurrogate) {
        if (codePoint > 56319) {
          if ((units -= 3) > -1)
            bytes.push(239, 191, 189);
          continue;
        } else if (i + 1 === length) {
          if ((units -= 3) > -1)
            bytes.push(239, 191, 189);
          continue;
        }
        leadSurrogate = codePoint;
        continue;
      }
      if (codePoint < 56320) {
        if ((units -= 3) > -1)
          bytes.push(239, 191, 189);
        leadSurrogate = codePoint;
        continue;
      }
      codePoint = (leadSurrogate - 55296 << 10 | codePoint - 56320) + 65536;
    } else if (leadSurrogate) {
      if ((units -= 3) > -1)
        bytes.push(239, 191, 189);
    }
    leadSurrogate = null;
    if (codePoint < 128) {
      if ((units -= 1) < 0)
        break;
      bytes.push(codePoint);
    } else if (codePoint < 2048) {
      if ((units -= 2) < 0)
        break;
      bytes.push(codePoint >> 6 | 192, codePoint & 63 | 128);
    } else if (codePoint < 65536) {
      if ((units -= 3) < 0)
        break;
      bytes.push(codePoint >> 12 | 224, codePoint >> 6 & 63 | 128, codePoint & 63 | 128);
    } else if (codePoint < 1114112) {
      if ((units -= 4) < 0)
        break;
      bytes.push(codePoint >> 18 | 240, codePoint >> 12 & 63 | 128, codePoint >> 6 & 63 | 128, codePoint & 63 | 128);
    } else {
      throw new Error('Invalid code point');
    }
  }
  return bytes;
}
function utf8Slice(buf, offset, end) {
  const res = [];
  while (offset < end) {
    const firstByte = buf[offset];
    let codePoint = null;
    let bytesPerSequence = firstByte > 239 ? 4 : firstByte > 223 ? 3 : firstByte > 191 ? 2 : 1;
    if (offset + bytesPerSequence <= end) {
      let secondByte, thirdByte, fourthByte, tempCodePoint;
      switch (bytesPerSequence) {
      case 1:
        if (firstByte < 128) {
          codePoint = firstByte;
        }
        break;
      case 2:
        secondByte = buf[offset + 1];
        if ((secondByte & 192) === 128) {
          tempCodePoint = (firstByte & 31) << 6 | secondByte & 63;
          if (tempCodePoint > 127) {
            codePoint = tempCodePoint;
          }
        }
        break;
      case 3:
        secondByte = buf[offset + 1];
        thirdByte = buf[offset + 2];
        if ((secondByte & 192) === 128 && (thirdByte & 192) === 128) {
          tempCodePoint = (firstByte & 15) << 12 | (secondByte & 63) << 6 | thirdByte & 63;
          if (tempCodePoint > 2047 && (tempCodePoint < 55296 || tempCodePoint > 57343)) {
            codePoint = tempCodePoint;
          }
        }
        break;
      case 4:
        secondByte = buf[offset + 1];
        thirdByte = buf[offset + 2];
        fourthByte = buf[offset + 3];
        if ((secondByte & 192) === 128 && (thirdByte & 192) === 128 && (fourthByte & 192) === 128) {
          tempCodePoint = (firstByte & 15) << 18 | (secondByte & 63) << 12 | (thirdByte & 63) << 6 | fourthByte & 63;
          if (tempCodePoint > 65535 && tempCodePoint < 1114112) {
            codePoint = tempCodePoint;
          }
        }
      }
    }
    if (codePoint === null) {
      codePoint = 65533;
      bytesPerSequence = 1;
    } else if (codePoint > 65535) {
      codePoint -= 65536;
      res.push(codePoint >>> 10 & 1023 | 55296);
      codePoint = 56320 | codePoint & 1023;
    }
    res.push(codePoint);
    offset += bytesPerSequence;
  }
  return decodeCodePointsArray(res);
}
const MAX_ARGUMENTS_LENGTH = 4096;
function decodeCodePointsArray(codePoints) {
  const len = codePoints.length;
  if (len <= MAX_ARGUMENTS_LENGTH) {
    return String.fromCharCode.apply(String, codePoints);
  }
  let res = '';
  let i = 0;
  while (i < len) {
    res += String.fromCharCode.apply(String, codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH));
  }
  return res;
}
;// CONCATENATED MODULE: ./node_modules/cborg/esm/lib/bl.js

const defaultChunkSize = 256;
class Bl {
  constructor(chunkSize = defaultChunkSize) {
    this.chunkSize = chunkSize;
    this.cursor = 0;
    this.maxCursor = -1;
    this.chunks = [];
    this._initReuseChunk = null;
  }
  reset() {
    this.cursor = 0;
    this.maxCursor = -1;
    if (this.chunks.length) {
      this.chunks = [];
    }
    if (this._initReuseChunk !== null) {
      this.chunks.push(this._initReuseChunk);
      this.maxCursor = this._initReuseChunk.length - 1;
    }
  }
  push(bytes) {
    let topChunk = this.chunks[this.chunks.length - 1];
    const newMax = this.cursor + bytes.length;
    if (newMax <= this.maxCursor + 1) {
      const chunkPos = topChunk.length - (this.maxCursor - this.cursor) - 1;
      topChunk.set(bytes, chunkPos);
    } else {
      if (topChunk) {
        const chunkPos = topChunk.length - (this.maxCursor - this.cursor) - 1;
        if (chunkPos < topChunk.length) {
          this.chunks[this.chunks.length - 1] = topChunk.subarray(0, chunkPos);
          this.maxCursor = this.cursor - 1;
        }
      }
      if (bytes.length < 64 && bytes.length < this.chunkSize) {
        topChunk = alloc(this.chunkSize);
        this.chunks.push(topChunk);
        this.maxCursor += topChunk.length;
        if (this._initReuseChunk === null) {
          this._initReuseChunk = topChunk;
        }
        topChunk.set(bytes, 0);
      } else {
        this.chunks.push(bytes);
        this.maxCursor += bytes.length;
      }
    }
    this.cursor += bytes.length;
  }
  toBytes(reset = false) {
    let byts;
    if (this.chunks.length === 1) {
      const chunk = this.chunks[0];
      if (reset && this.cursor > chunk.length / 2) {
        byts = this.cursor === chunk.length ? chunk : chunk.subarray(0, this.cursor);
        this._initReuseChunk = null;
        this.chunks = [];
      } else {
        byts = slice(chunk, 0, this.cursor);
      }
    } else {
      byts = byte_utils_concat(this.chunks, this.cursor);
    }
    if (reset) {
      this.reset();
    }
    return byts;
  }
}
;// CONCATENATED MODULE: ./node_modules/cborg/esm/lib/common.js
const decodeErrPrefix = 'CBOR decode error:';
const encodeErrPrefix = 'CBOR encode error:';
const uintMinorPrefixBytes = [];
uintMinorPrefixBytes[23] = 1;
uintMinorPrefixBytes[24] = 2;
uintMinorPrefixBytes[25] = 3;
uintMinorPrefixBytes[26] = 5;
uintMinorPrefixBytes[27] = 9;
function assertEnoughData(data, pos, need) {
  if (data.length - pos < need) {
    throw new Error(`${ decodeErrPrefix } not enough data for type`);
  }
}

;// CONCATENATED MODULE: ./node_modules/cborg/esm/lib/0uint.js


const uintBoundaries = [
  24,
  256,
  65536,
  4294967296,
  BigInt('18446744073709551616')
];
function readUint8(data, offset, options) {
  assertEnoughData(data, offset, 1);
  const value = data[offset];
  if (options.strict === true && value < uintBoundaries[0]) {
    throw new Error(`${ decodeErrPrefix } integer encoded in more bytes than necessary (strict decode)`);
  }
  return value;
}
function readUint16(data, offset, options) {
  assertEnoughData(data, offset, 2);
  const value = data[offset] << 8 | data[offset + 1];
  if (options.strict === true && value < uintBoundaries[1]) {
    throw new Error(`${ decodeErrPrefix } integer encoded in more bytes than necessary (strict decode)`);
  }
  return value;
}
function readUint32(data, offset, options) {
  assertEnoughData(data, offset, 4);
  const value = data[offset] * 16777216 + (data[offset + 1] << 16) + (data[offset + 2] << 8) + data[offset + 3];
  if (options.strict === true && value < uintBoundaries[2]) {
    throw new Error(`${ decodeErrPrefix } integer encoded in more bytes than necessary (strict decode)`);
  }
  return value;
}
function readUint64(data, offset, options) {
  assertEnoughData(data, offset, 8);
  const hi = data[offset] * 16777216 + (data[offset + 1] << 16) + (data[offset + 2] << 8) + data[offset + 3];
  const lo = data[offset + 4] * 16777216 + (data[offset + 5] << 16) + (data[offset + 6] << 8) + data[offset + 7];
  const value = (BigInt(hi) << BigInt(32)) + BigInt(lo);
  if (options.strict === true && value < uintBoundaries[3]) {
    throw new Error(`${ decodeErrPrefix } integer encoded in more bytes than necessary (strict decode)`);
  }
  if (value <= Number.MAX_SAFE_INTEGER) {
    return Number(value);
  }
  if (options.allowBigInt === true) {
    return value;
  }
  throw new Error(`${ decodeErrPrefix } integers outside of the safe integer range are not supported`);
}
function decodeUint8(data, pos, _minor, options) {
  return new Token(Type.uint, readUint8(data, pos + 1, options), 2);
}
function decodeUint16(data, pos, _minor, options) {
  return new Token(Type.uint, readUint16(data, pos + 1, options), 3);
}
function decodeUint32(data, pos, _minor, options) {
  return new Token(Type.uint, readUint32(data, pos + 1, options), 5);
}
function decodeUint64(data, pos, _minor, options) {
  return new Token(Type.uint, readUint64(data, pos + 1, options), 9);
}
function encodeUint(buf, token) {
  return encodeUintValue(buf, 0, token.value);
}
function encodeUintValue(buf, major, uint) {
  if (uint < uintBoundaries[0]) {
    const nuint = Number(uint);
    buf.push([major | nuint]);
  } else if (uint < uintBoundaries[1]) {
    const nuint = Number(uint);
    buf.push([
      major | 24,
      nuint
    ]);
  } else if (uint < uintBoundaries[2]) {
    const nuint = Number(uint);
    buf.push([
      major | 25,
      nuint >>> 8,
      nuint & 255
    ]);
  } else if (uint < uintBoundaries[3]) {
    const nuint = Number(uint);
    buf.push([
      major | 26,
      nuint >>> 24 & 255,
      nuint >>> 16 & 255,
      nuint >>> 8 & 255,
      nuint & 255
    ]);
  } else {
    const buint = BigInt(uint);
    if (buint < uintBoundaries[4]) {
      const set = [
        major | 27,
        0,
        0,
        0,
        0,
        0,
        0,
        0
      ];
      let lo = Number(buint & BigInt(4294967295));
      let hi = Number(buint >> BigInt(32) & BigInt(4294967295));
      set[8] = lo & 255;
      lo = lo >> 8;
      set[7] = lo & 255;
      lo = lo >> 8;
      set[6] = lo & 255;
      lo = lo >> 8;
      set[5] = lo & 255;
      set[4] = hi & 255;
      hi = hi >> 8;
      set[3] = hi & 255;
      hi = hi >> 8;
      set[2] = hi & 255;
      hi = hi >> 8;
      set[1] = hi & 255;
      buf.push(set);
    } else {
      throw new Error(`${ decodeErrPrefix } encountered BigInt larger than allowable range`);
    }
  }
}
encodeUint.encodedSize = function encodedSize(token) {
  return encodeUintValue.encodedSize(token.value);
};
encodeUintValue.encodedSize = function encodedSize(uint) {
  if (uint < uintBoundaries[0]) {
    return 1;
  }
  if (uint < uintBoundaries[1]) {
    return 2;
  }
  if (uint < uintBoundaries[2]) {
    return 3;
  }
  if (uint < uintBoundaries[3]) {
    return 5;
  }
  return 9;
};
encodeUint.compareTokens = function compareTokens(tok1, tok2) {
  return tok1.value < tok2.value ? -1 : tok1.value > tok2.value ? 1 : 0;
};
;// CONCATENATED MODULE: ./node_modules/cborg/esm/lib/1negint.js



function decodeNegint8(data, pos, _minor, options) {
  return new Token(Type.negint, -1 - readUint8(data, pos + 1, options), 2);
}
function decodeNegint16(data, pos, _minor, options) {
  return new Token(Type.negint, -1 - readUint16(data, pos + 1, options), 3);
}
function decodeNegint32(data, pos, _minor, options) {
  return new Token(Type.negint, -1 - readUint32(data, pos + 1, options), 5);
}
const neg1b = BigInt(-1);
const pos1b = BigInt(1);
function decodeNegint64(data, pos, _minor, options) {
  const int = readUint64(data, pos + 1, options);
  if (typeof int !== 'bigint') {
    const value = -1 - int;
    if (value >= Number.MIN_SAFE_INTEGER) {
      return new Token(Type.negint, value, 9);
    }
  }
  if (options.allowBigInt !== true) {
    throw new Error(`${ decodeErrPrefix } integers outside of the safe integer range are not supported`);
  }
  return new Token(Type.negint, neg1b - BigInt(int), 9);
}
function encodeNegint(buf, token) {
  const negint = token.value;
  const unsigned = typeof negint === 'bigint' ? negint * neg1b - pos1b : negint * -1 - 1;
  encodeUintValue(buf, token.type.majorEncoded, unsigned);
}
encodeNegint.encodedSize = function encodedSize(token) {
  const negint = token.value;
  const unsigned = typeof negint === 'bigint' ? negint * neg1b - pos1b : negint * -1 - 1;
  if (unsigned < uintBoundaries[0]) {
    return 1;
  }
  if (unsigned < uintBoundaries[1]) {
    return 2;
  }
  if (unsigned < uintBoundaries[2]) {
    return 3;
  }
  if (unsigned < uintBoundaries[3]) {
    return 5;
  }
  return 9;
};
encodeNegint.compareTokens = function compareTokens(tok1, tok2) {
  return tok1.value < tok2.value ? 1 : tok1.value > tok2.value ? -1 : 0;
};
;// CONCATENATED MODULE: ./node_modules/cborg/esm/lib/2bytes.js




function toToken(data, pos, prefix, length) {
  assertEnoughData(data, pos, prefix + length);
  const buf = slice(data, pos + prefix, pos + prefix + length);
  return new Token(Type.bytes, buf, prefix + length);
}
function decodeBytesCompact(data, pos, minor, _options) {
  return toToken(data, pos, 1, minor);
}
function decodeBytes8(data, pos, _minor, options) {
  return toToken(data, pos, 2, readUint8(data, pos + 1, options));
}
function decodeBytes16(data, pos, _minor, options) {
  return toToken(data, pos, 3, readUint16(data, pos + 1, options));
}
function decodeBytes32(data, pos, _minor, options) {
  return toToken(data, pos, 5, readUint32(data, pos + 1, options));
}
function decodeBytes64(data, pos, _minor, options) {
  const l = readUint64(data, pos + 1, options);
  if (typeof l === 'bigint') {
    throw new Error(`${ decodeErrPrefix } 64-bit integer bytes lengths not supported`);
  }
  return toToken(data, pos, 9, l);
}
function tokenBytes(token) {
  if (token.encodedBytes === undefined) {
    token.encodedBytes = token.type === Type.string ? byte_utils_fromString(token.value) : token.value;
  }
  return token.encodedBytes;
}
function encodeBytes(buf, token) {
  const bytes = tokenBytes(token);
  encodeUintValue(buf, token.type.majorEncoded, bytes.length);
  buf.push(bytes);
}
encodeBytes.encodedSize = function encodedSize(token) {
  const bytes = tokenBytes(token);
  return encodeUintValue.encodedSize(bytes.length) + bytes.length;
};
encodeBytes.compareTokens = function compareTokens(tok1, tok2) {
  return compareBytes(tokenBytes(tok1), tokenBytes(tok2));
};
function compareBytes(b1, b2) {
  return b1.length < b2.length ? -1 : b1.length > b2.length ? 1 : compare(b1, b2);
}
;// CONCATENATED MODULE: ./node_modules/cborg/esm/lib/3string.js





function _3string_toToken(data, pos, prefix, length, options) {
  const totLength = prefix + length;
  assertEnoughData(data, pos, totLength);
  const tok = new Token(Type.string, byte_utils_toString(data, pos + prefix, pos + totLength), totLength);
  if (options.retainStringBytes === true) {
    tok.byteValue = slice(data, pos + prefix, pos + totLength);
  }
  return tok;
}
function decodeStringCompact(data, pos, minor, options) {
  return _3string_toToken(data, pos, 1, minor, options);
}
function decodeString8(data, pos, _minor, options) {
  return _3string_toToken(data, pos, 2, readUint8(data, pos + 1, options), options);
}
function decodeString16(data, pos, _minor, options) {
  return _3string_toToken(data, pos, 3, readUint16(data, pos + 1, options), options);
}
function decodeString32(data, pos, _minor, options) {
  return _3string_toToken(data, pos, 5, readUint32(data, pos + 1, options), options);
}
function decodeString64(data, pos, _minor, options) {
  const l = readUint64(data, pos + 1, options);
  if (typeof l === 'bigint') {
    throw new Error(`${ decodeErrPrefix } 64-bit integer string lengths not supported`);
  }
  return _3string_toToken(data, pos, 9, l, options);
}
const encodeString = encodeBytes;
;// CONCATENATED MODULE: ./node_modules/cborg/esm/lib/4array.js



function _4array_toToken(_data, _pos, prefix, length) {
  return new Token(Type.array, length, prefix);
}
function decodeArrayCompact(data, pos, minor, _options) {
  return _4array_toToken(data, pos, 1, minor);
}
function decodeArray8(data, pos, _minor, options) {
  return _4array_toToken(data, pos, 2, readUint8(data, pos + 1, options));
}
function decodeArray16(data, pos, _minor, options) {
  return _4array_toToken(data, pos, 3, readUint16(data, pos + 1, options));
}
function decodeArray32(data, pos, _minor, options) {
  return _4array_toToken(data, pos, 5, readUint32(data, pos + 1, options));
}
function decodeArray64(data, pos, _minor, options) {
  const l = readUint64(data, pos + 1, options);
  if (typeof l === 'bigint') {
    throw new Error(`${ decodeErrPrefix } 64-bit integer array lengths not supported`);
  }
  return _4array_toToken(data, pos, 9, l);
}
function decodeArrayIndefinite(data, pos, _minor, options) {
  if (options.allowIndefinite === false) {
    throw new Error(`${ decodeErrPrefix } indefinite length items not allowed`);
  }
  return _4array_toToken(data, pos, 1, Infinity);
}
function encodeArray(buf, token) {
  encodeUintValue(buf, Type.array.majorEncoded, token.value);
}
encodeArray.compareTokens = encodeUint.compareTokens;
encodeArray.encodedSize = function encodedSize(token) {
  return encodeUintValue.encodedSize(token.value);
};
;// CONCATENATED MODULE: ./node_modules/cborg/esm/lib/5map.js



function _5map_toToken(_data, _pos, prefix, length) {
  return new Token(Type.map, length, prefix);
}
function decodeMapCompact(data, pos, minor, _options) {
  return _5map_toToken(data, pos, 1, minor);
}
function decodeMap8(data, pos, _minor, options) {
  return _5map_toToken(data, pos, 2, readUint8(data, pos + 1, options));
}
function decodeMap16(data, pos, _minor, options) {
  return _5map_toToken(data, pos, 3, readUint16(data, pos + 1, options));
}
function decodeMap32(data, pos, _minor, options) {
  return _5map_toToken(data, pos, 5, readUint32(data, pos + 1, options));
}
function decodeMap64(data, pos, _minor, options) {
  const l = readUint64(data, pos + 1, options);
  if (typeof l === 'bigint') {
    throw new Error(`${ decodeErrPrefix } 64-bit integer map lengths not supported`);
  }
  return _5map_toToken(data, pos, 9, l);
}
function decodeMapIndefinite(data, pos, _minor, options) {
  if (options.allowIndefinite === false) {
    throw new Error(`${ decodeErrPrefix } indefinite length items not allowed`);
  }
  return _5map_toToken(data, pos, 1, Infinity);
}
function encodeMap(buf, token) {
  encodeUintValue(buf, Type.map.majorEncoded, token.value);
}
encodeMap.compareTokens = encodeUint.compareTokens;
encodeMap.encodedSize = function encodedSize(token) {
  return encodeUintValue.encodedSize(token.value);
};
;// CONCATENATED MODULE: ./node_modules/cborg/esm/lib/6tag.js


function decodeTagCompact(_data, _pos, minor, _options) {
  return new Token(Type.tag, minor, 1);
}
function decodeTag8(data, pos, _minor, options) {
  return new Token(Type.tag, readUint8(data, pos + 1, options), 2);
}
function decodeTag16(data, pos, _minor, options) {
  return new Token(Type.tag, readUint16(data, pos + 1, options), 3);
}
function decodeTag32(data, pos, _minor, options) {
  return new Token(Type.tag, readUint32(data, pos + 1, options), 5);
}
function decodeTag64(data, pos, _minor, options) {
  return new Token(Type.tag, readUint64(data, pos + 1, options), 9);
}
function encodeTag(buf, token) {
  encodeUintValue(buf, Type.tag.majorEncoded, token.value);
}
encodeTag.compareTokens = encodeUint.compareTokens;
encodeTag.encodedSize = function encodedSize(token) {
  return encodeUintValue.encodedSize(token.value);
};
;// CONCATENATED MODULE: ./node_modules/cborg/esm/lib/7float.js



const MINOR_FALSE = 20;
const MINOR_TRUE = 21;
const MINOR_NULL = 22;
const MINOR_UNDEFINED = 23;
function decodeUndefined(_data, _pos, _minor, options) {
  if (options.allowUndefined === false) {
    throw new Error(`${ decodeErrPrefix } undefined values are not supported`);
  } else if (options.coerceUndefinedToNull === true) {
    return new Token(Type.null, null, 1);
  }
  return new Token(Type.undefined, undefined, 1);
}
function decodeBreak(_data, _pos, _minor, options) {
  if (options.allowIndefinite === false) {
    throw new Error(`${ decodeErrPrefix } indefinite length items not allowed`);
  }
  return new Token(Type.break, undefined, 1);
}
function createToken(value, bytes, options) {
  if (options) {
    if (options.allowNaN === false && Number.isNaN(value)) {
      throw new Error(`${ decodeErrPrefix } NaN values are not supported`);
    }
    if (options.allowInfinity === false && (value === Infinity || value === -Infinity)) {
      throw new Error(`${ decodeErrPrefix } Infinity values are not supported`);
    }
  }
  return new Token(Type.float, value, bytes);
}
function decodeFloat16(data, pos, _minor, options) {
  return createToken(readFloat16(data, pos + 1), 3, options);
}
function decodeFloat32(data, pos, _minor, options) {
  return createToken(readFloat32(data, pos + 1), 5, options);
}
function decodeFloat64(data, pos, _minor, options) {
  return createToken(readFloat64(data, pos + 1), 9, options);
}
function encodeFloat(buf, token, options) {
  const float = token.value;
  if (float === false) {
    buf.push([Type.float.majorEncoded | MINOR_FALSE]);
  } else if (float === true) {
    buf.push([Type.float.majorEncoded | MINOR_TRUE]);
  } else if (float === null) {
    buf.push([Type.float.majorEncoded | MINOR_NULL]);
  } else if (float === undefined) {
    buf.push([Type.float.majorEncoded | MINOR_UNDEFINED]);
  } else {
    let decoded;
    let success = false;
    if (!options || options.float64 !== true) {
      encodeFloat16(float);
      decoded = readFloat16(ui8a, 1);
      if (float === decoded || Number.isNaN(float)) {
        ui8a[0] = 249;
        buf.push(ui8a.slice(0, 3));
        success = true;
      } else {
        encodeFloat32(float);
        decoded = readFloat32(ui8a, 1);
        if (float === decoded) {
          ui8a[0] = 250;
          buf.push(ui8a.slice(0, 5));
          success = true;
        }
      }
    }
    if (!success) {
      encodeFloat64(float);
      decoded = readFloat64(ui8a, 1);
      ui8a[0] = 251;
      buf.push(ui8a.slice(0, 9));
    }
  }
}
encodeFloat.encodedSize = function encodedSize(token, options) {
  const float = token.value;
  if (float === false || float === true || float === null || float === undefined) {
    return 1;
  }
  if (!options || options.float64 !== true) {
    encodeFloat16(float);
    let decoded = readFloat16(ui8a, 1);
    if (float === decoded || Number.isNaN(float)) {
      return 3;
    }
    encodeFloat32(float);
    decoded = readFloat32(ui8a, 1);
    if (float === decoded) {
      return 5;
    }
  }
  return 9;
};
const _7float_buffer = new ArrayBuffer(9);
const dataView = new DataView(_7float_buffer, 1);
const ui8a = new Uint8Array(_7float_buffer, 0);
function encodeFloat16(inp) {
  if (inp === Infinity) {
    dataView.setUint16(0, 31744, false);
  } else if (inp === -Infinity) {
    dataView.setUint16(0, 64512, false);
  } else if (Number.isNaN(inp)) {
    dataView.setUint16(0, 32256, false);
  } else {
    dataView.setFloat32(0, inp);
    const valu32 = dataView.getUint32(0);
    const exponent = (valu32 & 2139095040) >> 23;
    const mantissa = valu32 & 8388607;
    if (exponent === 255) {
      dataView.setUint16(0, 31744, false);
    } else if (exponent === 0) {
      dataView.setUint16(0, (inp & 2147483648) >> 16 | mantissa >> 13, false);
    } else {
      const logicalExponent = exponent - 127;
      if (logicalExponent < -24) {
        dataView.setUint16(0, 0);
      } else if (logicalExponent < -14) {
        dataView.setUint16(0, (valu32 & 2147483648) >> 16 | 1 << 24 + logicalExponent, false);
      } else {
        dataView.setUint16(0, (valu32 & 2147483648) >> 16 | logicalExponent + 15 << 10 | mantissa >> 13, false);
      }
    }
  }
}
function readFloat16(ui8a, pos) {
  if (ui8a.length - pos < 2) {
    throw new Error(`${ decodeErrPrefix } not enough data for float16`);
  }
  const half = (ui8a[pos] << 8) + ui8a[pos + 1];
  if (half === 31744) {
    return Infinity;
  }
  if (half === 64512) {
    return -Infinity;
  }
  if (half === 32256) {
    return NaN;
  }
  const exp = half >> 10 & 31;
  const mant = half & 1023;
  let val;
  if (exp === 0) {
    val = mant * 2 ** -24;
  } else if (exp !== 31) {
    val = (mant + 1024) * 2 ** (exp - 25);
  } else {
    val = mant === 0 ? Infinity : NaN;
  }
  return half & 32768 ? -val : val;
}
function encodeFloat32(inp) {
  dataView.setFloat32(0, inp, false);
}
function readFloat32(ui8a, pos) {
  if (ui8a.length - pos < 4) {
    throw new Error(`${ decodeErrPrefix } not enough data for float32`);
  }
  const offset = (ui8a.byteOffset || 0) + pos;
  return new DataView(ui8a.buffer, offset, 4).getFloat32(0, false);
}
function encodeFloat64(inp) {
  dataView.setFloat64(0, inp, false);
}
function readFloat64(ui8a, pos) {
  if (ui8a.length - pos < 8) {
    throw new Error(`${ decodeErrPrefix } not enough data for float64`);
  }
  const offset = (ui8a.byteOffset || 0) + pos;
  return new DataView(ui8a.buffer, offset, 8).getFloat64(0, false);
}
encodeFloat.compareTokens = encodeUint.compareTokens;
;// CONCATENATED MODULE: ./node_modules/cborg/esm/lib/jump.js











function invalidMinor(data, pos, minor) {
  throw new Error(`${ decodeErrPrefix } encountered invalid minor (${ minor }) for major ${ data[pos] >>> 5 }`);
}
function errorer(msg) {
  return () => {
    throw new Error(`${ decodeErrPrefix } ${ msg }`);
  };
}
const jump = [];
for (let i = 0; i <= 23; i++) {
  jump[i] = invalidMinor;
}
jump[24] = decodeUint8;
jump[25] = decodeUint16;
jump[26] = decodeUint32;
jump[27] = decodeUint64;
jump[28] = invalidMinor;
jump[29] = invalidMinor;
jump[30] = invalidMinor;
jump[31] = invalidMinor;
for (let i = 32; i <= 55; i++) {
  jump[i] = invalidMinor;
}
jump[56] = decodeNegint8;
jump[57] = decodeNegint16;
jump[58] = decodeNegint32;
jump[59] = decodeNegint64;
jump[60] = invalidMinor;
jump[61] = invalidMinor;
jump[62] = invalidMinor;
jump[63] = invalidMinor;
for (let i = 64; i <= 87; i++) {
  jump[i] = decodeBytesCompact;
}
jump[88] = decodeBytes8;
jump[89] = decodeBytes16;
jump[90] = decodeBytes32;
jump[91] = decodeBytes64;
jump[92] = invalidMinor;
jump[93] = invalidMinor;
jump[94] = invalidMinor;
jump[95] = errorer('indefinite length bytes/strings are not supported');
for (let i = 96; i <= 119; i++) {
  jump[i] = decodeStringCompact;
}
jump[120] = decodeString8;
jump[121] = decodeString16;
jump[122] = decodeString32;
jump[123] = decodeString64;
jump[124] = invalidMinor;
jump[125] = invalidMinor;
jump[126] = invalidMinor;
jump[127] = errorer('indefinite length bytes/strings are not supported');
for (let i = 128; i <= 151; i++) {
  jump[i] = decodeArrayCompact;
}
jump[152] = decodeArray8;
jump[153] = decodeArray16;
jump[154] = decodeArray32;
jump[155] = decodeArray64;
jump[156] = invalidMinor;
jump[157] = invalidMinor;
jump[158] = invalidMinor;
jump[159] = decodeArrayIndefinite;
for (let i = 160; i <= 183; i++) {
  jump[i] = decodeMapCompact;
}
jump[184] = decodeMap8;
jump[185] = decodeMap16;
jump[186] = decodeMap32;
jump[187] = decodeMap64;
jump[188] = invalidMinor;
jump[189] = invalidMinor;
jump[190] = invalidMinor;
jump[191] = decodeMapIndefinite;
for (let i = 192; i <= 215; i++) {
  jump[i] = decodeTagCompact;
}
jump[216] = decodeTag8;
jump[217] = decodeTag16;
jump[218] = decodeTag32;
jump[219] = decodeTag64;
jump[220] = invalidMinor;
jump[221] = invalidMinor;
jump[222] = invalidMinor;
jump[223] = invalidMinor;
for (let i = 224; i <= 243; i++) {
  jump[i] = errorer('simple values are not supported');
}
jump[244] = invalidMinor;
jump[245] = invalidMinor;
jump[246] = invalidMinor;
jump[247] = decodeUndefined;
jump[248] = errorer('simple values are not supported');
jump[249] = decodeFloat16;
jump[250] = decodeFloat32;
jump[251] = decodeFloat64;
jump[252] = invalidMinor;
jump[253] = invalidMinor;
jump[254] = invalidMinor;
jump[255] = decodeBreak;
const quick = [];
for (let i = 0; i < 24; i++) {
  quick[i] = new Token(Type.uint, i, 1);
}
for (let i = -1; i >= -24; i--) {
  quick[31 - i] = new Token(Type.negint, i, 1);
}
quick[64] = new Token(Type.bytes, new Uint8Array(0), 1);
quick[96] = new Token(Type.string, '', 1);
quick[128] = new Token(Type.array, 0, 1);
quick[160] = new Token(Type.map, 0, 1);
quick[244] = new Token(Type.false, false, 1);
quick[245] = new Token(Type.true, true, 1);
quick[246] = new Token(Type.null, null, 1);
function quickEncodeToken(token) {
  switch (token.type) {
  case Type.false:
    return fromArray([244]);
  case Type.true:
    return fromArray([245]);
  case Type.null:
    return fromArray([246]);
  case Type.bytes:
    if (!token.value.length) {
      return fromArray([64]);
    }
    return;
  case Type.string:
    if (token.value === '') {
      return fromArray([96]);
    }
    return;
  case Type.array:
    if (token.value === 0) {
      return fromArray([128]);
    }
    return;
  case Type.map:
    if (token.value === 0) {
      return fromArray([160]);
    }
    return;
  case Type.uint:
    if (token.value < 24) {
      return fromArray([Number(token.value)]);
    }
    return;
  case Type.negint:
    if (token.value >= -24) {
      return fromArray([31 - Number(token.value)]);
    }
  }
}
;// CONCATENATED MODULE: ./node_modules/cborg/esm/lib/encode.js














const defaultEncodeOptions = {
  float64: false,
  mapSorter,
  quickEncodeToken: quickEncodeToken
};
function makeCborEncoders() {
  const encoders = [];
  encoders[Type.uint.major] = encodeUint;
  encoders[Type.negint.major] = encodeNegint;
  encoders[Type.bytes.major] = encodeBytes;
  encoders[Type.string.major] = encodeString;
  encoders[Type.array.major] = encodeArray;
  encoders[Type.map.major] = encodeMap;
  encoders[Type.tag.major] = encodeTag;
  encoders[Type.float.major] = encodeFloat;
  return encoders;
}
const cborEncoders = makeCborEncoders();
const buf = new Bl();
class Ref {
  constructor(obj, parent) {
    this.obj = obj;
    this.parent = parent;
  }
  includes(obj) {
    let p = this;
    do {
      if (p.obj === obj) {
        return true;
      }
    } while (p = p.parent);
    return false;
  }
  static createCheck(stack, obj) {
    if (stack && stack.includes(obj)) {
      throw new Error(`${ encodeErrPrefix } object contains circular references`);
    }
    return new Ref(obj, stack);
  }
}
const simpleTokens = {
  null: new Token(Type.null, null),
  undefined: new Token(Type.undefined, undefined),
  true: new Token(Type.true, true),
  false: new Token(Type.false, false),
  emptyArray: new Token(Type.array, 0),
  emptyMap: new Token(Type.map, 0)
};
const typeEncoders = {
  number(obj, _typ, _options, _refStack) {
    if (!Number.isInteger(obj) || !Number.isSafeInteger(obj)) {
      return new Token(Type.float, obj);
    } else if (obj >= 0) {
      return new Token(Type.uint, obj);
    } else {
      return new Token(Type.negint, obj);
    }
  },
  bigint(obj, _typ, _options, _refStack) {
    if (obj >= BigInt(0)) {
      return new Token(Type.uint, obj);
    } else {
      return new Token(Type.negint, obj);
    }
  },
  Uint8Array(obj, _typ, _options, _refStack) {
    return new Token(Type.bytes, obj);
  },
  string(obj, _typ, _options, _refStack) {
    return new Token(Type.string, obj);
  },
  boolean(obj, _typ, _options, _refStack) {
    return obj ? simpleTokens.true : simpleTokens.false;
  },
  null(_obj, _typ, _options, _refStack) {
    return simpleTokens.null;
  },
  undefined(_obj, _typ, _options, _refStack) {
    return simpleTokens.undefined;
  },
  ArrayBuffer(obj, _typ, _options, _refStack) {
    return new Token(Type.bytes, new Uint8Array(obj));
  },
  DataView(obj, _typ, _options, _refStack) {
    return new Token(Type.bytes, new Uint8Array(obj.buffer, obj.byteOffset, obj.byteLength));
  },
  Array(obj, _typ, options, refStack) {
    if (!obj.length) {
      if (options.addBreakTokens === true) {
        return [
          simpleTokens.emptyArray,
          new Token(Type.break)
        ];
      }
      return simpleTokens.emptyArray;
    }
    refStack = Ref.createCheck(refStack, obj);
    const entries = [];
    let i = 0;
    for (const e of obj) {
      entries[i++] = objectToTokens(e, options, refStack);
    }
    if (options.addBreakTokens) {
      return [
        new Token(Type.array, obj.length),
        entries,
        new Token(Type.break)
      ];
    }
    return [
      new Token(Type.array, obj.length),
      entries
    ];
  },
  Object(obj, typ, options, refStack) {
    const isMap = typ !== 'Object';
    const keys = isMap ? obj.keys() : Object.keys(obj);
    const length = isMap ? obj.size : keys.length;
    if (!length) {
      if (options.addBreakTokens === true) {
        return [
          simpleTokens.emptyMap,
          new Token(Type.break)
        ];
      }
      return simpleTokens.emptyMap;
    }
    refStack = Ref.createCheck(refStack, obj);
    const entries = [];
    let i = 0;
    for (const key of keys) {
      entries[i++] = [
        objectToTokens(key, options, refStack),
        objectToTokens(isMap ? obj.get(key) : obj[key], options, refStack)
      ];
    }
    sortMapEntries(entries, options);
    if (options.addBreakTokens) {
      return [
        new Token(Type.map, length),
        entries,
        new Token(Type.break)
      ];
    }
    return [
      new Token(Type.map, length),
      entries
    ];
  }
};
typeEncoders.Map = typeEncoders.Object;
typeEncoders.Buffer = typeEncoders.Uint8Array;
for (const typ of 'Uint8Clamped Uint16 Uint32 Int8 Int16 Int32 BigUint64 BigInt64 Float32 Float64'.split(' ')) {
  typeEncoders[`${ typ }Array`] = typeEncoders.DataView;
}
function objectToTokens(obj, options = {}, refStack) {
  const typ = is(obj);
  const customTypeEncoder = options && options.typeEncoders && options.typeEncoders[typ] || typeEncoders[typ];
  if (typeof customTypeEncoder === 'function') {
    const tokens = customTypeEncoder(obj, typ, options, refStack);
    if (tokens != null) {
      return tokens;
    }
  }
  const typeEncoder = typeEncoders[typ];
  if (!typeEncoder) {
    throw new Error(`${ encodeErrPrefix } unsupported type: ${ typ }`);
  }
  return typeEncoder(obj, typ, options, refStack);
}
function sortMapEntries(entries, options) {
  if (options.mapSorter) {
    entries.sort(options.mapSorter);
  }
}
function mapSorter(e1, e2) {
  const keyToken1 = Array.isArray(e1[0]) ? e1[0][0] : e1[0];
  const keyToken2 = Array.isArray(e2[0]) ? e2[0][0] : e2[0];
  if (keyToken1.type !== keyToken2.type) {
    return keyToken1.type.compare(keyToken2.type);
  }
  const major = keyToken1.type.major;
  const tcmp = cborEncoders[major].compareTokens(keyToken1, keyToken2);
  if (tcmp === 0) {
    console.warn('WARNING: complex key types used, CBOR key sorting guarantees are gone');
  }
  return tcmp;
}
function tokensToEncoded(buf, tokens, encoders, options) {
  if (Array.isArray(tokens)) {
    for (const token of tokens) {
      tokensToEncoded(buf, token, encoders, options);
    }
  } else {
    encoders[tokens.type.major](buf, tokens, options);
  }
}
function encodeCustom(data, encoders, options) {
  const tokens = objectToTokens(data, options);
  if (!Array.isArray(tokens) && options.quickEncodeToken) {
    const quickBytes = options.quickEncodeToken(tokens);
    if (quickBytes) {
      return quickBytes;
    }
    const encoder = encoders[tokens.type.major];
    if (encoder.encodedSize) {
      const size = encoder.encodedSize(tokens, options);
      const buf = new Bl(size);
      encoder(buf, tokens, options);
      if (buf.chunks.length !== 1) {
        throw new Error(`Unexpected error: pre-calculated length for ${ tokens } was wrong`);
      }
      return asU8A(buf.chunks[0]);
    }
  }
  buf.reset();
  tokensToEncoded(buf, tokens, encoders, options);
  return buf.toBytes(true);
}
function encode_encode(data, options) {
  options = Object.assign({}, defaultEncodeOptions, options);
  return encodeCustom(data, cborEncoders, options);
}

;// CONCATENATED MODULE: ./node_modules/cborg/esm/lib/decode.js



const defaultDecodeOptions = {
  strict: false,
  allowIndefinite: true,
  allowUndefined: true,
  allowBigInt: true
};
class Tokeniser {
  constructor(data, options = {}) {
    this.pos = 0;
    this.data = data;
    this.options = options;
  }
  done() {
    return this.pos >= this.data.length;
  }
  next() {
    const byt = this.data[this.pos];
    let token = quick[byt];
    if (token === undefined) {
      const decoder = jump[byt];
      if (!decoder) {
        throw new Error(`${ decodeErrPrefix } no decoder for major type ${ byt >>> 5 } (byte 0x${ byt.toString(16).padStart(2, '0') })`);
      }
      const minor = byt & 31;
      token = decoder(this.data, this.pos, minor, this.options);
    }
    this.pos += token.encodedLength;
    return token;
  }
}
const DONE = Symbol.for('DONE');
const BREAK = Symbol.for('BREAK');
function tokenToArray(token, tokeniser, options) {
  const arr = [];
  for (let i = 0; i < token.value; i++) {
    const value = tokensToObject(tokeniser, options);
    if (value === BREAK) {
      if (token.value === Infinity) {
        break;
      }
      throw new Error(`${ decodeErrPrefix } got unexpected break to lengthed array`);
    }
    if (value === DONE) {
      throw new Error(`${ decodeErrPrefix } found array but not enough entries (got ${ i }, expected ${ token.value })`);
    }
    arr[i] = value;
  }
  return arr;
}
function tokenToMap(token, tokeniser, options) {
  const useMaps = options.useMaps === true;
  const obj = useMaps ? undefined : {};
  const m = useMaps ? new Map() : undefined;
  for (let i = 0; i < token.value; i++) {
    const key = tokensToObject(tokeniser, options);
    if (key === BREAK) {
      if (token.value === Infinity) {
        break;
      }
      throw new Error(`${ decodeErrPrefix } got unexpected break to lengthed map`);
    }
    if (key === DONE) {
      throw new Error(`${ decodeErrPrefix } found map but not enough entries (got ${ i } [no key], expected ${ token.value })`);
    }
    if (useMaps !== true && typeof key !== 'string') {
      throw new Error(`${ decodeErrPrefix } non-string keys not supported (got ${ typeof key })`);
    }
    if (options.rejectDuplicateMapKeys === true) {
      if (useMaps && m.has(key) || !useMaps && key in obj) {
        throw new Error(`${ decodeErrPrefix } found repeat map key "${ key }"`);
      }
    }
    const value = tokensToObject(tokeniser, options);
    if (value === DONE) {
      throw new Error(`${ decodeErrPrefix } found map but not enough entries (got ${ i } [no value], expected ${ token.value })`);
    }
    if (useMaps) {
      m.set(key, value);
    } else {
      obj[key] = value;
    }
  }
  return useMaps ? m : obj;
}
function tokensToObject(tokeniser, options) {
  if (tokeniser.done()) {
    return DONE;
  }
  const token = tokeniser.next();
  if (token.type === Type.break) {
    return BREAK;
  }
  if (token.type.terminal) {
    return token.value;
  }
  if (token.type === Type.array) {
    return tokenToArray(token, tokeniser, options);
  }
  if (token.type === Type.map) {
    return tokenToMap(token, tokeniser, options);
  }
  if (token.type === Type.tag) {
    if (options.tags && typeof options.tags[token.value] === 'function') {
      const tagged = tokensToObject(tokeniser, options);
      return options.tags[token.value](tagged);
    }
    throw new Error(`${ decodeErrPrefix } tag not supported (${ token.value })`);
  }
  throw new Error('unsupported');
}
function decode_decode(data, options) {
  if (!(data instanceof Uint8Array)) {
    throw new Error(`${ decodeErrPrefix } data to decode must be a Uint8Array`);
  }
  options = Object.assign({}, defaultDecodeOptions, options);
  const tokeniser = options.tokenizer || new Tokeniser(data, options);
  const decoded = tokensToObject(tokeniser, options);
  if (decoded === DONE) {
    throw new Error(`${ decodeErrPrefix } did not find any content to decode`);
  }
  if (decoded === BREAK) {
    throw new Error(`${ decodeErrPrefix } got unexpected break`);
  }
  if (!tokeniser.done()) {
    throw new Error(`${ decodeErrPrefix } too many terminals, data makes no sense`);
  }
  return decoded;
}

;// CONCATENATED MODULE: ./node_modules/cborg/esm/cborg.js




;// CONCATENATED MODULE: ./node_modules/@ipld/car/node_modules/@ipld/dag-cbor/esm/index.js


const CID_CBOR_TAG = 42;
function cidEncoder(obj) {
  if (obj.asCID !== obj) {
    return null;
  }
  const cid = cid_CID.asCID(obj);
  if (!cid) {
    return null;
  }
  const bytes = new Uint8Array(cid.bytes.byteLength + 1);
  bytes.set(cid.bytes, 1);
  return [
    new Token(Type.tag, CID_CBOR_TAG),
    new Token(Type.bytes, bytes)
  ];
}
function undefinedEncoder() {
  throw new Error('`undefined` is not supported by the IPLD Data Model and cannot be encoded');
}
function numberEncoder(num) {
  if (Number.isNaN(num)) {
    throw new Error('`NaN` is not supported by the IPLD Data Model and cannot be encoded');
  }
  if (num === Infinity || num === -Infinity) {
    throw new Error('`Infinity` and `-Infinity` is not supported by the IPLD Data Model and cannot be encoded');
  }
  return null;
}
const encodeOptions = {
  float64: true,
  typeEncoders: {
    Object: cidEncoder,
    undefined: undefinedEncoder,
    number: numberEncoder
  }
};
function cidDecoder(bytes) {
  if (bytes[0] !== 0) {
    throw new Error('Invalid CID for CBOR tag 42; expected leading 0x00');
  }
  return cid_CID.decode(bytes.subarray(1));
}
const decodeOptions = {
  allowIndefinite: false,
  coerceUndefinedToNull: true,
  allowNaN: false,
  allowInfinity: false,
  allowBigInt: true,
  strict: true,
  useMaps: false,
  tags: []
};
decodeOptions.tags[CID_CBOR_TAG] = cidDecoder;
const esm_name = 'dag-cbor';
const code = 113;
const esm_encode = node => encode_encode(node, encodeOptions);
const esm_decode = data => decode_decode(data, decodeOptions);
;// CONCATENATED MODULE: ./node_modules/@ipld/car/esm/lib/decoder.js




const CIDV0_BYTES = {
  SHA2_256: 18,
  LENGTH: 32,
  DAG_PB: 112
};
async function readVarint(reader) {
  const bytes = await reader.upTo(8);
  const i = varint.decode(bytes);
  reader.seek(varint.decode.bytes);
  return i;
}
async function readHeader(reader) {
  const length = await readVarint(reader);
  if (length === 0) {
    throw new Error('Invalid CAR header (zero length)');
  }
  const header = await reader.exactly(length);
  reader.seek(length);
  const block = esm_decode(header);
  if (block == null || Array.isArray(block) || typeof block !== 'object') {
    throw new Error('Invalid CAR header format');
  }
  if (block.version !== 1) {
    if (typeof block.version === 'string') {
      throw new Error(`Invalid CAR version: "${ block.version }"`);
    }
    throw new Error(`Invalid CAR version: ${ block.version }`);
  }
  if (!Array.isArray(block.roots)) {
    throw new Error('Invalid CAR header format');
  }
  if (Object.keys(block).filter(p => p !== 'roots' && p !== 'version').length) {
    throw new Error('Invalid CAR header format');
  }
  return block;
}
async function readMultihash(reader) {
  const bytes = await reader.upTo(8);
  varint.decode(bytes);
  const codeLength = varint.decode.bytes;
  const length = varint.decode(bytes.subarray(varint.decode.bytes));
  const lengthLength = varint.decode.bytes;
  const mhLength = codeLength + lengthLength + length;
  const multihash = await reader.exactly(mhLength);
  reader.seek(mhLength);
  return multihash;
}
async function readCid(reader) {
  const first = await reader.exactly(2);
  if (first[0] === CIDV0_BYTES.SHA2_256 && first[1] === CIDV0_BYTES.LENGTH) {
    const bytes = await reader.exactly(34);
    reader.seek(34);
    const multihash = digest_decode(bytes);
    return cid_CID.create(0, CIDV0_BYTES.DAG_PB, multihash);
  }
  const version = await readVarint(reader);
  if (version !== 1) {
    throw new Error(`Unexpected CID version (${ version })`);
  }
  const codec = await readVarint(reader);
  const bytes = await readMultihash(reader);
  const multihash = digest_decode(bytes);
  return cid_CID.create(version, codec, multihash);
}
async function readBlockHead(reader) {
  const start = reader.pos;
  let length = await readVarint(reader);
  if (length === 0) {
    throw new Error('Invalid CAR section (zero length)');
  }
  length += reader.pos - start;
  const cid = await readCid(reader);
  const blockLength = length - (reader.pos - start);
  return {
    cid,
    length,
    blockLength
  };
}
async function readBlock(reader) {
  const {cid, blockLength} = await readBlockHead(reader);
  const bytes = await reader.exactly(blockLength);
  reader.seek(blockLength);
  return {
    bytes,
    cid
  };
}
async function readBlockIndex(reader) {
  const offset = reader.pos;
  const {cid, length, blockLength} = await readBlockHead(reader);
  const index = {
    cid,
    length,
    blockLength,
    offset,
    blockOffset: reader.pos
  };
  reader.seek(index.blockLength);
  return index;
}
function createDecoder(reader) {
  const headerPromise = readHeader(reader);
  return {
    header: () => headerPromise,
    async *blocks() {
      await headerPromise;
      while ((await reader.upTo(8)).length > 0) {
        yield await readBlock(reader);
      }
    },
    async *blocksIndex() {
      await headerPromise;
      while ((await reader.upTo(8)).length > 0) {
        yield await readBlockIndex(reader);
      }
    }
  };
}
function bytesReader(bytes) {
  let pos = 0;
  return {
    async upTo(length) {
      return bytes.subarray(pos, pos + Math.min(length, bytes.length - pos));
    },
    async exactly(length) {
      if (length > bytes.length - pos) {
        throw new Error('Unexpected end of data');
      }
      return bytes.subarray(pos, pos + length);
    },
    seek(length) {
      pos += length;
    },
    get pos() {
      return pos;
    }
  };
}
function chunkReader(readChunk) {
  let pos = 0;
  let have = 0;
  let offset = 0;
  let currentChunk = new Uint8Array(0);
  const read = async length => {
    have = currentChunk.length - offset;
    const bufa = [currentChunk.subarray(offset)];
    while (have < length) {
      const chunk = await readChunk();
      if (chunk == null) {
        break;
      }
      if (have < 0) {
        if (chunk.length > have) {
          bufa.push(chunk.subarray(-have));
        }
      } else {
        bufa.push(chunk);
      }
      have += chunk.length;
    }
    currentChunk = new Uint8Array(bufa.reduce((p, c) => p + c.length, 0));
    let off = 0;
    for (const b of bufa) {
      currentChunk.set(b, off);
      off += b.length;
    }
    offset = 0;
  };
  return {
    async upTo(length) {
      if (currentChunk.length - offset < length) {
        await read(length);
      }
      return currentChunk.subarray(offset, offset + Math.min(currentChunk.length - offset, length));
    },
    async exactly(length) {
      if (currentChunk.length - offset < length) {
        await read(length);
      }
      if (currentChunk.length - offset < length) {
        throw new Error('Unexpected end of data');
      }
      return currentChunk.subarray(offset, offset + length);
    },
    seek(length) {
      pos += length;
      offset += length;
    },
    get pos() {
      return pos;
    }
  };
}
function asyncIterableReader(asyncIterable) {
  const iterator = asyncIterable[Symbol.asyncIterator]();
  async function readChunk() {
    const next = await iterator.next();
    if (next.done) {
      return null;
    }
    return next.value;
  }
  return chunkReader(readChunk);
}
;// CONCATENATED MODULE: ./node_modules/@ipld/car/esm/lib/reader-browser.js

class reader_browser_CarReader {
  constructor(version, roots, blocks) {
    this._version = version;
    this._roots = roots;
    this._blocks = blocks;
    this._keys = blocks.map(b => b.cid.toString());
  }
  get version() {
    return this._version;
  }
  async getRoots() {
    return this._roots;
  }
  async has(key) {
    return this._keys.indexOf(key.toString()) > -1;
  }
  async get(key) {
    const index = this._keys.indexOf(key.toString());
    return index > -1 ? this._blocks[index] : undefined;
  }
  async *blocks() {
    for (const block of this._blocks) {
      yield block;
    }
  }
  async *cids() {
    for (const block of this._blocks) {
      yield block.cid;
    }
  }
  static async fromBytes(bytes) {
    if (!(bytes instanceof Uint8Array)) {
      throw new TypeError('fromBytes() requires a Uint8Array');
    }
    return decodeReaderComplete(bytesReader(bytes));
  }
  static async fromIterable(asyncIterable) {
    if (!asyncIterable || !(typeof asyncIterable[Symbol.asyncIterator] === 'function')) {
      throw new TypeError('fromIterable() requires an async iterable');
    }
    return decodeReaderComplete(asyncIterableReader(asyncIterable));
  }
}
async function decodeReaderComplete(reader) {
  const decoder = createDecoder(reader);
  const {version, roots} = await decoder.header();
  const blocks = [];
  for await (const block of decoder.blocks()) {
    blocks.push(block);
  }
  return new reader_browser_CarReader(version, roots, blocks);
}
const __browser = true;
;// CONCATENATED MODULE: ./node_modules/@ipld/car/esm/lib/reader.js



const fsread = (0,external_util_.promisify)(external_fs_.read);
class CarReader extends reader_browser_CarReader {
  static async readRaw(fd, blockIndex) {
    const {cid, blockLength, blockOffset} = blockIndex;
    const bytes = new Uint8Array(blockLength);
    let read;
    if (typeof fd === 'number') {
      read = (await fsread(fd, bytes, 0, blockLength, blockOffset)).bytesRead;
    } else if (typeof fd === 'object' && typeof fd.read === 'function') {
      read = (await fd.read(bytes, 0, blockLength, blockOffset)).bytesRead;
    } else {
      throw new TypeError('Bad fd');
    }
    if (read !== blockLength) {
      throw new Error(`Failed to read entire block (${ read } instead of ${ blockLength })`);
    }
    return {
      cid,
      bytes
    };
  }
}
const reader_browser = false;
;// CONCATENATED MODULE: ./node_modules/@ipld/car/esm/lib/indexer.js

class indexer_CarIndexer {
  constructor(version, roots, iterator) {
    this._version = version;
    this._roots = roots;
    this._iterator = iterator;
  }
  get version() {
    return this._version;
  }
  async getRoots() {
    return this._roots;
  }
  [Symbol.asyncIterator]() {
    return this._iterator;
  }
  static async fromBytes(bytes) {
    if (!(bytes instanceof Uint8Array)) {
      throw new TypeError('fromBytes() requires a Uint8Array');
    }
    return decodeIndexerComplete(bytesReader(bytes));
  }
  static async fromIterable(asyncIterable) {
    if (!asyncIterable || !(typeof asyncIterable[Symbol.asyncIterator] === 'function')) {
      throw new TypeError('fromIterable() requires an async iterable');
    }
    return decodeIndexerComplete(asyncIterableReader(asyncIterable));
  }
}
async function decodeIndexerComplete(reader) {
  const decoder = createDecoder(reader);
  const {version, roots} = await decoder.header();
  return new indexer_CarIndexer(version, roots, decoder.blocksIndex());
}
;// CONCATENATED MODULE: ./node_modules/@ipld/car/esm/lib/iterator.js

class CarIteratorBase {
  constructor(version, roots, iterable) {
    this._version = version;
    this._roots = roots;
    this._iterable = iterable;
    this._decoded = false;
  }
  get version() {
    return this._version;
  }
  async getRoots() {
    return this._roots;
  }
}
class CarBlockIterator extends CarIteratorBase {
  [Symbol.asyncIterator]() {
    if (this._decoded) {
      throw new Error('Cannot decode more than once');
    }
    if (!this._iterable) {
      throw new Error('Block iterable not found');
    }
    this._decoded = true;
    return this._iterable[Symbol.asyncIterator]();
  }
  static async fromBytes(bytes) {
    const {version, roots, iterator} = await fromBytes(bytes);
    return new CarBlockIterator(version, roots, iterator);
  }
  static async fromIterable(asyncIterable) {
    const {version, roots, iterator} = await fromIterable(asyncIterable);
    return new CarBlockIterator(version, roots, iterator);
  }
}
class CarCIDIterator extends CarIteratorBase {
  [Symbol.asyncIterator]() {
    if (this._decoded) {
      throw new Error('Cannot decode more than once');
    }
    if (!this._iterable) {
      throw new Error('Block iterable not found');
    }
    this._decoded = true;
    const iterable = this._iterable[Symbol.asyncIterator]();
    return {
      async next() {
        const next = await iterable.next();
        if (next.done) {
          return next;
        }
        return {
          done: false,
          value: next.value.cid
        };
      }
    };
  }
  static async fromBytes(bytes) {
    const {version, roots, iterator} = await fromBytes(bytes);
    return new CarCIDIterator(version, roots, iterator);
  }
  static async fromIterable(asyncIterable) {
    const {version, roots, iterator} = await fromIterable(asyncIterable);
    return new CarCIDIterator(version, roots, iterator);
  }
}
async function fromBytes(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError('fromBytes() requires a Uint8Array');
  }
  return decodeIterator(bytesReader(bytes));
}
async function fromIterable(asyncIterable) {
  if (!asyncIterable || !(typeof asyncIterable[Symbol.asyncIterator] === 'function')) {
    throw new TypeError('fromIterable() requires an async iterable');
  }
  return decodeIterator(asyncIterableReader(asyncIterable));
}
async function decodeIterator(reader) {
  const decoder = createDecoder(reader);
  const {version, roots} = await decoder.header();
  return {
    version,
    roots,
    iterator: decoder.blocks()
  };
}
;// CONCATENATED MODULE: ./node_modules/@ipld/car/esm/lib/encoder.js


function createHeader(roots) {
  const headerBytes = esm_encode({
    version: 1,
    roots
  });
  const varintBytes = varint.encode(headerBytes.length);
  const header = new Uint8Array(varintBytes.length + headerBytes.length);
  header.set(varintBytes, 0);
  header.set(headerBytes, varintBytes.length);
  return header;
}
function createEncoder(writer) {
  return {
    async setRoots(roots) {
      const bytes = createHeader(roots);
      await writer.write(bytes);
    },
    async writeBlock(block) {
      const {cid, bytes} = block;
      await writer.write(new Uint8Array(varint.encode(cid.bytes.length + bytes.length)));
      await writer.write(cid.bytes);
      if (bytes.length) {
        await writer.write(bytes);
      }
    },
    async close() {
      return writer.end();
    }
  };
}

;// CONCATENATED MODULE: ./node_modules/@ipld/car/esm/lib/iterator-channel.js
function noop() {
}
function iterator_channel_create() {
  const chunkQueue = [];
  let drainer = null;
  let drainerResolver = noop;
  let ended = false;
  let outWait = null;
  let outWaitResolver = noop;
  const makeDrainer = () => {
    if (!drainer) {
      drainer = new Promise(resolve => {
        drainerResolver = () => {
          drainer = null;
          drainerResolver = noop;
          resolve();
        };
      });
    }
    return drainer;
  };
  const writer = {
    write(chunk) {
      chunkQueue.push(chunk);
      const drainer = makeDrainer();
      outWaitResolver();
      return drainer;
    },
    async end() {
      ended = true;
      const drainer = makeDrainer();
      outWaitResolver();
      return drainer;
    }
  };
  const iterator = {
    async next() {
      const chunk = chunkQueue.shift();
      if (chunk) {
        if (chunkQueue.length === 0) {
          drainerResolver();
        }
        return {
          done: false,
          value: chunk
        };
      }
      if (ended) {
        drainerResolver();
        return {
          done: true,
          value: undefined
        };
      }
      if (!outWait) {
        outWait = new Promise(resolve => {
          outWaitResolver = () => {
            outWait = null;
            outWaitResolver = noop;
            return resolve(iterator.next());
          };
        });
      }
      return outWait;
    }
  };
  return {
    writer,
    iterator
  };
}
;// CONCATENATED MODULE: ./node_modules/@ipld/car/esm/lib/writer-browser.js




class writer_browser_CarWriter {
  constructor(roots, encoder) {
    this._encoder = encoder;
    this._mutex = encoder.setRoots(roots);
    this._ended = false;
  }
  async put(block) {
    if (!(block.bytes instanceof Uint8Array) || !block.cid) {
      throw new TypeError('Can only write {cid, bytes} objects');
    }
    if (this._ended) {
      throw new Error('Already closed');
    }
    const cid = cid_CID.asCID(block.cid);
    if (!cid) {
      throw new TypeError('Can only write {cid, bytes} objects');
    }
    this._mutex = this._mutex.then(() => this._encoder.writeBlock({
      cid,
      bytes: block.bytes
    }));
    return this._mutex;
  }
  async close() {
    if (this._ended) {
      throw new Error('Already closed');
    }
    await this._mutex;
    this._ended = true;
    return this._encoder.close();
  }
  static create(roots) {
    roots = toRoots(roots);
    const {encoder, iterator} = encodeWriter();
    const writer = new writer_browser_CarWriter(roots, encoder);
    const out = new CarWriterOut(iterator);
    return {
      writer,
      out
    };
  }
  static createAppender() {
    const {encoder, iterator} = encodeWriter();
    encoder.setRoots = () => Promise.resolve();
    const writer = new writer_browser_CarWriter([], encoder);
    const out = new CarWriterOut(iterator);
    return {
      writer,
      out
    };
  }
  static async updateRootsInBytes(bytes, roots) {
    const reader = bytesReader(bytes);
    await readHeader(reader);
    const newHeader = createHeader(roots);
    if (reader.pos !== newHeader.length) {
      throw new Error(`updateRoots() can only overwrite a header of the same length (old header is ${ reader.pos } bytes, new header is ${ newHeader.length } bytes)`);
    }
    bytes.set(newHeader, 0);
    return bytes;
  }
}
class CarWriterOut {
  constructor(iterator) {
    this._iterator = iterator;
  }
  [Symbol.asyncIterator]() {
    if (this._iterating) {
      throw new Error('Multiple iterator not supported');
    }
    this._iterating = true;
    return this._iterator;
  }
}
function encodeWriter() {
  const iw = iterator_channel_create();
  const {writer, iterator} = iw;
  const encoder = createEncoder(writer);
  return {
    encoder,
    iterator
  };
}
function toRoots(roots) {
  if (roots === undefined) {
    return [];
  }
  if (!Array.isArray(roots)) {
    const cid = cid_CID.asCID(roots);
    if (!cid) {
      throw new TypeError('roots must be a single CID or an array of CIDs');
    }
    return [cid];
  }
  const _roots = [];
  for (const root of roots) {
    const _root = cid_CID.asCID(root);
    if (!_root) {
      throw new TypeError('roots must be a single CID or an array of CIDs');
    }
    _roots.push(_root);
  }
  return _roots;
}
const writer_browser_browser = true;
;// CONCATENATED MODULE: ./node_modules/@ipld/car/esm/lib/writer.js





const writer_fsread = (0,external_util_.promisify)(external_fs_.read);
const fswrite = (0,external_util_.promisify)(external_fs_.write);
class writer_CarWriter extends writer_browser_CarWriter {
  static async updateRootsInFile(fd, roots) {
    const chunkSize = 256;
    let bytes;
    let offset = 0;
    let readChunk;
    if (typeof fd === 'number') {
      readChunk = async () => (await writer_fsread(fd, bytes, 0, chunkSize, offset)).bytesRead;
    } else if (typeof fd === 'object' && typeof fd.read === 'function') {
      readChunk = async () => (await fd.read(bytes, 0, chunkSize, offset)).bytesRead;
    } else {
      throw new TypeError('Bad fd');
    }
    const fdReader = chunkReader(async () => {
      bytes = new Uint8Array(chunkSize);
      const read = await readChunk();
      offset += read;
      return read < chunkSize ? bytes.subarray(0, read) : bytes;
    });
    await readHeader(fdReader);
    const newHeader = createHeader(roots);
    if (fdReader.pos !== newHeader.length) {
      throw new Error(`updateRoots() can only overwrite a header of the same length (old header is ${ fdReader.pos } bytes, new header is ${ newHeader.length } bytes)`);
    }
    if (typeof fd === 'number') {
      await fswrite(fd, newHeader, 0, newHeader.length, 0);
    } else if (typeof fd === 'object' && typeof fd.read === 'function') {
      await fd.write(newHeader, 0, newHeader.length, 0);
    }
  }
}
const writer_browser = false;
// EXTERNAL MODULE: external "stream"
var external_stream_ = __webpack_require__(12781);
;// CONCATENATED MODULE: ./node_modules/@ipld/car/esm/lib/indexed-reader.js





class CarIndexedReader {
  constructor(version, path, roots, index, order) {
    this._version = version;
    this._path = path;
    this._roots = roots;
    this._index = index;
    this._order = order;
    this._fd = null;
  }
  get version() {
    return this._version;
  }
  async getRoots() {
    return this._roots;
  }
  async has(key) {
    return this._index.has(key.toString());
  }
  async get(key) {
    const blockIndex = this._index.get(key.toString());
    if (!blockIndex) {
      return undefined;
    }
    if (!this._fd) {
      this._fd = await fs.promises.open(this._path, 'r');
    }
    const readIndex = {
      cid: key,
      length: 0,
      offset: 0,
      blockLength: blockIndex.blockLength,
      blockOffset: blockIndex.blockOffset
    };
    return NodeCarReader.readRaw(this._fd, readIndex);
  }
  async *blocks() {
    for (const cidStr of this._order) {
      const block = await this.get(CID.parse(cidStr));
      if (!block) {
        throw new Error('Unexpected internal error');
      }
      yield block;
    }
  }
  async *cids() {
    for (const cidStr of this._order) {
      yield CID.parse(cidStr);
    }
  }
  async close() {
    if (this._fd) {
      return this._fd.close();
    }
  }
  static async fromFile(path) {
    if (typeof path !== 'string') {
      throw new TypeError('fromFile() requires a file path string');
    }
    const iterable = await CarIndexer.fromIterable(Readable.from(fs.createReadStream(path)));
    const index = new Map();
    const order = [];
    for await (const {cid, blockLength, blockOffset} of iterable) {
      const cidStr = cid.toString();
      index.set(cidStr, {
        blockLength,
        blockOffset
      });
      order.push(cidStr);
    }
    return new CarIndexedReader(iterable.version, path, await iterable.getRoots(), index, order);
  }
}
const indexed_reader_browser = false;
;// CONCATENATED MODULE: ./node_modules/@ipld/car/esm/car.js






;// CONCATENATED MODULE: ./node_modules/multiformats/esm/src/hashes/hasher.js

const hasher_from = ({name, code, encode}) => new Hasher(name, code, encode);
class Hasher {
  constructor(name, code, encode) {
    this.name = name;
    this.code = code;
    this.encode = encode;
  }
  digest(input) {
    if (input instanceof Uint8Array) {
      const result = this.encode(input);
      return result instanceof Uint8Array ? create(this.code, result) : result.then(digest => create(this.code, digest));
    } else {
      throw Error('Unknown type, must be binary type');
    }
  }
}
;// CONCATENATED MODULE: ./node_modules/multiformats/esm/src/index.js






;// CONCATENATED MODULE: ./node_modules/multiformats/esm/src/block.js

const block_readonly = ({enumerable = true, configurable = false} = {}) => ({
  enumerable,
  configurable,
  writable: false
});
const links = function* (source, base) {
  if (source == null)
    return;
  if (source instanceof Uint8Array)
    return;
  for (const [key, value] of Object.entries(source)) {
    const path = [
      ...base,
      key
    ];
    if (value != null && typeof value === 'object') {
      if (Array.isArray(value)) {
        for (const [index, element] of value.entries()) {
          const elementPath = [
            ...path,
            index
          ];
          const cid = cid_CID.asCID(element);
          if (cid) {
            yield [
              elementPath.join('/'),
              cid
            ];
          } else if (typeof element === 'object') {
            yield* links(element, elementPath);
          }
        }
      } else {
        const cid = cid_CID.asCID(value);
        if (cid) {
          yield [
            path.join('/'),
            cid
          ];
        } else {
          yield* links(value, path);
        }
      }
    }
  }
};
const tree = function* (source, base) {
  if (source == null)
    return;
  for (const [key, value] of Object.entries(source)) {
    const path = [
      ...base,
      key
    ];
    yield path.join('/');
    if (value != null && !(value instanceof Uint8Array) && typeof value === 'object' && !cid_CID.asCID(value)) {
      if (Array.isArray(value)) {
        for (const [index, element] of value.entries()) {
          const elementPath = [
            ...path,
            index
          ];
          yield elementPath.join('/');
          if (typeof element === 'object' && !cid_CID.asCID(element)) {
            yield* tree(element, elementPath);
          }
        }
      } else {
        yield* tree(value, path);
      }
    }
  }
};
const get = (source, path) => {
  let node = source;
  for (const [index, key] of path.entries()) {
    node = node[key];
    if (node == null) {
      throw new Error(`Object has no property at ${ path.slice(0, index + 1).map(part => `[${ JSON.stringify(part) }]`).join('') }`);
    }
    const cid = cid_CID.asCID(node);
    if (cid) {
      return {
        value: cid,
        remaining: path.slice(index + 1).join('/')
      };
    }
  }
  return { value: node };
};
class Block {
  constructor({cid, bytes, value}) {
    if (!cid || !bytes || typeof value === 'undefined')
      throw new Error('Missing required argument');
    this.cid = cid;
    this.bytes = bytes;
    this.value = value;
    this.asBlock = this;
    Object.defineProperties(this, {
      cid: block_readonly(),
      bytes: block_readonly(),
      value: block_readonly(),
      asBlock: block_readonly()
    });
  }
  links() {
    return links(this.value, []);
  }
  tree() {
    return tree(this.value, []);
  }
  get(path = '/') {
    return get(this.value, path.split('/').filter(Boolean));
  }
}
const block_encode = async ({value, codec, hasher}) => {
  if (typeof value === 'undefined')
    throw new Error('Missing required argument "value"');
  if (!codec || !hasher)
    throw new Error('Missing required argument: codec or hasher');
  const bytes = codec.encode(value);
  const hash = await hasher.digest(bytes);
  const cid = cid_CID.create(1, codec.code, hash);
  return new Block({
    value,
    bytes,
    cid
  });
};
const block_decode = async ({bytes, codec, hasher}) => {
  if (!bytes)
    throw new Error('Missing required argument "bytes"');
  if (!codec || !hasher)
    throw new Error('Missing required argument: codec or hasher');
  const value = codec.decode(bytes);
  const hash = await hasher.digest(bytes);
  const cid = CID.create(1, codec.code, hash);
  return new Block({
    value,
    bytes,
    cid
  });
};
const createUnsafe = ({
  bytes,
  cid,
  value: maybeValue,
  codec
}) => {
  const value = maybeValue !== undefined ? maybeValue : codec && codec.decode(bytes);
  if (value === undefined)
    throw new Error('Missing required argument, must either provide "value" or "codec"');
  return new Block({
    cid,
    bytes,
    value
  });
};
const block_create = async ({bytes, cid, hasher, codec}) => {
  if (!bytes)
    throw new Error('Missing required argument "bytes"');
  if (!hasher)
    throw new Error('Missing required argument "hasher"');
  const value = codec.decode(bytes);
  const hash = await hasher.digest(bytes);
  if (!binary.equals(cid.multihash.bytes, hash.bytes)) {
    throw new Error('CID hash does not match bytes');
  }
  return createUnsafe({
    bytes,
    cid,
    value,
    codec
  });
};

;// CONCATENATED MODULE: ./node_modules/multiformats/esm/src/codecs/raw.js

const raw_name = 'raw';
const raw_code = 85;
const raw_encode = node => coerce(node);
const raw_decode = data => coerce(data);
;// CONCATENATED MODULE: ./node_modules/@ipld/dag-cbor/esm/index.js


const esm_CID_CBOR_TAG = 42;
function esm_cidEncoder(obj) {
  if (obj.asCID !== obj) {
    return null;
  }
  const cid = cid_CID.asCID(obj);
  if (!cid) {
    return null;
  }
  const bytes = new Uint8Array(cid.bytes.byteLength + 1);
  bytes.set(cid.bytes, 1);
  return [
    new Token(Type.tag, esm_CID_CBOR_TAG),
    new Token(Type.bytes, bytes)
  ];
}
function esm_undefinedEncoder() {
  throw new Error('`undefined` is not supported by the IPLD Data Model and cannot be encoded');
}
function esm_numberEncoder(num) {
  if (Number.isNaN(num)) {
    throw new Error('`NaN` is not supported by the IPLD Data Model and cannot be encoded');
  }
  if (num === Infinity || num === -Infinity) {
    throw new Error('`Infinity` and `-Infinity` is not supported by the IPLD Data Model and cannot be encoded');
  }
  return null;
}
const esm_encodeOptions = {
  float64: true,
  typeEncoders: {
    Object: esm_cidEncoder,
    undefined: esm_undefinedEncoder,
    number: esm_numberEncoder
  }
};
function esm_cidDecoder(bytes) {
  if (bytes[0] !== 0) {
    throw new Error('Invalid CID for CBOR tag 42; expected leading 0x00');
  }
  return cid_CID.decode(bytes.subarray(1));
}
const esm_decodeOptions = {
  allowIndefinite: false,
  allowUndefined: false,
  allowNaN: false,
  allowInfinity: false,
  allowBigInt: true,
  strict: true,
  useMaps: false,
  tags: []
};
esm_decodeOptions.tags[esm_CID_CBOR_TAG] = esm_cidDecoder;
const dag_cbor_esm_name = 'dag-cbor';
const esm_code = 113;
const dag_cbor_esm_encode = node => encode_encode(node, esm_encodeOptions);
const dag_cbor_esm_decode = data => decode_decode(data, esm_decodeOptions);
;// CONCATENATED MODULE: ./node_modules/@ipld/dag-pb/esm/src/pb-decode.js
const pb_decode_textDecoder = new TextDecoder();
function decodeVarint(bytes, offset) {
  let v = 0;
  for (let shift = 0;; shift += 7) {
    if (shift >= 64) {
      throw new Error('protobuf: varint overflow');
    }
    if (offset >= bytes.length) {
      throw new Error('protobuf: unexpected end of data');
    }
    const b = bytes[offset++];
    v += shift < 28 ? (b & 127) << shift : (b & 127) * 2 ** shift;
    if (b < 128) {
      break;
    }
  }
  return [
    v,
    offset
  ];
}
function decodeBytes(bytes, offset) {
  let byteLen;
  [byteLen, offset] = decodeVarint(bytes, offset);
  const postOffset = offset + byteLen;
  if (byteLen < 0 || postOffset < 0) {
    throw new Error('protobuf: invalid length');
  }
  if (postOffset > bytes.length) {
    throw new Error('protobuf: unexpected end of data');
  }
  return [
    bytes.subarray(offset, postOffset),
    postOffset
  ];
}
function decodeKey(bytes, index) {
  let wire;
  [wire, index] = decodeVarint(bytes, index);
  return [
    wire & 7,
    wire >> 3,
    index
  ];
}
function decodeLink(bytes) {
  const link = {};
  const l = bytes.length;
  let index = 0;
  while (index < l) {
    let wireType, fieldNum;
    [wireType, fieldNum, index] = decodeKey(bytes, index);
    if (fieldNum === 1) {
      if (link.Hash) {
        throw new Error('protobuf: (PBLink) duplicate Hash section');
      }
      if (wireType !== 2) {
        throw new Error(`protobuf: (PBLink) wrong wireType (${ wireType }) for Hash`);
      }
      if (link.Name !== undefined) {
        throw new Error('protobuf: (PBLink) invalid order, found Name before Hash');
      }
      if (link.Tsize !== undefined) {
        throw new Error('protobuf: (PBLink) invalid order, found Tsize before Hash');
      }
      ;
      [link.Hash, index] = decodeBytes(bytes, index);
    } else if (fieldNum === 2) {
      if (link.Name !== undefined) {
        throw new Error('protobuf: (PBLink) duplicate Name section');
      }
      if (wireType !== 2) {
        throw new Error(`protobuf: (PBLink) wrong wireType (${ wireType }) for Name`);
      }
      if (link.Tsize !== undefined) {
        throw new Error('protobuf: (PBLink) invalid order, found Tsize before Name');
      }
      let byts;
      [byts, index] = decodeBytes(bytes, index);
      link.Name = pb_decode_textDecoder.decode(byts);
    } else if (fieldNum === 3) {
      if (link.Tsize !== undefined) {
        throw new Error('protobuf: (PBLink) duplicate Tsize section');
      }
      if (wireType !== 0) {
        throw new Error(`protobuf: (PBLink) wrong wireType (${ wireType }) for Tsize`);
      }
      ;
      [link.Tsize, index] = decodeVarint(bytes, index);
    } else {
      throw new Error(`protobuf: (PBLink) invalid fieldNumber, expected 1, 2 or 3, got ${ fieldNum }`);
    }
  }
  if (index > l) {
    throw new Error('protobuf: (PBLink) unexpected end of data');
  }
  return link;
}
function decodeNode(bytes) {
  const l = bytes.length;
  let index = 0;
  let links;
  let linksBeforeData = false;
  let data;
  while (index < l) {
    let wireType, fieldNum;
    [wireType, fieldNum, index] = decodeKey(bytes, index);
    if (wireType !== 2) {
      throw new Error(`protobuf: (PBNode) invalid wireType, expected 2, got ${ wireType }`);
    }
    if (fieldNum === 1) {
      if (data) {
        throw new Error('protobuf: (PBNode) duplicate Data section');
      }
      ;
      [data, index] = decodeBytes(bytes, index);
      if (links) {
        linksBeforeData = true;
      }
    } else if (fieldNum === 2) {
      if (linksBeforeData) {
        throw new Error('protobuf: (PBNode) duplicate Links section');
      } else if (!links) {
        links = [];
      }
      let byts;
      [byts, index] = decodeBytes(bytes, index);
      links.push(decodeLink(byts));
    } else {
      throw new Error(`protobuf: (PBNode) invalid fieldNumber, expected 1 or 2, got ${ fieldNum }`);
    }
  }
  if (index > l) {
    throw new Error('protobuf: (PBNode) unexpected end of data');
  }
  const node = {};
  if (data) {
    node.Data = data;
  }
  node.Links = links || [];
  return node;
}
;// CONCATENATED MODULE: ./node_modules/@ipld/dag-pb/esm/src/pb-encode.js
const pb_encode_textEncoder = new TextEncoder();
const maxInt32 = 2 ** 32;
const maxUInt32 = 2 ** 31;
function encodeLink(link, bytes) {
  let i = bytes.length;
  if (typeof link.Tsize === 'number') {
    if (link.Tsize < 0) {
      throw new Error('Tsize cannot be negative');
    }
    if (!Number.isSafeInteger(link.Tsize)) {
      throw new Error('Tsize too large for encoding');
    }
    i = encodeVarint(bytes, i, link.Tsize) - 1;
    bytes[i] = 24;
  }
  if (typeof link.Name === 'string') {
    const nameBytes = pb_encode_textEncoder.encode(link.Name);
    i -= nameBytes.length;
    bytes.set(nameBytes, i);
    i = encodeVarint(bytes, i, nameBytes.length) - 1;
    bytes[i] = 18;
  }
  if (link.Hash) {
    i -= link.Hash.length;
    bytes.set(link.Hash, i);
    i = encodeVarint(bytes, i, link.Hash.length) - 1;
    bytes[i] = 10;
  }
  return bytes.length - i;
}
function encodeNode(node) {
  const size = sizeNode(node);
  const bytes = new Uint8Array(size);
  let i = size;
  if (node.Data) {
    i -= node.Data.length;
    bytes.set(node.Data, i);
    i = encodeVarint(bytes, i, node.Data.length) - 1;
    bytes[i] = 10;
  }
  if (node.Links) {
    for (let index = node.Links.length - 1; index >= 0; index--) {
      const size = encodeLink(node.Links[index], bytes.subarray(0, i));
      i -= size;
      i = encodeVarint(bytes, i, size) - 1;
      bytes[i] = 18;
    }
  }
  return bytes;
}
function sizeLink(link) {
  let n = 0;
  if (link.Hash) {
    const l = link.Hash.length;
    n += 1 + l + sov(l);
  }
  if (typeof link.Name === 'string') {
    const l = pb_encode_textEncoder.encode(link.Name).length;
    n += 1 + l + sov(l);
  }
  if (typeof link.Tsize === 'number') {
    n += 1 + sov(link.Tsize);
  }
  return n;
}
function sizeNode(node) {
  let n = 0;
  if (node.Data) {
    const l = node.Data.length;
    n += 1 + l + sov(l);
  }
  if (node.Links) {
    for (const link of node.Links) {
      const l = sizeLink(link);
      n += 1 + l + sov(l);
    }
  }
  return n;
}
function encodeVarint(bytes, offset, v) {
  offset -= sov(v);
  const base = offset;
  while (v >= maxUInt32) {
    bytes[offset++] = v & 127 | 128;
    v /= 128;
  }
  while (v >= 128) {
    bytes[offset++] = v & 127 | 128;
    v >>>= 7;
  }
  bytes[offset] = v;
  return base;
}
function sov(x) {
  if (x % 2 === 0) {
    x++;
  }
  return Math.floor((len64(x) + 6) / 7);
}
function len64(x) {
  let n = 0;
  if (x >= maxInt32) {
    x = Math.floor(x / maxInt32);
    n = 32;
  }
  if (x >= 1 << 16) {
    x >>>= 16;
    n += 16;
  }
  if (x >= 1 << 8) {
    x >>>= 8;
    n += 8;
  }
  return n + len8tab[x];
}
const len8tab = [
  0,
  1,
  2,
  2,
  3,
  3,
  3,
  3,
  4,
  4,
  4,
  4,
  4,
  4,
  4,
  4,
  5,
  5,
  5,
  5,
  5,
  5,
  5,
  5,
  5,
  5,
  5,
  5,
  5,
  5,
  5,
  5,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8,
  8
];
;// CONCATENATED MODULE: ./node_modules/@ipld/dag-pb/esm/src/util.js

const pbNodeProperties = [
  'Data',
  'Links'
];
const pbLinkProperties = [
  'Hash',
  'Name',
  'Tsize'
];
const util_textEncoder = new TextEncoder();
function linkComparator(a, b) {
  if (a === b) {
    return 0;
  }
  const abuf = a.Name ? util_textEncoder.encode(a.Name) : [];
  const bbuf = b.Name ? util_textEncoder.encode(b.Name) : [];
  let x = abuf.length;
  let y = bbuf.length;
  for (let i = 0, len = Math.min(x, y); i < len; ++i) {
    if (abuf[i] !== bbuf[i]) {
      x = abuf[i];
      y = bbuf[i];
      break;
    }
  }
  return x < y ? -1 : y < x ? 1 : 0;
}
function hasOnlyProperties(node, properties) {
  return !Object.keys(node).some(p => !properties.includes(p));
}
function asLink(link) {
  if (typeof link.asCID === 'object') {
    const Hash = cid_CID.asCID(link);
    if (!Hash) {
      throw new TypeError('Invalid DAG-PB form');
    }
    return { Hash };
  }
  if (typeof link !== 'object' || Array.isArray(link)) {
    throw new TypeError('Invalid DAG-PB form');
  }
  const pbl = {};
  if (link.Hash) {
    let cid = cid_CID.asCID(link.Hash);
    try {
      if (!cid) {
        if (typeof link.Hash === 'string') {
          cid = cid_CID.parse(link.Hash);
        } else if (link.Hash instanceof Uint8Array) {
          cid = cid_CID.decode(link.Hash);
        }
      }
    } catch (e) {
      throw new TypeError(`Invalid DAG-PB form: ${ e.message }`);
    }
    if (cid) {
      pbl.Hash = cid;
    }
  }
  if (!pbl.Hash) {
    throw new TypeError('Invalid DAG-PB form');
  }
  if (typeof link.Name === 'string') {
    pbl.Name = link.Name;
  }
  if (typeof link.Tsize === 'number') {
    pbl.Tsize = link.Tsize;
  }
  return pbl;
}
function prepare(node) {
  if (node instanceof Uint8Array || typeof node === 'string') {
    node = { Data: node };
  }
  if (typeof node !== 'object' || Array.isArray(node)) {
    throw new TypeError('Invalid DAG-PB form');
  }
  const pbn = {};
  if (node.Data !== undefined) {
    if (typeof node.Data === 'string') {
      pbn.Data = util_textEncoder.encode(node.Data);
    } else if (node.Data instanceof Uint8Array) {
      pbn.Data = node.Data;
    } else {
      throw new TypeError('Invalid DAG-PB form');
    }
  }
  if (node.Links !== undefined) {
    if (Array.isArray(node.Links)) {
      pbn.Links = node.Links.map(asLink);
      pbn.Links.sort(linkComparator);
    } else {
      throw new TypeError('Invalid DAG-PB form');
    }
  } else {
    pbn.Links = [];
  }
  return pbn;
}
function validate(node) {
  if (!node || typeof node !== 'object' || Array.isArray(node)) {
    throw new TypeError('Invalid DAG-PB form');
  }
  if (!hasOnlyProperties(node, pbNodeProperties)) {
    throw new TypeError('Invalid DAG-PB form (extraneous properties)');
  }
  if (node.Data !== undefined && !(node.Data instanceof Uint8Array)) {
    throw new TypeError('Invalid DAG-PB form (Data must be a Uint8Array)');
  }
  if (!Array.isArray(node.Links)) {
    throw new TypeError('Invalid DAG-PB form (Links must be an array)');
  }
  for (let i = 0; i < node.Links.length; i++) {
    const link = node.Links[i];
    if (!link || typeof link !== 'object' || Array.isArray(link)) {
      throw new TypeError('Invalid DAG-PB form (bad link object)');
    }
    if (!hasOnlyProperties(link, pbLinkProperties)) {
      throw new TypeError('Invalid DAG-PB form (extraneous properties on link object)');
    }
    if (!link.Hash) {
      throw new TypeError('Invalid DAG-PB form (link must have a Hash)');
    }
    if (link.Hash.asCID !== link.Hash) {
      throw new TypeError('Invalid DAG-PB form (link Hash must be a CID)');
    }
    if (link.Name !== undefined && typeof link.Name !== 'string') {
      throw new TypeError('Invalid DAG-PB form (link Name must be a string)');
    }
    if (link.Tsize !== undefined && (typeof link.Tsize !== 'number' || link.Tsize % 1 !== 0)) {
      throw new TypeError('Invalid DAG-PB form (link Tsize must be an integer)');
    }
    if (i > 0 && linkComparator(link, node.Links[i - 1]) === -1) {
      throw new TypeError('Invalid DAG-PB form (links must be sorted by Name bytes)');
    }
  }
}
function createNode(data, links = []) {
  return prepare({
    Data: data,
    Links: links
  });
}
function createLink(name, size, cid) {
  return asLink({
    Hash: cid,
    Name: name,
    Tsize: size
  });
}
;// CONCATENATED MODULE: ./node_modules/@ipld/dag-pb/esm/src/index.js




const src_name = 'dag-pb';
const src_code = 112;
function src_encode(node) {
  validate(node);
  const pbn = {};
  if (node.Links) {
    pbn.Links = node.Links.map(l => {
      const link = {};
      if (l.Hash) {
        link.Hash = l.Hash.bytes;
      }
      if (l.Name !== undefined) {
        link.Name = l.Name;
      }
      if (l.Tsize !== undefined) {
        link.Tsize = l.Tsize;
      }
      return link;
    });
  }
  if (node.Data) {
    pbn.Data = node.Data;
  }
  return encodeNode(pbn);
}
function src_decode(bytes) {
  const pbn = decodeNode(bytes);
  const node = {};
  if (pbn.Data) {
    node.Data = pbn.Data;
  }
  if (pbn.Links) {
    node.Links = pbn.Links.map(l => {
      const link = {};
      try {
        link.Hash = cid_CID.decode(l.Hash);
      } catch (e) {
      }
      if (!link.Hash) {
        throw new Error('Invalid Hash field found in link, expected CID');
      }
      if (l.Name !== undefined) {
        link.Name = l.Name;
      }
      if (l.Tsize !== undefined) {
        link.Tsize = l.Tsize;
      }
      return link;
    });
  }
  return node;
}

;// CONCATENATED MODULE: ./node_modules/carbites/esm/lib/treewalk/splitter.js





class TreewalkCarSplitter {
  constructor(reader, targetSize, options = {}) {
    if (typeof targetSize !== 'number' || targetSize <= 0) {
      throw new Error('invalid target chunk size');
    }
    this._reader = reader;
    this._targetSize = targetSize;
    this._decoders = [
      esm_src_namespaceObject,
      raw_namespaceObject,
      dag_cbor_esm_namespaceObject,
      ...options.decoders || []
    ];
  }
  async *cars() {
    const roots = await this._reader.getRoots();
    if (roots.length !== 1)
      throw new Error(`unexpected number of roots: ${ roots.length }`);
    let channel;
    for await (const val of this._cars(roots[0])) {
      channel = val.channel;
      if (val.out)
        yield val.out;
    }
    if (!channel) {
      throw new Error('missing CAR writer channel');
    }
    channel.writer.close();
    yield channel.out;
  }
  async _get(cid) {
    const rawBlock = await this._reader.get(cid);
    if (!rawBlock)
      throw new Error(`missing block for ${ cid }`);
    const {bytes} = rawBlock;
    const decoder = this._decoders.find(d => d.code === cid.code);
    if (!decoder)
      throw new Error(`missing decoder for ${ cid.code }`);
    return new Block({
      cid,
      bytes,
      value: decoder.decode(bytes)
    });
  }
  async *_cars(cid, parents = [], channel = undefined) {
    const block = await this._get(cid);
    channel = channel || Object.assign(writer_CarWriter.create(cid), { size: 0 });
    if (channel.size > 0 && channel.size + block.bytes.byteLength >= this._targetSize) {
      channel.writer.close();
      const {out} = channel;
      channel = newCar(parents);
      yield {
        channel,
        out
      };
    }
    parents = parents.concat(block);
    channel.size += block.bytes.byteLength;
    channel.writer.put(block);
    for (const [, cid] of block.links()) {
      for await (const val of this._cars(cid, parents, channel)) {
        channel = val.channel;
        yield val;
      }
    }
    if (!channel) {
      throw new Error('missing CAR writer channel');
    }
    yield { channel };
  }
  static async fromIterable(iterable, targetSize, options) {
    const reader = await CarReader.fromIterable(iterable);
    return new TreewalkCarSplitter(reader, targetSize, options);
  }
  static async fromBlob(blob, targetSize, options) {
    const buffer = await blob.arrayBuffer();
    const reader = await CarReader.fromBytes(new Uint8Array(buffer));
    return new TreewalkCarSplitter(reader, targetSize, options);
  }
}
function newCar(parents) {
  const ch = Object.assign(writer_CarWriter.create(parents[0].cid), { size: parents.reduce((size, b) => size + b.bytes.byteLength, 0) });
  for (const b of parents) {
    ch.writer.put(b);
  }
  return ch;
}
;// CONCATENATED MODULE: ./node_modules/carbites/esm/lib/treewalk/joiner.js

class TreewalkCarJoiner {
  constructor(cars) {
    this._cars = Array.from(cars);
    if (!this._cars.length)
      throw new Error('missing CARs');
  }
  async *car() {
    const reader = this._cars[0];
    const roots = await reader.getRoots();
    const {writer, out} = CarWriter.create(roots);
    const writeCar = async () => {
      const written = new Set();
      const writeBlocks = async reader => {
        for await (const b of reader.blocks()) {
          if (written.has(b.cid.toString()))
            continue;
          await writer.put(b);
          written.add(b.cid.toString());
        }
      };
      try {
        await writeBlocks(reader);
        for (const reader of this._cars.slice(1)) {
          await writeBlocks(reader);
        }
      } catch (err) {
        console.error(err);
      } finally {
        await writer.close();
      }
    };
    writeCar();
    yield* out;
  }
}
;// CONCATENATED MODULE: ./node_modules/carbites/esm/lib/treewalk/index.js



// EXTERNAL MODULE: ./node_modules/it-last/index.js
var it_last = __webpack_require__(7754);
// EXTERNAL MODULE: ./node_modules/it-pipe/index.js
var it_pipe = __webpack_require__(38947);
// EXTERNAL MODULE: ./node_modules/it-parallel-batch/index.js
var it_parallel_batch = __webpack_require__(51046);
// EXTERNAL MODULE: ./node_modules/merge-options/index.js
var merge_options = __webpack_require__(70890);
;// CONCATENATED MODULE: ./node_modules/merge-options/index.mjs
/**
 * Thin ESM wrapper for CJS named exports.
 *
 * Ref: https://redfin.engineering/node-modules-at-war-why-commonjs-and-es-modules-cant-get-along-9617135eeca1
 */


/* harmony default export */ const node_modules_merge_options = (merge_options);

// EXTERNAL MODULE: external "crypto"
var external_crypto_ = __webpack_require__(6113);
;// CONCATENATED MODULE: ./node_modules/multiformats/esm/src/hashes/sha2.js



const sha256 = hasher_from({
  name: 'sha2-256',
  code: 18,
  encode: input => coerce(external_crypto_.createHash('sha256').update(input).digest())
});
const sha512 = hasher_from({
  name: 'sha2-512',
  code: 19,
  encode: input => coerce(external_crypto_.createHash('sha512').update(input).digest())
});
// EXTERNAL MODULE: ./node_modules/murmurhash3js-revisited/index.js
var murmurhash3js_revisited = __webpack_require__(63655);
;// CONCATENATED MODULE: ./node_modules/@multiformats/murmur3/esm/index.js



function fromNumberTo32BitBuf(number) {
  const bytes = new Array(4);
  for (let i = 0; i < 4; i++) {
    bytes[i] = number & 255;
    number = number >> 8;
  }
  return new Uint8Array(bytes);
}
const murmur332 = hasher_from({
  name: 'murmur3-32',
  code: 35,
  encode: input => fromNumberTo32BitBuf(murmurhash3js_revisited.x86.hash32(input))
});
const murmur3128 = hasher_from({
  name: 'murmur3-128',
  code: 34,
  encode: input => fromHex(murmurhash3js_revisited.x64.hash128(input))
});
;// CONCATENATED MODULE: ./node_modules/ipfs-unixfs-importer/esm/src/options.js



async function hamtHashFn(buf) {
  return (await murmur3128.encode(buf)).slice(0, 8).reverse();
}
const defaultOptions = {
  chunker: 'fixed',
  strategy: 'balanced',
  rawLeaves: false,
  onlyHash: false,
  reduceSingleLeafToSelf: true,
  hasher: sha256,
  leafType: 'file',
  cidVersion: 0,
  progress: () => () => {
  },
  shardSplitThreshold: 1000,
  fileImportConcurrency: 50,
  blockWriteConcurrency: 10,
  minChunkSize: 262144,
  maxChunkSize: 262144,
  avgChunkSize: 262144,
  window: 16,
  polynomial: 17437180132763652,
  maxChildrenPerNode: 174,
  layerRepeat: 4,
  wrapWithDirectory: false,
  recursive: false,
  hidden: false,
  timeout: undefined,
  hamtHashFn,
  hamtHashCode: 34,
  hamtBucketBits: 8
};
/* harmony default export */ const src_options = ((options = {}) => {
  const defaults = node_modules_merge_options.bind({ ignoreUndefined: true });
  return defaults(defaultOptions, options);
});
// EXTERNAL MODULE: ./node_modules/err-code/index.js
var err_code = __webpack_require__(17058);
// EXTERNAL MODULE: ./node_modules/protobufjs/minimal.js
var minimal = __webpack_require__(51883);
;// CONCATENATED MODULE: ./node_modules/ipfs-unixfs/esm/src/unixfs.js

const $Reader = minimal.Reader, $Writer = minimal.Writer, $util = minimal.util;
const $root = minimal.roots['ipfs-unixfs'] || (minimal.roots['ipfs-unixfs'] = {});
const Data = $root.Data = (() => {
  function Data(p) {
    this.blocksizes = [];
    if (p)
      for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
        if (p[ks[i]] != null)
          this[ks[i]] = p[ks[i]];
  }
  Data.prototype.Type = 0;
  Data.prototype.Data = $util.newBuffer([]);
  Data.prototype.filesize = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
  Data.prototype.blocksizes = $util.emptyArray;
  Data.prototype.hashType = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
  Data.prototype.fanout = $util.Long ? $util.Long.fromBits(0, 0, true) : 0;
  Data.prototype.mode = 0;
  Data.prototype.mtime = null;
  Data.encode = function encode(m, w) {
    if (!w)
      w = $Writer.create();
    w.uint32(8).int32(m.Type);
    if (m.Data != null && Object.hasOwnProperty.call(m, 'Data'))
      w.uint32(18).bytes(m.Data);
    if (m.filesize != null && Object.hasOwnProperty.call(m, 'filesize'))
      w.uint32(24).uint64(m.filesize);
    if (m.blocksizes != null && m.blocksizes.length) {
      for (var i = 0; i < m.blocksizes.length; ++i)
        w.uint32(32).uint64(m.blocksizes[i]);
    }
    if (m.hashType != null && Object.hasOwnProperty.call(m, 'hashType'))
      w.uint32(40).uint64(m.hashType);
    if (m.fanout != null && Object.hasOwnProperty.call(m, 'fanout'))
      w.uint32(48).uint64(m.fanout);
    if (m.mode != null && Object.hasOwnProperty.call(m, 'mode'))
      w.uint32(56).uint32(m.mode);
    if (m.mtime != null && Object.hasOwnProperty.call(m, 'mtime'))
      $root.UnixTime.encode(m.mtime, w.uint32(66).fork()).ldelim();
    return w;
  };
  Data.decode = function decode(r, l) {
    if (!(r instanceof $Reader))
      r = $Reader.create(r);
    var c = l === undefined ? r.len : r.pos + l, m = new $root.Data();
    while (r.pos < c) {
      var t = r.uint32();
      switch (t >>> 3) {
      case 1:
        m.Type = r.int32();
        break;
      case 2:
        m.Data = r.bytes();
        break;
      case 3:
        m.filesize = r.uint64();
        break;
      case 4:
        if (!(m.blocksizes && m.blocksizes.length))
          m.blocksizes = [];
        if ((t & 7) === 2) {
          var c2 = r.uint32() + r.pos;
          while (r.pos < c2)
            m.blocksizes.push(r.uint64());
        } else
          m.blocksizes.push(r.uint64());
        break;
      case 5:
        m.hashType = r.uint64();
        break;
      case 6:
        m.fanout = r.uint64();
        break;
      case 7:
        m.mode = r.uint32();
        break;
      case 8:
        m.mtime = $root.UnixTime.decode(r, r.uint32());
        break;
      default:
        r.skipType(t & 7);
        break;
      }
    }
    if (!m.hasOwnProperty('Type'))
      throw $util.ProtocolError('missing required \'Type\'', { instance: m });
    return m;
  };
  Data.fromObject = function fromObject(d) {
    if (d instanceof $root.Data)
      return d;
    var m = new $root.Data();
    switch (d.Type) {
    case 'Raw':
    case 0:
      m.Type = 0;
      break;
    case 'Directory':
    case 1:
      m.Type = 1;
      break;
    case 'File':
    case 2:
      m.Type = 2;
      break;
    case 'Metadata':
    case 3:
      m.Type = 3;
      break;
    case 'Symlink':
    case 4:
      m.Type = 4;
      break;
    case 'HAMTShard':
    case 5:
      m.Type = 5;
      break;
    }
    if (d.Data != null) {
      if (typeof d.Data === 'string')
        $util.base64.decode(d.Data, m.Data = $util.newBuffer($util.base64.length(d.Data)), 0);
      else if (d.Data.length)
        m.Data = d.Data;
    }
    if (d.filesize != null) {
      if ($util.Long)
        (m.filesize = $util.Long.fromValue(d.filesize)).unsigned = true;
      else if (typeof d.filesize === 'string')
        m.filesize = parseInt(d.filesize, 10);
      else if (typeof d.filesize === 'number')
        m.filesize = d.filesize;
      else if (typeof d.filesize === 'object')
        m.filesize = new $util.LongBits(d.filesize.low >>> 0, d.filesize.high >>> 0).toNumber(true);
    }
    if (d.blocksizes) {
      if (!Array.isArray(d.blocksizes))
        throw TypeError('.Data.blocksizes: array expected');
      m.blocksizes = [];
      for (var i = 0; i < d.blocksizes.length; ++i) {
        if ($util.Long)
          (m.blocksizes[i] = $util.Long.fromValue(d.blocksizes[i])).unsigned = true;
        else if (typeof d.blocksizes[i] === 'string')
          m.blocksizes[i] = parseInt(d.blocksizes[i], 10);
        else if (typeof d.blocksizes[i] === 'number')
          m.blocksizes[i] = d.blocksizes[i];
        else if (typeof d.blocksizes[i] === 'object')
          m.blocksizes[i] = new $util.LongBits(d.blocksizes[i].low >>> 0, d.blocksizes[i].high >>> 0).toNumber(true);
      }
    }
    if (d.hashType != null) {
      if ($util.Long)
        (m.hashType = $util.Long.fromValue(d.hashType)).unsigned = true;
      else if (typeof d.hashType === 'string')
        m.hashType = parseInt(d.hashType, 10);
      else if (typeof d.hashType === 'number')
        m.hashType = d.hashType;
      else if (typeof d.hashType === 'object')
        m.hashType = new $util.LongBits(d.hashType.low >>> 0, d.hashType.high >>> 0).toNumber(true);
    }
    if (d.fanout != null) {
      if ($util.Long)
        (m.fanout = $util.Long.fromValue(d.fanout)).unsigned = true;
      else if (typeof d.fanout === 'string')
        m.fanout = parseInt(d.fanout, 10);
      else if (typeof d.fanout === 'number')
        m.fanout = d.fanout;
      else if (typeof d.fanout === 'object')
        m.fanout = new $util.LongBits(d.fanout.low >>> 0, d.fanout.high >>> 0).toNumber(true);
    }
    if (d.mode != null) {
      m.mode = d.mode >>> 0;
    }
    if (d.mtime != null) {
      if (typeof d.mtime !== 'object')
        throw TypeError('.Data.mtime: object expected');
      m.mtime = $root.UnixTime.fromObject(d.mtime);
    }
    return m;
  };
  Data.toObject = function toObject(m, o) {
    if (!o)
      o = {};
    var d = {};
    if (o.arrays || o.defaults) {
      d.blocksizes = [];
    }
    if (o.defaults) {
      d.Type = o.enums === String ? 'Raw' : 0;
      if (o.bytes === String)
        d.Data = '';
      else {
        d.Data = [];
        if (o.bytes !== Array)
          d.Data = $util.newBuffer(d.Data);
      }
      if ($util.Long) {
        var n = new $util.Long(0, 0, true);
        d.filesize = o.longs === String ? n.toString() : o.longs === Number ? n.toNumber() : n;
      } else
        d.filesize = o.longs === String ? '0' : 0;
      if ($util.Long) {
        var n = new $util.Long(0, 0, true);
        d.hashType = o.longs === String ? n.toString() : o.longs === Number ? n.toNumber() : n;
      } else
        d.hashType = o.longs === String ? '0' : 0;
      if ($util.Long) {
        var n = new $util.Long(0, 0, true);
        d.fanout = o.longs === String ? n.toString() : o.longs === Number ? n.toNumber() : n;
      } else
        d.fanout = o.longs === String ? '0' : 0;
      d.mode = 0;
      d.mtime = null;
    }
    if (m.Type != null && m.hasOwnProperty('Type')) {
      d.Type = o.enums === String ? $root.Data.DataType[m.Type] : m.Type;
    }
    if (m.Data != null && m.hasOwnProperty('Data')) {
      d.Data = o.bytes === String ? $util.base64.encode(m.Data, 0, m.Data.length) : o.bytes === Array ? Array.prototype.slice.call(m.Data) : m.Data;
    }
    if (m.filesize != null && m.hasOwnProperty('filesize')) {
      if (typeof m.filesize === 'number')
        d.filesize = o.longs === String ? String(m.filesize) : m.filesize;
      else
        d.filesize = o.longs === String ? $util.Long.prototype.toString.call(m.filesize) : o.longs === Number ? new $util.LongBits(m.filesize.low >>> 0, m.filesize.high >>> 0).toNumber(true) : m.filesize;
    }
    if (m.blocksizes && m.blocksizes.length) {
      d.blocksizes = [];
      for (var j = 0; j < m.blocksizes.length; ++j) {
        if (typeof m.blocksizes[j] === 'number')
          d.blocksizes[j] = o.longs === String ? String(m.blocksizes[j]) : m.blocksizes[j];
        else
          d.blocksizes[j] = o.longs === String ? $util.Long.prototype.toString.call(m.blocksizes[j]) : o.longs === Number ? new $util.LongBits(m.blocksizes[j].low >>> 0, m.blocksizes[j].high >>> 0).toNumber(true) : m.blocksizes[j];
      }
    }
    if (m.hashType != null && m.hasOwnProperty('hashType')) {
      if (typeof m.hashType === 'number')
        d.hashType = o.longs === String ? String(m.hashType) : m.hashType;
      else
        d.hashType = o.longs === String ? $util.Long.prototype.toString.call(m.hashType) : o.longs === Number ? new $util.LongBits(m.hashType.low >>> 0, m.hashType.high >>> 0).toNumber(true) : m.hashType;
    }
    if (m.fanout != null && m.hasOwnProperty('fanout')) {
      if (typeof m.fanout === 'number')
        d.fanout = o.longs === String ? String(m.fanout) : m.fanout;
      else
        d.fanout = o.longs === String ? $util.Long.prototype.toString.call(m.fanout) : o.longs === Number ? new $util.LongBits(m.fanout.low >>> 0, m.fanout.high >>> 0).toNumber(true) : m.fanout;
    }
    if (m.mode != null && m.hasOwnProperty('mode')) {
      d.mode = m.mode;
    }
    if (m.mtime != null && m.hasOwnProperty('mtime')) {
      d.mtime = $root.UnixTime.toObject(m.mtime, o);
    }
    return d;
  };
  Data.prototype.toJSON = function toJSON() {
    return this.constructor.toObject(this, minimal.util.toJSONOptions);
  };
  Data.DataType = function () {
    const valuesById = {}, values = Object.create(valuesById);
    values[valuesById[0] = 'Raw'] = 0;
    values[valuesById[1] = 'Directory'] = 1;
    values[valuesById[2] = 'File'] = 2;
    values[valuesById[3] = 'Metadata'] = 3;
    values[valuesById[4] = 'Symlink'] = 4;
    values[valuesById[5] = 'HAMTShard'] = 5;
    return values;
  }();
  return Data;
})();
const UnixTime = $root.UnixTime = (() => {
  function UnixTime(p) {
    if (p)
      for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
        if (p[ks[i]] != null)
          this[ks[i]] = p[ks[i]];
  }
  UnixTime.prototype.Seconds = $util.Long ? $util.Long.fromBits(0, 0, false) : 0;
  UnixTime.prototype.FractionalNanoseconds = 0;
  UnixTime.encode = function encode(m, w) {
    if (!w)
      w = $Writer.create();
    w.uint32(8).int64(m.Seconds);
    if (m.FractionalNanoseconds != null && Object.hasOwnProperty.call(m, 'FractionalNanoseconds'))
      w.uint32(21).fixed32(m.FractionalNanoseconds);
    return w;
  };
  UnixTime.decode = function decode(r, l) {
    if (!(r instanceof $Reader))
      r = $Reader.create(r);
    var c = l === undefined ? r.len : r.pos + l, m = new $root.UnixTime();
    while (r.pos < c) {
      var t = r.uint32();
      switch (t >>> 3) {
      case 1:
        m.Seconds = r.int64();
        break;
      case 2:
        m.FractionalNanoseconds = r.fixed32();
        break;
      default:
        r.skipType(t & 7);
        break;
      }
    }
    if (!m.hasOwnProperty('Seconds'))
      throw $util.ProtocolError('missing required \'Seconds\'', { instance: m });
    return m;
  };
  UnixTime.fromObject = function fromObject(d) {
    if (d instanceof $root.UnixTime)
      return d;
    var m = new $root.UnixTime();
    if (d.Seconds != null) {
      if ($util.Long)
        (m.Seconds = $util.Long.fromValue(d.Seconds)).unsigned = false;
      else if (typeof d.Seconds === 'string')
        m.Seconds = parseInt(d.Seconds, 10);
      else if (typeof d.Seconds === 'number')
        m.Seconds = d.Seconds;
      else if (typeof d.Seconds === 'object')
        m.Seconds = new $util.LongBits(d.Seconds.low >>> 0, d.Seconds.high >>> 0).toNumber();
    }
    if (d.FractionalNanoseconds != null) {
      m.FractionalNanoseconds = d.FractionalNanoseconds >>> 0;
    }
    return m;
  };
  UnixTime.toObject = function toObject(m, o) {
    if (!o)
      o = {};
    var d = {};
    if (o.defaults) {
      if ($util.Long) {
        var n = new $util.Long(0, 0, false);
        d.Seconds = o.longs === String ? n.toString() : o.longs === Number ? n.toNumber() : n;
      } else
        d.Seconds = o.longs === String ? '0' : 0;
      d.FractionalNanoseconds = 0;
    }
    if (m.Seconds != null && m.hasOwnProperty('Seconds')) {
      if (typeof m.Seconds === 'number')
        d.Seconds = o.longs === String ? String(m.Seconds) : m.Seconds;
      else
        d.Seconds = o.longs === String ? $util.Long.prototype.toString.call(m.Seconds) : o.longs === Number ? new $util.LongBits(m.Seconds.low >>> 0, m.Seconds.high >>> 0).toNumber() : m.Seconds;
    }
    if (m.FractionalNanoseconds != null && m.hasOwnProperty('FractionalNanoseconds')) {
      d.FractionalNanoseconds = m.FractionalNanoseconds;
    }
    return d;
  };
  UnixTime.prototype.toJSON = function toJSON() {
    return this.constructor.toObject(this, minimal.util.toJSONOptions);
  };
  return UnixTime;
})();
const Metadata = $root.Metadata = (() => {
  function Metadata(p) {
    if (p)
      for (var ks = Object.keys(p), i = 0; i < ks.length; ++i)
        if (p[ks[i]] != null)
          this[ks[i]] = p[ks[i]];
  }
  Metadata.prototype.MimeType = '';
  Metadata.encode = function encode(m, w) {
    if (!w)
      w = $Writer.create();
    if (m.MimeType != null && Object.hasOwnProperty.call(m, 'MimeType'))
      w.uint32(10).string(m.MimeType);
    return w;
  };
  Metadata.decode = function decode(r, l) {
    if (!(r instanceof $Reader))
      r = $Reader.create(r);
    var c = l === undefined ? r.len : r.pos + l, m = new $root.Metadata();
    while (r.pos < c) {
      var t = r.uint32();
      switch (t >>> 3) {
      case 1:
        m.MimeType = r.string();
        break;
      default:
        r.skipType(t & 7);
        break;
      }
    }
    return m;
  };
  Metadata.fromObject = function fromObject(d) {
    if (d instanceof $root.Metadata)
      return d;
    var m = new $root.Metadata();
    if (d.MimeType != null) {
      m.MimeType = String(d.MimeType);
    }
    return m;
  };
  Metadata.toObject = function toObject(m, o) {
    if (!o)
      o = {};
    var d = {};
    if (o.defaults) {
      d.MimeType = '';
    }
    if (m.MimeType != null && m.hasOwnProperty('MimeType')) {
      d.MimeType = m.MimeType;
    }
    return d;
  };
  Metadata.prototype.toJSON = function toJSON() {
    return this.constructor.toObject(this, minimal.util.toJSONOptions);
  };
  return Metadata;
})();

;// CONCATENATED MODULE: ./node_modules/ipfs-unixfs/esm/src/index.js


const PBData = Data;
const types = [
  'raw',
  'directory',
  'file',
  'metadata',
  'symlink',
  'hamt-sharded-directory'
];
const dirTypes = [
  'directory',
  'hamt-sharded-directory'
];
const DEFAULT_FILE_MODE = parseInt('0644', 8);
const DEFAULT_DIRECTORY_MODE = parseInt('0755', 8);
function parseMode(mode) {
  if (mode == null) {
    return undefined;
  }
  if (typeof mode === 'number') {
    return mode & 4095;
  }
  mode = mode.toString();
  if (mode.substring(0, 1) === '0') {
    return parseInt(mode, 8) & 4095;
  }
  return parseInt(mode, 10) & 4095;
}
function parseMtime(input) {
  if (input == null) {
    return undefined;
  }
  let mtime;
  if (input.secs != null) {
    mtime = {
      secs: input.secs,
      nsecs: input.nsecs
    };
  }
  if (input.Seconds != null) {
    mtime = {
      secs: input.Seconds,
      nsecs: input.FractionalNanoseconds
    };
  }
  if (Array.isArray(input)) {
    mtime = {
      secs: input[0],
      nsecs: input[1]
    };
  }
  if (input instanceof Date) {
    const ms = input.getTime();
    const secs = Math.floor(ms / 1000);
    mtime = {
      secs: secs,
      nsecs: (ms - secs * 1000) * 1000
    };
  }
  if (!Object.prototype.hasOwnProperty.call(mtime, 'secs')) {
    return undefined;
  }
  if (mtime != null && mtime.nsecs != null && (mtime.nsecs < 0 || mtime.nsecs > 999999999)) {
    throw err_code(new Error('mtime-nsecs must be within the range [0,999999999]'), 'ERR_INVALID_MTIME_NSECS');
  }
  return mtime;
}
class UnixFS {
  static unmarshal(marshaled) {
    const message = PBData.decode(marshaled);
    const decoded = PBData.toObject(message, {
      defaults: false,
      arrays: true,
      longs: Number,
      objects: false
    });
    const data = new UnixFS({
      type: types[decoded.Type],
      data: decoded.Data,
      blockSizes: decoded.blocksizes,
      mode: decoded.mode,
      mtime: decoded.mtime ? {
        secs: decoded.mtime.Seconds,
        nsecs: decoded.mtime.FractionalNanoseconds
      } : undefined
    });
    data._originalMode = decoded.mode || 0;
    return data;
  }
  constructor(options = { type: 'file' }) {
    const {type, data, blockSizes, hashType, fanout, mtime, mode} = options;
    if (type && !types.includes(type)) {
      throw err_code(new Error('Type: ' + type + ' is not valid'), 'ERR_INVALID_TYPE');
    }
    this.type = type || 'file';
    this.data = data;
    this.hashType = hashType;
    this.fanout = fanout;
    this.blockSizes = blockSizes || [];
    this._originalMode = 0;
    this.mode = parseMode(mode);
    if (mtime) {
      this.mtime = parseMtime(mtime);
      if (this.mtime && !this.mtime.nsecs) {
        this.mtime.nsecs = 0;
      }
    }
  }
  set mode(mode) {
    this._mode = this.isDirectory() ? DEFAULT_DIRECTORY_MODE : DEFAULT_FILE_MODE;
    const parsedMode = parseMode(mode);
    if (parsedMode !== undefined) {
      this._mode = parsedMode;
    }
  }
  get mode() {
    return this._mode;
  }
  isDirectory() {
    return Boolean(this.type && dirTypes.includes(this.type));
  }
  addBlockSize(size) {
    this.blockSizes.push(size);
  }
  removeBlockSize(index) {
    this.blockSizes.splice(index, 1);
  }
  fileSize() {
    if (this.isDirectory()) {
      return 0;
    }
    let sum = 0;
    this.blockSizes.forEach(size => {
      sum += size;
    });
    if (this.data) {
      sum += this.data.length;
    }
    return sum;
  }
  marshal() {
    let type;
    switch (this.type) {
    case 'raw':
      type = PBData.DataType.Raw;
      break;
    case 'directory':
      type = PBData.DataType.Directory;
      break;
    case 'file':
      type = PBData.DataType.File;
      break;
    case 'metadata':
      type = PBData.DataType.Metadata;
      break;
    case 'symlink':
      type = PBData.DataType.Symlink;
      break;
    case 'hamt-sharded-directory':
      type = PBData.DataType.HAMTShard;
      break;
    default:
      throw err_code(new Error('Type: ' + type + ' is not valid'), 'ERR_INVALID_TYPE');
    }
    let data = this.data;
    if (!this.data || !this.data.length) {
      data = undefined;
    }
    let mode;
    if (this.mode != null) {
      mode = this._originalMode & 4294963200 | (parseMode(this.mode) || 0);
      if (mode === DEFAULT_FILE_MODE && !this.isDirectory()) {
        mode = undefined;
      }
      if (mode === DEFAULT_DIRECTORY_MODE && this.isDirectory()) {
        mode = undefined;
      }
    }
    let mtime;
    if (this.mtime != null) {
      const parsed = parseMtime(this.mtime);
      if (parsed) {
        mtime = {
          Seconds: parsed.secs,
          FractionalNanoseconds: parsed.nsecs
        };
        if (mtime.FractionalNanoseconds === 0) {
          delete mtime.FractionalNanoseconds;
        }
      }
    }
    const pbData = {
      Type: type,
      Data: data,
      filesize: this.isDirectory() ? undefined : this.fileSize(),
      blocksizes: this.blockSizes,
      hashType: this.hashType,
      fanout: this.fanout,
      mode,
      mtime
    };
    return PBData.encode(pbData).finish();
  }
}

;// CONCATENATED MODULE: ./node_modules/ipfs-unixfs-importer/esm/src/utils/persist.js



const persist = async (buffer, blockstore, options) => {
  if (!options.codec) {
    options.codec = esm_src_namespaceObject;
  }
  if (!options.hasher) {
    options.hasher = sha256;
  }
  if (options.cidVersion === undefined) {
    options.cidVersion = 1;
  }
  if (options.codec === esm_src_namespaceObject && options.hasher !== sha256) {
    options.cidVersion = 1;
  }
  const multihash = await options.hasher.digest(buffer);
  const cid = cid_CID.create(options.cidVersion, options.codec.code, multihash);
  if (!options.onlyHash) {
    await blockstore.put(cid, buffer, { signal: options.signal });
  }
  return cid;
};
/* harmony default export */ const utils_persist = (persist);
;// CONCATENATED MODULE: ./node_modules/ipfs-unixfs-importer/esm/src/dag-builder/dir.js



const dirBuilder = async (item, blockstore, options) => {
  const unixfs = new UnixFS({
    type: 'directory',
    mtime: item.mtime,
    mode: item.mode
  });
  const buffer = src_encode(prepare({ Data: unixfs.marshal() }));
  const cid = await utils_persist(buffer, blockstore, options);
  const path = item.path;
  return {
    cid,
    path,
    unixfs,
    size: buffer.length
  };
};
/* harmony default export */ const dag_builder_dir = (dirBuilder);
// EXTERNAL MODULE: ./node_modules/it-all/index.js
var it_all = __webpack_require__(44279);
;// CONCATENATED MODULE: ./node_modules/ipfs-unixfs-importer/esm/src/dag-builder/file/flat.js

async function flat(source, reduce) {
  return reduce(await it_all(source));
}
/* harmony default export */ const file_flat = (flat);
// EXTERNAL MODULE: ./node_modules/it-batch/index.js
var it_batch = __webpack_require__(40783);
;// CONCATENATED MODULE: ./node_modules/ipfs-unixfs-importer/esm/src/dag-builder/file/balanced.js

function balanced(source, reduce, options) {
  return reduceToParents(source, reduce, options);
}
async function reduceToParents(source, reduce, options) {
  const roots = [];
  for await (const chunked of it_batch(source, options.maxChildrenPerNode)) {
    roots.push(await reduce(chunked));
  }
  if (roots.length > 1) {
    return reduceToParents(roots, reduce, options);
  }
  return roots[0];
}
/* harmony default export */ const file_balanced = (balanced);
;// CONCATENATED MODULE: ./node_modules/ipfs-unixfs-importer/esm/src/dag-builder/file/trickle.js

async function trickleStream(source, reduce, options) {
  const root = new Root(options.layerRepeat);
  let iteration = 0;
  let maxDepth = 1;
  let subTree = root;
  for await (const layer of it_batch(source, options.maxChildrenPerNode)) {
    if (subTree.isFull()) {
      if (subTree !== root) {
        root.addChild(await subTree.reduce(reduce));
      }
      if (iteration && iteration % options.layerRepeat === 0) {
        maxDepth++;
      }
      subTree = new SubTree(maxDepth, options.layerRepeat, iteration);
      iteration++;
    }
    subTree.append(layer);
  }
  if (subTree && subTree !== root) {
    root.addChild(await subTree.reduce(reduce));
  }
  return root.reduce(reduce);
}
/* harmony default export */ const trickle = (trickleStream);
class SubTree {
  constructor(maxDepth, layerRepeat, iteration = 0) {
    this.maxDepth = maxDepth;
    this.layerRepeat = layerRepeat;
    this.currentDepth = 1;
    this.iteration = iteration;
    this.root = this.node = this.parent = {
      children: [],
      depth: this.currentDepth,
      maxDepth,
      maxChildren: (this.maxDepth - this.currentDepth) * this.layerRepeat
    };
  }
  isFull() {
    if (!this.root.data) {
      return false;
    }
    if (this.currentDepth < this.maxDepth && this.node.maxChildren) {
      this._addNextNodeToParent(this.node);
      return false;
    }
    const distantRelative = this._findParent(this.node, this.currentDepth);
    if (distantRelative) {
      this._addNextNodeToParent(distantRelative);
      return false;
    }
    return true;
  }
  _addNextNodeToParent(parent) {
    this.parent = parent;
    const nextNode = {
      children: [],
      depth: parent.depth + 1,
      parent,
      maxDepth: this.maxDepth,
      maxChildren: Math.floor(parent.children.length / this.layerRepeat) * this.layerRepeat
    };
    parent.children.push(nextNode);
    this.currentDepth = nextNode.depth;
    this.node = nextNode;
  }
  append(layer) {
    this.node.data = layer;
  }
  reduce(reduce) {
    return this._reduce(this.root, reduce);
  }
  async _reduce(node, reduce) {
    let children = [];
    if (node.children.length) {
      children = await Promise.all(node.children.filter(child => child.data).map(child => this._reduce(child, reduce)));
    }
    return reduce((node.data || []).concat(children));
  }
  _findParent(node, depth) {
    const parent = node.parent;
    if (!parent || parent.depth === 0) {
      return;
    }
    if (parent.children.length === parent.maxChildren || !parent.maxChildren) {
      return this._findParent(parent, depth);
    }
    return parent;
  }
}
class Root extends SubTree {
  constructor(layerRepeat) {
    super(0, layerRepeat);
    this.root.depth = 0;
    this.currentDepth = 1;
  }
  addChild(child) {
    this.root.children.push(child);
  }
  reduce(reduce) {
    return reduce((this.root.data || []).concat(this.root.children));
  }
}
;// CONCATENATED MODULE: ./node_modules/ipfs-unixfs-importer/esm/src/dag-builder/file/buffer-importer.js




async function* bufferImporter(file, block, options) {
  for await (let buffer of file.content) {
    yield async () => {
      options.progress(buffer.length, file.path);
      let unixfs;
      const opts = {
        codec: esm_src_namespaceObject,
        cidVersion: options.cidVersion,
        hasher: options.hasher,
        onlyHash: options.onlyHash
      };
      if (options.rawLeaves) {
        opts.codec = raw_namespaceObject;
        opts.cidVersion = 1;
      } else {
        unixfs = new UnixFS({
          type: options.leafType,
          data: buffer
        });
        buffer = src_encode({
          Data: unixfs.marshal(),
          Links: []
        });
      }
      return {
        cid: await utils_persist(buffer, block, opts),
        unixfs,
        size: buffer.length
      };
    };
  }
}
/* harmony default export */ const buffer_importer = (bufferImporter);
;// CONCATENATED MODULE: ./node_modules/ipfs-unixfs-importer/esm/src/dag-builder/file/index.js











const dagBuilders = {
  flat: file_flat,
  balanced: file_balanced,
  trickle: trickle
};
async function* buildFileBatch(file, blockstore, options) {
  let count = -1;
  let previous;
  let bufferImporter;
  if (typeof options.bufferImporter === 'function') {
    bufferImporter = options.bufferImporter;
  } else {
    bufferImporter = buffer_importer;
  }
  for await (const entry of it_parallel_batch(bufferImporter(file, blockstore, options), options.blockWriteConcurrency)) {
    count++;
    if (count === 0) {
      previous = entry;
      continue;
    } else if (count === 1 && previous) {
      yield previous;
      previous = null;
    }
    yield entry;
  }
  if (previous) {
    previous.single = true;
    yield previous;
  }
}
const file_reduce = (file, blockstore, options) => {
  async function reducer(leaves) {
    if (leaves.length === 1 && leaves[0].single && options.reduceSingleLeafToSelf) {
      const leaf = leaves[0];
      if (file.mtime !== undefined || file.mode !== undefined) {
        let buffer = await blockstore.get(leaf.cid);
        leaf.unixfs = new UnixFS({
          type: 'file',
          mtime: file.mtime,
          mode: file.mode,
          data: buffer
        });
        buffer = src_encode(prepare({ Data: leaf.unixfs.marshal() }));
        leaf.cid = await utils_persist(buffer, blockstore, {
          ...options,
          codec: esm_src_namespaceObject,
          hasher: options.hasher,
          cidVersion: options.cidVersion
        });
        leaf.size = buffer.length;
      }
      return {
        cid: leaf.cid,
        path: file.path,
        unixfs: leaf.unixfs,
        size: leaf.size
      };
    }
    const f = new UnixFS({
      type: 'file',
      mtime: file.mtime,
      mode: file.mode
    });
    const links = leaves.filter(leaf => {
      if (leaf.cid.code === raw_code && leaf.size) {
        return true;
      }
      if (leaf.unixfs && !leaf.unixfs.data && leaf.unixfs.fileSize()) {
        return true;
      }
      return Boolean(leaf.unixfs && leaf.unixfs.data && leaf.unixfs.data.length);
    }).map(leaf => {
      if (leaf.cid.code === raw_code) {
        f.addBlockSize(leaf.size);
        return {
          Name: '',
          Tsize: leaf.size,
          Hash: leaf.cid
        };
      }
      if (!leaf.unixfs || !leaf.unixfs.data) {
        f.addBlockSize(leaf.unixfs && leaf.unixfs.fileSize() || 0);
      } else {
        f.addBlockSize(leaf.unixfs.data.length);
      }
      return {
        Name: '',
        Tsize: leaf.size,
        Hash: leaf.cid
      };
    });
    const node = {
      Data: f.marshal(),
      Links: links
    };
    const buffer = src_encode(prepare(node));
    const cid = await utils_persist(buffer, blockstore, options);
    return {
      cid,
      path: file.path,
      unixfs: f,
      size: buffer.length + node.Links.reduce((acc, curr) => acc + curr.Tsize, 0)
    };
  }
  return reducer;
};
function fileBuilder(file, block, options) {
  const dagBuilder = dagBuilders[options.strategy];
  if (!dagBuilder) {
    throw err_code(new Error(`Unknown importer build strategy name: ${ options.strategy }`), 'ERR_BAD_STRATEGY');
  }
  return dagBuilder(buildFileBatch(file, block, options), file_reduce(file, block, options), options);
}
/* harmony default export */ const dag_builder_file = (fileBuilder);
// EXTERNAL MODULE: ./node_modules/bl/BufferList.js
var BufferList = __webpack_require__(31967);
// EXTERNAL MODULE: ./node_modules/rabin-wasm/src/index.js
var rabin_wasm_src = __webpack_require__(67893);
;// CONCATENATED MODULE: ./node_modules/ipfs-unixfs-importer/esm/src/chunker/rabin.js



async function* rabinChunker(source, options) {
  let min, max, avg;
  if (options.minChunkSize && options.maxChunkSize && options.avgChunkSize) {
    avg = options.avgChunkSize;
    min = options.minChunkSize;
    max = options.maxChunkSize;
  } else if (!options.avgChunkSize) {
    throw err_code(new Error('please specify an average chunk size'), 'ERR_INVALID_AVG_CHUNK_SIZE');
  } else {
    avg = options.avgChunkSize;
    min = avg / 3;
    max = avg + avg / 2;
  }
  if (min < 16) {
    throw err_code(new Error('rabin min must be greater than 16'), 'ERR_INVALID_MIN_CHUNK_SIZE');
  }
  if (max < min) {
    max = min;
  }
  if (avg < min) {
    avg = min;
  }
  const sizepow = Math.floor(Math.log2(avg));
  for await (const chunk of rabin_rabin(source, {
      min: min,
      max: max,
      bits: sizepow,
      window: options.window,
      polynomial: options.polynomial
    })) {
    yield chunk;
  }
}
/* harmony default export */ const rabin = (rabinChunker);
async function* rabin_rabin(source, options) {
  const r = await (0,rabin_wasm_src.create)(options.bits, options.min, options.max, options.window);
  const buffers = new BufferList();
  for await (const chunk of source) {
    buffers.append(chunk);
    const sizes = r.fingerprint(chunk);
    for (let i = 0; i < sizes.length; i++) {
      const size = sizes[i];
      const buf = buffers.slice(0, size);
      buffers.consume(size);
      yield buf;
    }
  }
  if (buffers.length) {
    yield buffers.slice(0);
  }
}
;// CONCATENATED MODULE: ./node_modules/ipfs-unixfs-importer/esm/src/chunker/fixed-size.js

async function* fixedSizeChunker(source, options) {
  let bl = new BufferList();
  let currentLength = 0;
  let emitted = false;
  const maxChunkSize = options.maxChunkSize;
  for await (const buffer of source) {
    bl.append(buffer);
    currentLength += buffer.length;
    while (currentLength >= maxChunkSize) {
      yield bl.slice(0, maxChunkSize);
      emitted = true;
      if (maxChunkSize === bl.length) {
        bl = new BufferList();
        currentLength = 0;
      } else {
        const newBl = new BufferList();
        newBl.append(bl.shallowSlice(maxChunkSize));
        bl = newBl;
        currentLength -= maxChunkSize;
      }
    }
  }
  if (!emitted || currentLength) {
    yield bl.slice(0, currentLength);
  }
}
/* harmony default export */ const fixed_size = (fixedSizeChunker);
;// CONCATENATED MODULE: ./node_modules/multiformats/esm/src/bases/identity.js


const identity = from({
  prefix: '\0',
  name: 'identity',
  encode: buf => bytes_toString(buf),
  decode: str => fromString(str)
});
;// CONCATENATED MODULE: ./node_modules/multiformats/esm/src/bases/base2.js

const base2 = rfc4648({
  prefix: '0',
  name: 'base2',
  alphabet: '01',
  bitsPerChar: 1
});
;// CONCATENATED MODULE: ./node_modules/multiformats/esm/src/bases/base8.js

const base8 = rfc4648({
  prefix: '7',
  name: 'base8',
  alphabet: '01234567',
  bitsPerChar: 3
});
;// CONCATENATED MODULE: ./node_modules/multiformats/esm/src/bases/base10.js

const base10 = baseX({
  prefix: '9',
  name: 'base10',
  alphabet: '0123456789'
});
;// CONCATENATED MODULE: ./node_modules/multiformats/esm/src/bases/base16.js

const base16 = rfc4648({
  prefix: 'f',
  name: 'base16',
  alphabet: '0123456789abcdef',
  bitsPerChar: 4
});
const base16upper = rfc4648({
  prefix: 'F',
  name: 'base16upper',
  alphabet: '0123456789ABCDEF',
  bitsPerChar: 4
});
;// CONCATENATED MODULE: ./node_modules/multiformats/esm/src/bases/base36.js

const base36 = baseX({
  prefix: 'k',
  name: 'base36',
  alphabet: '0123456789abcdefghijklmnopqrstuvwxyz'
});
const base36upper = baseX({
  prefix: 'K',
  name: 'base36upper',
  alphabet: '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
});
;// CONCATENATED MODULE: ./node_modules/multiformats/esm/src/bases/base64.js

const base64 = rfc4648({
  prefix: 'm',
  name: 'base64',
  alphabet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
  bitsPerChar: 6
});
const base64pad = rfc4648({
  prefix: 'M',
  name: 'base64pad',
  alphabet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=',
  bitsPerChar: 6
});
const base64url = rfc4648({
  prefix: 'u',
  name: 'base64url',
  alphabet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
  bitsPerChar: 6
});
const base64urlpad = rfc4648({
  prefix: 'U',
  name: 'base64urlpad',
  alphabet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=',
  bitsPerChar: 6
});
;// CONCATENATED MODULE: ./node_modules/multiformats/esm/src/bases/base256emoji.js

const alphabet = Array.from('\uD83D\uDE80\uD83E\uDE90\u2604\uD83D\uDEF0\uD83C\uDF0C\uD83C\uDF11\uD83C\uDF12\uD83C\uDF13\uD83C\uDF14\uD83C\uDF15\uD83C\uDF16\uD83C\uDF17\uD83C\uDF18\uD83C\uDF0D\uD83C\uDF0F\uD83C\uDF0E\uD83D\uDC09\u2600\uD83D\uDCBB\uD83D\uDDA5\uD83D\uDCBE\uD83D\uDCBF\uD83D\uDE02\u2764\uD83D\uDE0D\uD83E\uDD23\uD83D\uDE0A\uD83D\uDE4F\uD83D\uDC95\uD83D\uDE2D\uD83D\uDE18\uD83D\uDC4D\uD83D\uDE05\uD83D\uDC4F\uD83D\uDE01\uD83D\uDD25\uD83E\uDD70\uD83D\uDC94\uD83D\uDC96\uD83D\uDC99\uD83D\uDE22\uD83E\uDD14\uD83D\uDE06\uD83D\uDE44\uD83D\uDCAA\uD83D\uDE09\u263A\uD83D\uDC4C\uD83E\uDD17\uD83D\uDC9C\uD83D\uDE14\uD83D\uDE0E\uD83D\uDE07\uD83C\uDF39\uD83E\uDD26\uD83C\uDF89\uD83D\uDC9E\u270C\u2728\uD83E\uDD37\uD83D\uDE31\uD83D\uDE0C\uD83C\uDF38\uD83D\uDE4C\uD83D\uDE0B\uD83D\uDC97\uD83D\uDC9A\uD83D\uDE0F\uD83D\uDC9B\uD83D\uDE42\uD83D\uDC93\uD83E\uDD29\uD83D\uDE04\uD83D\uDE00\uD83D\uDDA4\uD83D\uDE03\uD83D\uDCAF\uD83D\uDE48\uD83D\uDC47\uD83C\uDFB6\uD83D\uDE12\uD83E\uDD2D\u2763\uD83D\uDE1C\uD83D\uDC8B\uD83D\uDC40\uD83D\uDE2A\uD83D\uDE11\uD83D\uDCA5\uD83D\uDE4B\uD83D\uDE1E\uD83D\uDE29\uD83D\uDE21\uD83E\uDD2A\uD83D\uDC4A\uD83E\uDD73\uD83D\uDE25\uD83E\uDD24\uD83D\uDC49\uD83D\uDC83\uD83D\uDE33\u270B\uD83D\uDE1A\uD83D\uDE1D\uD83D\uDE34\uD83C\uDF1F\uD83D\uDE2C\uD83D\uDE43\uD83C\uDF40\uD83C\uDF37\uD83D\uDE3B\uD83D\uDE13\u2B50\u2705\uD83E\uDD7A\uD83C\uDF08\uD83D\uDE08\uD83E\uDD18\uD83D\uDCA6\u2714\uD83D\uDE23\uD83C\uDFC3\uD83D\uDC90\u2639\uD83C\uDF8A\uD83D\uDC98\uD83D\uDE20\u261D\uD83D\uDE15\uD83C\uDF3A\uD83C\uDF82\uD83C\uDF3B\uD83D\uDE10\uD83D\uDD95\uD83D\uDC9D\uD83D\uDE4A\uD83D\uDE39\uD83D\uDDE3\uD83D\uDCAB\uD83D\uDC80\uD83D\uDC51\uD83C\uDFB5\uD83E\uDD1E\uD83D\uDE1B\uD83D\uDD34\uD83D\uDE24\uD83C\uDF3C\uD83D\uDE2B\u26BD\uD83E\uDD19\u2615\uD83C\uDFC6\uD83E\uDD2B\uD83D\uDC48\uD83D\uDE2E\uD83D\uDE46\uD83C\uDF7B\uD83C\uDF43\uD83D\uDC36\uD83D\uDC81\uD83D\uDE32\uD83C\uDF3F\uD83E\uDDE1\uD83C\uDF81\u26A1\uD83C\uDF1E\uD83C\uDF88\u274C\u270A\uD83D\uDC4B\uD83D\uDE30\uD83E\uDD28\uD83D\uDE36\uD83E\uDD1D\uD83D\uDEB6\uD83D\uDCB0\uD83C\uDF53\uD83D\uDCA2\uD83E\uDD1F\uD83D\uDE41\uD83D\uDEA8\uD83D\uDCA8\uD83E\uDD2C\u2708\uD83C\uDF80\uD83C\uDF7A\uD83E\uDD13\uD83D\uDE19\uD83D\uDC9F\uD83C\uDF31\uD83D\uDE16\uD83D\uDC76\uD83E\uDD74\u25B6\u27A1\u2753\uD83D\uDC8E\uD83D\uDCB8\u2B07\uD83D\uDE28\uD83C\uDF1A\uD83E\uDD8B\uD83D\uDE37\uD83D\uDD7A\u26A0\uD83D\uDE45\uD83D\uDE1F\uD83D\uDE35\uD83D\uDC4E\uD83E\uDD32\uD83E\uDD20\uD83E\uDD27\uD83D\uDCCC\uD83D\uDD35\uD83D\uDC85\uD83E\uDDD0\uD83D\uDC3E\uD83C\uDF52\uD83D\uDE17\uD83E\uDD11\uD83C\uDF0A\uD83E\uDD2F\uD83D\uDC37\u260E\uD83D\uDCA7\uD83D\uDE2F\uD83D\uDC86\uD83D\uDC46\uD83C\uDFA4\uD83D\uDE47\uD83C\uDF51\u2744\uD83C\uDF34\uD83D\uDCA3\uD83D\uDC38\uD83D\uDC8C\uD83D\uDCCD\uD83E\uDD40\uD83E\uDD22\uD83D\uDC45\uD83D\uDCA1\uD83D\uDCA9\uD83D\uDC50\uD83D\uDCF8\uD83D\uDC7B\uD83E\uDD10\uD83E\uDD2E\uD83C\uDFBC\uD83E\uDD75\uD83D\uDEA9\uD83C\uDF4E\uD83C\uDF4A\uD83D\uDC7C\uD83D\uDC8D\uD83D\uDCE3\uD83E\uDD42');
const alphabetBytesToChars = alphabet.reduce((p, c, i) => {
  p[i] = c;
  return p;
}, []);
const alphabetCharsToBytes = alphabet.reduce((p, c, i) => {
  p[c.codePointAt(0)] = i;
  return p;
}, []);
function base256emoji_encode(data) {
  return data.reduce((p, c) => {
    p += alphabetBytesToChars[c];
    return p;
  }, '');
}
function base256emoji_decode(str) {
  const byts = [];
  for (const char of str) {
    const byt = alphabetCharsToBytes[char.codePointAt(0)];
    if (byt === undefined) {
      throw new Error(`Non-base256emoji character: ${ char }`);
    }
    byts.push(byt);
  }
  return new Uint8Array(byts);
}
const base256emoji = from({
  prefix: '\uD83D\uDE80',
  name: 'base256emoji',
  encode: base256emoji_encode,
  decode: base256emoji_decode
});
;// CONCATENATED MODULE: ./node_modules/multiformats/esm/src/hashes/identity.js


const identity_code = 0;
const identity_name = 'identity';
const identity_encode = coerce;
const digest = input => create(identity_code, identity_encode(input));
const identity_identity = {
  code: identity_code,
  name: identity_name,
  encode: identity_encode,
  digest
};
;// CONCATENATED MODULE: ./node_modules/multiformats/esm/src/codecs/json.js
const json_textEncoder = new TextEncoder();
const json_textDecoder = new TextDecoder();
const json_name = 'json';
const json_code = 512;
const json_encode = node => json_textEncoder.encode(JSON.stringify(node));
const json_decode = data => JSON.parse(json_textDecoder.decode(data));
;// CONCATENATED MODULE: ./node_modules/multiformats/esm/src/basics.js















const bases = {
  ...identity_namespaceObject,
  ...base2_namespaceObject,
  ...base8_namespaceObject,
  ...base10_namespaceObject,
  ...base16_namespaceObject,
  ...base32_namespaceObject,
  ...base36_namespaceObject,
  ...base58_namespaceObject,
  ...base64_namespaceObject,
  ...base256emoji_namespaceObject
};
const hashes = {
  ...sha2_namespaceObject,
  ...hashes_identity_namespaceObject
};
const codecs = {
  raw: raw_namespaceObject,
  json: json_namespaceObject
};

;// CONCATENATED MODULE: ./node_modules/uint8arrays/esm/src/util/as-uint8array.js
function as_uint8array_asUint8Array(buf) {
  if (globalThis.Buffer != null) {
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  return buf;
}
;// CONCATENATED MODULE: ./node_modules/uint8arrays/esm/src/alloc.js

function alloc_alloc(size = 0) {
  if (globalThis.Buffer != null && globalThis.Buffer.alloc != null) {
    return asUint8Array(globalThis.Buffer.alloc(size));
  }
  return new Uint8Array(size);
}
function allocUnsafe(size = 0) {
  if (globalThis.Buffer != null && globalThis.Buffer.allocUnsafe != null) {
    return as_uint8array_asUint8Array(globalThis.Buffer.allocUnsafe(size));
  }
  return new Uint8Array(size);
}
;// CONCATENATED MODULE: ./node_modules/uint8arrays/esm/src/util/bases.js


function createCodec(name, prefix, encode, decode) {
  return {
    name,
    prefix,
    encoder: {
      name,
      prefix,
      encode
    },
    decoder: { decode }
  };
}
const string = createCodec('utf8', 'u', buf => {
  const decoder = new TextDecoder('utf8');
  return 'u' + decoder.decode(buf);
}, str => {
  const encoder = new TextEncoder();
  return encoder.encode(str.substring(1));
});
const ascii = createCodec('ascii', 'a', buf => {
  let string = 'a';
  for (let i = 0; i < buf.length; i++) {
    string += String.fromCharCode(buf[i]);
  }
  return string;
}, str => {
  str = str.substring(1);
  const buf = allocUnsafe(str.length);
  for (let i = 0; i < str.length; i++) {
    buf[i] = str.charCodeAt(i);
  }
  return buf;
});
const BASES = {
  utf8: string,
  'utf-8': string,
  hex: bases.base16,
  latin1: ascii,
  ascii: ascii,
  binary: ascii,
  ...bases
};
/* harmony default export */ const util_bases = (BASES);
;// CONCATENATED MODULE: ./node_modules/uint8arrays/esm/src/from-string.js


function from_string_fromString(string, encoding = 'utf8') {
  const base = util_bases[encoding];
  if (!base) {
    throw new Error(`Unsupported encoding "${ encoding }"`);
  }
  if ((encoding === 'utf8' || encoding === 'utf-8') && globalThis.Buffer != null && globalThis.Buffer.from != null) {
    return as_uint8array_asUint8Array(globalThis.Buffer.from(string, 'utf-8'));
  }
  return base.decoder.decode(`${ base.prefix }${ string }`);
}
;// CONCATENATED MODULE: ./node_modules/ipfs-unixfs-importer/esm/src/dag-builder/validate-chunks.js


async function* validateChunks(source) {
  for await (const content of source) {
    if (content.length === undefined) {
      throw err_code(new Error('Content was invalid'), 'ERR_INVALID_CONTENT');
    }
    if (typeof content === 'string' || content instanceof String) {
      yield from_string_fromString(content.toString());
    } else if (Array.isArray(content)) {
      yield Uint8Array.from(content);
    } else if (content instanceof Uint8Array) {
      yield content;
    } else {
      throw err_code(new Error('Content was invalid'), 'ERR_INVALID_CONTENT');
    }
  }
}
/* harmony default export */ const validate_chunks = (validateChunks);
;// CONCATENATED MODULE: ./node_modules/ipfs-unixfs-importer/esm/src/dag-builder/index.js






function isIterable(thing) {
  return Symbol.iterator in thing;
}
function isAsyncIterable(thing) {
  return Symbol.asyncIterator in thing;
}
function contentAsAsyncIterable(content) {
  try {
    if (content instanceof Uint8Array) {
      return async function* () {
        yield content;
      }();
    } else if (isIterable(content)) {
      return async function* () {
        yield* content;
      }();
    } else if (isAsyncIterable(content)) {
      return content;
    }
  } catch {
    throw err_code(new Error('Content was invalid'), 'ERR_INVALID_CONTENT');
  }
  throw err_code(new Error('Content was invalid'), 'ERR_INVALID_CONTENT');
}
async function* dagBuilder(source, blockstore, options) {
  for await (const entry of source) {
    if (entry.path) {
      if (entry.path.substring(0, 2) === './') {
        options.wrapWithDirectory = true;
      }
      entry.path = entry.path.split('/').filter(path => path && path !== '.').join('/');
    }
    if (entry.content) {
      let chunker;
      if (typeof options.chunker === 'function') {
        chunker = options.chunker;
      } else if (options.chunker === 'rabin') {
        chunker = rabin;
      } else {
        chunker = fixed_size;
      }
      let chunkValidator;
      if (typeof options.chunkValidator === 'function') {
        chunkValidator = options.chunkValidator;
      } else {
        chunkValidator = validate_chunks;
      }
      const file = {
        path: entry.path,
        mtime: entry.mtime,
        mode: entry.mode,
        content: chunker(chunkValidator(contentAsAsyncIterable(entry.content), options), options)
      };
      yield () => dag_builder_file(file, blockstore, options);
    } else if (entry.path) {
      const dir = {
        path: entry.path,
        mtime: entry.mtime,
        mode: entry.mode
      };
      yield () => dag_builder_dir(dir, blockstore, options);
    } else {
      throw new Error('Import candidate must have content or path or both');
    }
  }
}
/* harmony default export */ const dag_builder = (dagBuilder);
;// CONCATENATED MODULE: ./node_modules/ipfs-unixfs-importer/esm/src/dir.js
class Dir {
  constructor(props, options) {
    this.options = options || {};
    this.root = props.root;
    this.dir = props.dir;
    this.path = props.path;
    this.dirty = props.dirty;
    this.flat = props.flat;
    this.parent = props.parent;
    this.parentKey = props.parentKey;
    this.unixfs = props.unixfs;
    this.mode = props.mode;
    this.mtime = props.mtime;
    this.cid = undefined;
    this.size = undefined;
  }
  async put(name, value) {
  }
  get(name) {
    return Promise.resolve(this);
  }
  async *eachChildSeries() {
  }
  async *flush(blockstore) {
  }
}
/* harmony default export */ const src_dir = (Dir);
;// CONCATENATED MODULE: ./node_modules/ipfs-unixfs-importer/esm/src/dir-flat.js




class DirFlat extends src_dir {
  constructor(props, options) {
    super(props, options);
    this._children = {};
  }
  async put(name, value) {
    this.cid = undefined;
    this.size = undefined;
    this._children[name] = value;
  }
  get(name) {
    return Promise.resolve(this._children[name]);
  }
  childCount() {
    return Object.keys(this._children).length;
  }
  directChildrenCount() {
    return this.childCount();
  }
  onlyChild() {
    return this._children[Object.keys(this._children)[0]];
  }
  async *eachChildSeries() {
    const keys = Object.keys(this._children);
    for (let i = 0; i < keys.length; i++) {
      const key = keys[i];
      yield {
        key: key,
        child: this._children[key]
      };
    }
  }
  async *flush(block) {
    const children = Object.keys(this._children);
    const links = [];
    for (let i = 0; i < children.length; i++) {
      let child = this._children[children[i]];
      if (child instanceof src_dir) {
        for await (const entry of child.flush(block)) {
          child = entry;
          yield child;
        }
      }
      if (child.size != null && child.cid) {
        links.push({
          Name: children[i],
          Tsize: child.size,
          Hash: child.cid
        });
      }
    }
    const unixfs = new UnixFS({
      type: 'directory',
      mtime: this.mtime,
      mode: this.mode
    });
    const node = {
      Data: unixfs.marshal(),
      Links: links
    };
    const buffer = src_encode(prepare(node));
    const cid = await utils_persist(buffer, block, this.options);
    const size = buffer.length + node.Links.reduce((acc, curr) => acc + (curr.Tsize == null ? 0 : curr.Tsize), 0);
    this.cid = cid;
    this.size = size;
    yield {
      cid,
      unixfs,
      path: this.path,
      size
    };
  }
}
/* harmony default export */ const dir_flat = (DirFlat);
// EXTERNAL MODULE: ./node_modules/hamt-sharding/src/index.js
var hamt_sharding_src = __webpack_require__(12103);
;// CONCATENATED MODULE: ./node_modules/ipfs-unixfs-importer/esm/src/dir-sharded.js





class DirSharded extends src_dir {
  constructor(props, options) {
    super(props, options);
    this._bucket = (0,hamt_sharding_src.createHAMT)({
      hashFn: options.hamtHashFn,
      bits: options.hamtBucketBits
    });
  }
  async put(name, value) {
    await this._bucket.put(name, value);
  }
  get(name) {
    return this._bucket.get(name);
  }
  childCount() {
    return this._bucket.leafCount();
  }
  directChildrenCount() {
    return this._bucket.childrenCount();
  }
  onlyChild() {
    return this._bucket.onlyChild();
  }
  async *eachChildSeries() {
    for await (const {key, value} of this._bucket.eachLeafSeries()) {
      yield {
        key,
        child: value
      };
    }
  }
  async *flush(blockstore) {
    for await (const entry of flush(this._bucket, blockstore, this, this.options)) {
      yield {
        ...entry,
        path: this.path
      };
    }
  }
}
/* harmony default export */ const dir_sharded = (DirSharded);
async function* flush(bucket, blockstore, shardRoot, options) {
  const children = bucket._children;
  const links = [];
  let childrenSize = 0;
  for (let i = 0; i < children.length; i++) {
    const child = children.get(i);
    if (!child) {
      continue;
    }
    const labelPrefix = i.toString(16).toUpperCase().padStart(2, '0');
    if (child instanceof hamt_sharding_src.Bucket) {
      let shard;
      for await (const subShard of await flush(child, blockstore, null, options)) {
        shard = subShard;
      }
      if (!shard) {
        throw new Error('Could not flush sharded directory, no subshard found');
      }
      links.push({
        Name: labelPrefix,
        Tsize: shard.size,
        Hash: shard.cid
      });
      childrenSize += shard.size;
    } else if (typeof child.value.flush === 'function') {
      const dir = child.value;
      let flushedDir;
      for await (const entry of dir.flush(blockstore)) {
        flushedDir = entry;
        yield flushedDir;
      }
      const label = labelPrefix + child.key;
      links.push({
        Name: label,
        Tsize: flushedDir.size,
        Hash: flushedDir.cid
      });
      childrenSize += flushedDir.size;
    } else {
      const value = child.value;
      if (!value.cid) {
        continue;
      }
      const label = labelPrefix + child.key;
      const size = value.size;
      links.push({
        Name: label,
        Tsize: size,
        Hash: value.cid
      });
      childrenSize += size;
    }
  }
  const data = Uint8Array.from(children.bitField().reverse());
  const dir = new UnixFS({
    type: 'hamt-sharded-directory',
    data,
    fanout: bucket.tableSize(),
    hashType: options.hamtHashCode,
    mtime: shardRoot && shardRoot.mtime,
    mode: shardRoot && shardRoot.mode
  });
  const node = {
    Data: dir.marshal(),
    Links: links
  };
  const buffer = src_encode(prepare(node));
  const cid = await utils_persist(buffer, blockstore, options);
  const size = buffer.length + childrenSize;
  yield {
    cid,
    unixfs: dir,
    size
  };
}
;// CONCATENATED MODULE: ./node_modules/ipfs-unixfs-importer/esm/src/flat-to-shard.js


async function flatToShard(child, dir, threshold, options) {
  let newDir = dir;
  if (dir instanceof dir_flat && dir.directChildrenCount() >= threshold) {
    newDir = await convertToShard(dir, options);
  }
  const parent = newDir.parent;
  if (parent) {
    if (newDir !== dir) {
      if (child) {
        child.parent = newDir;
      }
      if (!newDir.parentKey) {
        throw new Error('No parent key found');
      }
      await parent.put(newDir.parentKey, newDir);
    }
    return flatToShard(newDir, parent, threshold, options);
  }
  return newDir;
}
async function convertToShard(oldDir, options) {
  const newDir = new dir_sharded({
    root: oldDir.root,
    dir: true,
    parent: oldDir.parent,
    parentKey: oldDir.parentKey,
    path: oldDir.path,
    dirty: oldDir.dirty,
    flat: false,
    mtime: oldDir.mtime,
    mode: oldDir.mode
  }, options);
  for await (const {key, child} of oldDir.eachChildSeries()) {
    await newDir.put(key, child);
  }
  return newDir;
}
/* harmony default export */ const flat_to_shard = (flatToShard);
;// CONCATENATED MODULE: ./node_modules/ipfs-unixfs-importer/esm/src/utils/to-path-components.js
const toPathComponents = (path = '') => {
  return (path.trim().match(/([^\\/]|\\\/)+/g) || []).filter(Boolean);
};
/* harmony default export */ const to_path_components = (toPathComponents);
;// CONCATENATED MODULE: ./node_modules/ipfs-unixfs-importer/esm/src/tree-builder.js




async function addToTree(elem, tree, options) {
  const pathElems = to_path_components(elem.path || '');
  const lastIndex = pathElems.length - 1;
  let parent = tree;
  let currentPath = '';
  for (let i = 0; i < pathElems.length; i++) {
    const pathElem = pathElems[i];
    currentPath += `${ currentPath ? '/' : '' }${ pathElem }`;
    const last = i === lastIndex;
    parent.dirty = true;
    parent.cid = undefined;
    parent.size = undefined;
    if (last) {
      await parent.put(pathElem, elem);
      tree = await flat_to_shard(null, parent, options.shardSplitThreshold, options);
    } else {
      let dir = await parent.get(pathElem);
      if (!dir || !(dir instanceof src_dir)) {
        dir = new dir_flat({
          root: false,
          dir: true,
          parent: parent,
          parentKey: pathElem,
          path: currentPath,
          dirty: true,
          flat: true,
          mtime: dir && dir.unixfs && dir.unixfs.mtime,
          mode: dir && dir.unixfs && dir.unixfs.mode
        }, options);
      }
      await parent.put(pathElem, dir);
      parent = dir;
    }
  }
  return tree;
}
async function* flushAndYield(tree, blockstore) {
  if (!(tree instanceof src_dir)) {
    if (tree && tree.unixfs && tree.unixfs.isDirectory()) {
      yield tree;
    }
    return;
  }
  yield* tree.flush(blockstore);
}
async function* treeBuilder(source, block, options) {
  let tree = new dir_flat({
    root: true,
    dir: true,
    path: '',
    dirty: true,
    flat: true
  }, options);
  for await (const entry of source) {
    if (!entry) {
      continue;
    }
    tree = await addToTree(entry, tree, options);
    if (!entry.unixfs || !entry.unixfs.isDirectory()) {
      yield entry;
    }
  }
  if (options.wrapWithDirectory) {
    yield* flushAndYield(tree, block);
  } else {
    for await (const unwrapped of tree.eachChildSeries()) {
      if (!unwrapped) {
        continue;
      }
      yield* flushAndYield(unwrapped.child, block);
    }
  }
}
/* harmony default export */ const tree_builder = (treeBuilder);
;// CONCATENATED MODULE: ./node_modules/ipfs-unixfs-importer/esm/src/index.js




async function* importer(source, blockstore, options = {}) {
  const opts = src_options(options);
  let dagBuilder;
  if (typeof options.dagBuilder === 'function') {
    dagBuilder = options.dagBuilder;
  } else {
    dagBuilder = dag_builder;
  }
  let treeBuilder;
  if (typeof options.treeBuilder === 'function') {
    treeBuilder = options.treeBuilder;
  } else {
    treeBuilder = tree_builder;
  }
  let candidates;
  if (Symbol.asyncIterator in source || Symbol.iterator in source) {
    candidates = source;
  } else {
    candidates = [source];
  }
  for await (const entry of treeBuilder(it_parallel_batch(dagBuilder(candidates, blockstore, opts), opts.fileImportConcurrency), blockstore, opts)) {
    yield {
      cid: entry.cid,
      path: entry.path,
      unixfs: entry.unixfs,
      size: entry.size
    };
  }
}
// EXTERNAL MODULE: ./node_modules/browser-readablestream-to-it/index.js
var browser_readablestream_to_it = __webpack_require__(94459);
// EXTERNAL MODULE: ./node_modules/blob-to-it/index.js
var blob_to_it = __webpack_require__(85146);
// EXTERNAL MODULE: ./node_modules/it-peekable/index.js
var it_peekable = __webpack_require__(60127);
// EXTERNAL MODULE: ./node_modules/it-map/index.js
var it_map = __webpack_require__(55594);
;// CONCATENATED MODULE: ./node_modules/ipfs-core-utils/esm/src/files/utils.js
function isBytes(obj) {
  return ArrayBuffer.isView(obj) || obj instanceof ArrayBuffer;
}
function isBlob(obj) {
  return obj.constructor && (obj.constructor.name === 'Blob' || obj.constructor.name === 'File') && typeof obj.stream === 'function';
}
function isFileObject(obj) {
  return typeof obj === 'object' && (obj.path || obj.content);
}
const isReadableStream = value => value && typeof value.getReader === 'function';
;// CONCATENATED MODULE: ./node_modules/ipfs-core-utils/esm/src/files/normalise-content.js








async function* toAsyncIterable(thing) {
  yield thing;
}
async function normaliseContent(input) {
  if (isBytes(input)) {
    return toAsyncIterable(normalise_content_toBytes(input));
  }
  if (typeof input === 'string' || input instanceof String) {
    return toAsyncIterable(normalise_content_toBytes(input.toString()));
  }
  if (isBlob(input)) {
    return blob_to_it(input);
  }
  if (isReadableStream(input)) {
    input = browser_readablestream_to_it(input);
  }
  if (Symbol.iterator in input || Symbol.asyncIterator in input) {
    const peekable = it_peekable(input);
    const {value, done} = await peekable.peek();
    if (done) {
      return toAsyncIterable(new Uint8Array(0));
    }
    peekable.push(value);
    if (Number.isInteger(value)) {
      return toAsyncIterable(Uint8Array.from(await it_all(peekable)));
    }
    if (isBytes(value) || typeof value === 'string' || value instanceof String) {
      return it_map(peekable, normalise_content_toBytes);
    }
  }
  throw err_code(new Error(`Unexpected input: ${ input }`), 'ERR_UNEXPECTED_INPUT');
}
function normalise_content_toBytes(chunk) {
  if (chunk instanceof Uint8Array) {
    return chunk;
  }
  if (ArrayBuffer.isView(chunk)) {
    return new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
  }
  if (chunk instanceof ArrayBuffer) {
    return new Uint8Array(chunk);
  }
  if (Array.isArray(chunk)) {
    return Uint8Array.from(chunk);
  }
  return from_string_fromString(chunk.toString());
}
;// CONCATENATED MODULE: ./node_modules/ipfs-core-utils/esm/src/files/normalise-candidate-single.js





async function* normaliseCandidateSingle(input, normaliseContent) {
  if (input === null || input === undefined) {
    throw err_code(new Error(`Unexpected input: ${ input }`), 'ERR_UNEXPECTED_INPUT');
  }
  if (typeof input === 'string' || input instanceof String) {
    yield toFileObject(input.toString(), normaliseContent);
    return;
  }
  if (isBytes(input) || isBlob(input)) {
    yield toFileObject(input, normaliseContent);
    return;
  }
  if (isReadableStream(input)) {
    input = browser_readablestream_to_it(input);
  }
  if (Symbol.iterator in input || Symbol.asyncIterator in input) {
    const peekable = it_peekable(input);
    const {value, done} = await peekable.peek();
    if (done) {
      yield { content: [] };
      return;
    }
    peekable.push(value);
    if (Number.isInteger(value) || isBytes(value) || typeof value === 'string' || value instanceof String) {
      yield toFileObject(peekable, normaliseContent);
      return;
    }
    throw err_code(new Error('Unexpected input: multiple items passed - if you are using ipfs.add, please use ipfs.addAll instead'), 'ERR_UNEXPECTED_INPUT');
  }
  if (isFileObject(input)) {
    yield toFileObject(input, normaliseContent);
    return;
  }
  throw err_code(new Error('Unexpected input: cannot convert "' + typeof input + '" into ImportCandidate'), 'ERR_UNEXPECTED_INPUT');
}
async function toFileObject(input, normaliseContent) {
  const {path, mode, mtime, content} = input;
  const file = {
    path: path || '',
    mode: parseMode(mode),
    mtime: parseMtime(mtime)
  };
  if (content) {
    file.content = await normaliseContent(content);
  } else if (!path) {
    file.content = await normaliseContent(input);
  }
  return file;
}
;// CONCATENATED MODULE: ./node_modules/ipfs-core-utils/esm/src/files/normalise-input-single.js


function normaliseInput(input) {
  return normaliseCandidateSingle(input, normaliseContent);
}
;// CONCATENATED MODULE: ./node_modules/ipfs-core-utils/esm/src/files/normalise-candidate-multiple.js






async function* normaliseCandidateMultiple(input, normaliseContent) {
  if (typeof input === 'string' || input instanceof String || isBytes(input) || isBlob(input) || input._readableState) {
    throw err_code(new Error('Unexpected input: single item passed - if you are using ipfs.addAll, please use ipfs.add instead'), 'ERR_UNEXPECTED_INPUT');
  }
  if (isReadableStream(input)) {
    input = browser_readablestream_to_it(input);
  }
  if (Symbol.iterator in input || Symbol.asyncIterator in input) {
    const peekable = it_peekable(input);
    const {value, done} = await peekable.peek();
    if (done) {
      yield* [];
      return;
    }
    peekable.push(value);
    if (Number.isInteger(value)) {
      throw err_code(new Error('Unexpected input: single item passed - if you are using ipfs.addAll, please use ipfs.add instead'), 'ERR_UNEXPECTED_INPUT');
    }
    if (value._readableState) {
      yield* it_map(peekable, value => normalise_candidate_multiple_toFileObject({ content: value }, normaliseContent));
      return;
    }
    if (isBytes(value)) {
      yield normalise_candidate_multiple_toFileObject({ content: peekable }, normaliseContent);
      return;
    }
    if (isFileObject(value) || value[Symbol.iterator] || value[Symbol.asyncIterator] || isReadableStream(value) || isBlob(value)) {
      yield* it_map(peekable, value => normalise_candidate_multiple_toFileObject(value, normaliseContent));
      return;
    }
  }
  if (isFileObject(input)) {
    throw err_code(new Error('Unexpected input: single item passed - if you are using ipfs.addAll, please use ipfs.add instead'), 'ERR_UNEXPECTED_INPUT');
  }
  throw err_code(new Error('Unexpected input: ' + typeof input), 'ERR_UNEXPECTED_INPUT');
}
async function normalise_candidate_multiple_toFileObject(input, normaliseContent) {
  const {path, mode, mtime, content} = input;
  const file = {
    path: path || '',
    mode: parseMode(mode),
    mtime: parseMtime(mtime)
  };
  if (content) {
    file.content = await normaliseContent(content);
  } else if (!path) {
    file.content = await normaliseContent(input);
  }
  return file;
}
;// CONCATENATED MODULE: ./node_modules/ipfs-core-utils/esm/src/files/normalise-input-multiple.js


function normalise_input_multiple_normaliseInput(input) {
  return normaliseCandidateMultiple(input, normaliseContent);
}
;// CONCATENATED MODULE: ./node_modules/ipfs-car/dist/esm/pack/utils/normalise-input.js


function normalise_input_isBytes(obj) {
    return ArrayBuffer.isView(obj) || obj instanceof ArrayBuffer;
}
function normalise_input_isBlob(obj) {
    return Boolean(obj.constructor) &&
        (obj.constructor.name === 'Blob' || obj.constructor.name === 'File') &&
        typeof obj.stream === 'function';
}
function isSingle(input) {
    return typeof input === 'string' || input instanceof String || normalise_input_isBytes(input) || normalise_input_isBlob(input) || '_readableState' in input;
}
/**
 * Get a single or multiple normaliser depending on the input.
 */
function getNormaliser(input) {
    if (isSingle(input)) {
        return normaliseInput(input);
    }
    else {
        return normalise_input_multiple_normaliseInput(input);
    }
}

;// CONCATENATED MODULE: ./node_modules/blockstore-core/esm/src/errors.js

function notFoundError(err) {
  err = err || new Error('Not Found');
  return err_code(err, 'ERR_NOT_FOUND');
}
function abortedError(err) {
  err = err || new Error('Aborted');
  return err_code(err, 'ERR_ABORTED');
}
// EXTERNAL MODULE: ./node_modules/it-drain/index.js
var it_drain = __webpack_require__(98259);
// EXTERNAL MODULE: ./node_modules/it-filter/index.js
var it_filter = __webpack_require__(55863);
// EXTERNAL MODULE: ./node_modules/it-take/index.js
var it_take = __webpack_require__(61955);
;// CONCATENATED MODULE: ./node_modules/blockstore-core/esm/src/base.js




const sortAll = (iterable, sorter) => {
  return async function* () {
    const values = await it_all(iterable);
    yield* values.sort(sorter);
  }();
};
class base_BaseBlockstore {
  open() {
    return Promise.reject(new Error('.open is not implemented'));
  }
  close() {
    return Promise.reject(new Error('.close is not implemented'));
  }
  put(key, val, options) {
    return Promise.reject(new Error('.put is not implemented'));
  }
  get(key, options) {
    return Promise.reject(new Error('.get is not implemented'));
  }
  has(key, options) {
    return Promise.reject(new Error('.has is not implemented'));
  }
  delete(key, options) {
    return Promise.reject(new Error('.delete is not implemented'));
  }
  async *putMany(source, options = {}) {
    for await (const {key, value} of source) {
      await this.put(key, value, options);
      yield {
        key,
        value
      };
    }
  }
  async *getMany(source, options = {}) {
    for await (const key of source) {
      yield this.get(key, options);
    }
  }
  async *deleteMany(source, options = {}) {
    for await (const key of source) {
      await this.delete(key, options);
      yield key;
    }
  }
  batch() {
    let puts = [];
    let dels = [];
    return {
      put(key, value) {
        puts.push({
          key,
          value
        });
      },
      delete(key) {
        dels.push(key);
      },
      commit: async options => {
        await it_drain(this.putMany(puts, options));
        puts = [];
        await it_drain(this.deleteMany(dels, options));
        dels = [];
      }
    };
  }
  async *_all(q, options) {
    throw new Error('._all is not implemented');
  }
  async *_allKeys(q, options) {
    throw new Error('._allKeys is not implemented');
  }
  query(q, options) {
    let it = this._all(q, options);
    if (q.prefix != null) {
      it = it_filter(it, e => e.key.toString().startsWith(q.prefix || ''));
    }
    if (Array.isArray(q.filters)) {
      it = q.filters.reduce((it, f) => it_filter(it, f), it);
    }
    if (Array.isArray(q.orders)) {
      it = q.orders.reduce((it, f) => sortAll(it, f), it);
    }
    if (q.offset != null) {
      let i = 0;
      it = it_filter(it, () => i++ >= (q.offset || 0));
    }
    if (q.limit != null) {
      it = it_take(it, q.limit);
    }
    return it;
  }
  queryKeys(q, options) {
    let it = this._allKeys(q, options);
    if (q.prefix != null) {
      it = it_filter(it, cid => cid.toString().startsWith(q.prefix || ''));
    }
    if (Array.isArray(q.filters)) {
      it = q.filters.reduce((it, f) => it_filter(it, f), it);
    }
    if (Array.isArray(q.orders)) {
      it = q.orders.reduce((it, f) => sortAll(it, f), it);
    }
    if (q.offset != null) {
      let i = 0;
      it = it_filter(it, () => i++ >= q.offset);
    }
    if (q.limit != null) {
      it = it_take(it, q.limit);
    }
    return it;
  }
}
;// CONCATENATED MODULE: ./node_modules/blockstore-core/esm/src/memory.js






class MemoryBlockstore extends (/* unused pure expression or super */ null && (BaseBlockstore)) {
  constructor() {
    super();
    this.data = {};
  }
  open() {
    return Promise.resolve();
  }
  close() {
    return Promise.resolve();
  }
  async put(key, val) {
    this.data[base32.encode(key.multihash.bytes)] = val;
  }
  async get(key) {
    const exists = await this.has(key);
    if (!exists)
      throw Errors.notFoundError();
    return this.data[base32.encode(key.multihash.bytes)];
  }
  async has(key) {
    return this.data[base32.encode(key.multihash.bytes)] !== undefined;
  }
  async delete(key) {
    delete this.data[base32.encode(key.multihash.bytes)];
  }
  async *_all() {
    yield* Object.entries(this.data).map(([key, value]) => ({
      key: CID.createV1(raw.code, Digest.decode(base32.decode(key))),
      value
    }));
  }
  async *_allKeys() {
    yield* Object.entries(this.data).map(([key]) => CID.createV1(raw.code, Digest.decode(base32.decode(key))));
  }
}
;// CONCATENATED MODULE: ./node_modules/blockstore-core/esm/src/index.js



const src_Errors = { ...errors_namespaceObject };
;// CONCATENATED MODULE: ./node_modules/ipfs-car/dist/esm/blockstore/memory.js


class MemoryBlockStore extends base_BaseBlockstore {
    constructor() {
        super();
        this.store = new Map();
    }
    async *blocks() {
        for (const [cidStr, bytes] of this.store.entries()) {
            yield { cid: cid_CID.parse(cidStr), bytes };
        }
    }
    put(cid, bytes) {
        this.store.set(cid.toString(), bytes);
        return Promise.resolve();
    }
    get(cid) {
        const bytes = this.store.get(cid.toString());
        if (!bytes) {
            throw new Error(`block with cid ${cid.toString()} no found`);
        }
        return Promise.resolve(bytes);
    }
    has(cid) {
        return Promise.resolve(this.store.has(cid.toString()));
    }
    close() {
        this.store.clear();
        return Promise.resolve();
    }
}

;// CONCATENATED MODULE: ./node_modules/ipfs-car/dist/esm/pack/constants.js

const unixfsImporterOptionsDefault = {
    cidVersion: 1,
    chunker: 'fixed',
    maxChunkSize: 262144,
    hasher: sha256,
    rawLeaves: true,
    wrapWithDirectory: true,
    maxChildrenPerNode: 174
};

;// CONCATENATED MODULE: ./node_modules/ipfs-car/dist/esm/pack/index.js







async function pack({ input, blockstore: userBlockstore, hasher, maxChunkSize, maxChildrenPerNode, wrapWithDirectory, rawLeaves }) {
    if (!input || (Array.isArray(input) && !input.length)) {
        throw new Error('missing input file(s)');
    }
    const blockstore = userBlockstore ? userBlockstore : new MemoryBlockStore();
    // Consume the source
    const rootEntry = await it_last(it_pipe(getNormaliser(input), (source) => importer(source, blockstore, {
        ...unixfsImporterOptionsDefault,
        hasher: hasher || unixfsImporterOptionsDefault.hasher,
        maxChunkSize: maxChunkSize || unixfsImporterOptionsDefault.maxChunkSize,
        maxChildrenPerNode: maxChildrenPerNode || unixfsImporterOptionsDefault.maxChildrenPerNode,
        wrapWithDirectory: wrapWithDirectory === false ? false : unixfsImporterOptionsDefault.wrapWithDirectory,
        rawLeaves: rawLeaves == null ? unixfsImporterOptionsDefault.rawLeaves : rawLeaves
    })));
    if (!rootEntry || !rootEntry.cid) {
        throw new Error('given input could not be parsed correctly');
    }
    const root = rootEntry.cid;
    const { writer, out: carOut } = await writer_CarWriter.create([root]);
    const carOutIter = carOut[Symbol.asyncIterator]();
    let writingPromise;
    const writeAll = async () => {
        for await (const block of blockstore.blocks()) {
            // `await` will block until all bytes in `carOut` are consumed by the user
            // so we have backpressure here
            await writer.put(block);
        }
        await writer.close();
        if (!userBlockstore) {
            await blockstore.close();
        }
    };
    const out = {
        [Symbol.asyncIterator]() {
            if (writingPromise != null) {
                throw new Error('Multiple iterator not supported');
            }
            // don't start writing until the user starts consuming the iterator
            writingPromise = writeAll();
            return {
                async next() {
                    const result = await carOutIter.next();
                    if (result.done) {
                        await writingPromise; // any errors will propagate from here
                    }
                    return result;
                }
            };
        }
    };
    return { root, out };
}

// EXTERNAL MODULE: ./node_modules/throttled-queue/dist/throttledQueue.js
var throttledQueue = __webpack_require__(10275);
// EXTERNAL MODULE: external "http"
var external_http_ = __webpack_require__(13685);
// EXTERNAL MODULE: external "https"
var external_https_ = __webpack_require__(95687);
// EXTERNAL MODULE: external "zlib"
var external_zlib_ = __webpack_require__(59796);
;// CONCATENATED MODULE: ./node_modules/mrmime/index.mjs
const mimes = {
  "ez": "application/andrew-inset",
  "aw": "application/applixware",
  "atom": "application/atom+xml",
  "atomcat": "application/atomcat+xml",
  "atomdeleted": "application/atomdeleted+xml",
  "atomsvc": "application/atomsvc+xml",
  "dwd": "application/atsc-dwd+xml",
  "held": "application/atsc-held+xml",
  "rsat": "application/atsc-rsat+xml",
  "bdoc": "application/bdoc",
  "xcs": "application/calendar+xml",
  "ccxml": "application/ccxml+xml",
  "cdfx": "application/cdfx+xml",
  "cdmia": "application/cdmi-capability",
  "cdmic": "application/cdmi-container",
  "cdmid": "application/cdmi-domain",
  "cdmio": "application/cdmi-object",
  "cdmiq": "application/cdmi-queue",
  "cu": "application/cu-seeme",
  "mpd": "application/dash+xml",
  "davmount": "application/davmount+xml",
  "dbk": "application/docbook+xml",
  "dssc": "application/dssc+der",
  "xdssc": "application/dssc+xml",
  "es": "application/ecmascript",
  "ecma": "application/ecmascript",
  "emma": "application/emma+xml",
  "emotionml": "application/emotionml+xml",
  "epub": "application/epub+zip",
  "exi": "application/exi",
  "fdt": "application/fdt+xml",
  "pfr": "application/font-tdpfr",
  "geojson": "application/geo+json",
  "gml": "application/gml+xml",
  "gpx": "application/gpx+xml",
  "gxf": "application/gxf",
  "gz": "application/gzip",
  "hjson": "application/hjson",
  "stk": "application/hyperstudio",
  "ink": "application/inkml+xml",
  "inkml": "application/inkml+xml",
  "ipfix": "application/ipfix",
  "its": "application/its+xml",
  "jar": "application/java-archive",
  "war": "application/java-archive",
  "ear": "application/java-archive",
  "ser": "application/java-serialized-object",
  "class": "application/java-vm",
  "js": "application/javascript",
  "mjs": "application/javascript",
  "json": "application/json",
  "map": "application/json",
  "json5": "application/json5",
  "jsonml": "application/jsonml+json",
  "jsonld": "application/ld+json",
  "lgr": "application/lgr+xml",
  "lostxml": "application/lost+xml",
  "hqx": "application/mac-binhex40",
  "cpt": "application/mac-compactpro",
  "mads": "application/mads+xml",
  "webmanifest": "application/manifest+json",
  "mrc": "application/marc",
  "mrcx": "application/marcxml+xml",
  "ma": "application/mathematica",
  "nb": "application/mathematica",
  "mb": "application/mathematica",
  "mathml": "application/mathml+xml",
  "mbox": "application/mbox",
  "mscml": "application/mediaservercontrol+xml",
  "metalink": "application/metalink+xml",
  "meta4": "application/metalink4+xml",
  "mets": "application/mets+xml",
  "maei": "application/mmt-aei+xml",
  "musd": "application/mmt-usd+xml",
  "mods": "application/mods+xml",
  "m21": "application/mp21",
  "mp21": "application/mp21",
  "mp4s": "application/mp4",
  "m4p": "application/mp4",
  "doc": "application/msword",
  "dot": "application/msword",
  "mxf": "application/mxf",
  "nq": "application/n-quads",
  "nt": "application/n-triples",
  "cjs": "application/node",
  "bin": "application/octet-stream",
  "dms": "application/octet-stream",
  "lrf": "application/octet-stream",
  "mar": "application/octet-stream",
  "so": "application/octet-stream",
  "dist": "application/octet-stream",
  "distz": "application/octet-stream",
  "pkg": "application/octet-stream",
  "bpk": "application/octet-stream",
  "dump": "application/octet-stream",
  "elc": "application/octet-stream",
  "deploy": "application/octet-stream",
  "exe": "application/octet-stream",
  "dll": "application/octet-stream",
  "deb": "application/octet-stream",
  "dmg": "application/octet-stream",
  "iso": "application/octet-stream",
  "img": "application/octet-stream",
  "msi": "application/octet-stream",
  "msp": "application/octet-stream",
  "msm": "application/octet-stream",
  "buffer": "application/octet-stream",
  "oda": "application/oda",
  "opf": "application/oebps-package+xml",
  "ogx": "application/ogg",
  "omdoc": "application/omdoc+xml",
  "onetoc": "application/onenote",
  "onetoc2": "application/onenote",
  "onetmp": "application/onenote",
  "onepkg": "application/onenote",
  "oxps": "application/oxps",
  "relo": "application/p2p-overlay+xml",
  "xer": "application/patch-ops-error+xml",
  "pdf": "application/pdf",
  "pgp": "application/pgp-encrypted",
  "asc": "application/pgp-signature",
  "sig": "application/pgp-signature",
  "prf": "application/pics-rules",
  "p10": "application/pkcs10",
  "p7m": "application/pkcs7-mime",
  "p7c": "application/pkcs7-mime",
  "p7s": "application/pkcs7-signature",
  "p8": "application/pkcs8",
  "ac": "application/pkix-attr-cert",
  "cer": "application/pkix-cert",
  "crl": "application/pkix-crl",
  "pkipath": "application/pkix-pkipath",
  "pki": "application/pkixcmp",
  "pls": "application/pls+xml",
  "ai": "application/postscript",
  "eps": "application/postscript",
  "ps": "application/postscript",
  "provx": "application/provenance+xml",
  "cww": "application/prs.cww",
  "pskcxml": "application/pskc+xml",
  "raml": "application/raml+yaml",
  "rdf": "application/rdf+xml",
  "owl": "application/rdf+xml",
  "rif": "application/reginfo+xml",
  "rnc": "application/relax-ng-compact-syntax",
  "rl": "application/resource-lists+xml",
  "rld": "application/resource-lists-diff+xml",
  "rs": "application/rls-services+xml",
  "rapd": "application/route-apd+xml",
  "sls": "application/route-s-tsid+xml",
  "rusd": "application/route-usd+xml",
  "gbr": "application/rpki-ghostbusters",
  "mft": "application/rpki-manifest",
  "roa": "application/rpki-roa",
  "rsd": "application/rsd+xml",
  "rss": "application/rss+xml",
  "rtf": "application/rtf",
  "sbml": "application/sbml+xml",
  "scq": "application/scvp-cv-request",
  "scs": "application/scvp-cv-response",
  "spq": "application/scvp-vp-request",
  "spp": "application/scvp-vp-response",
  "sdp": "application/sdp",
  "senmlx": "application/senml+xml",
  "sensmlx": "application/sensml+xml",
  "setpay": "application/set-payment-initiation",
  "setreg": "application/set-registration-initiation",
  "shf": "application/shf+xml",
  "siv": "application/sieve",
  "sieve": "application/sieve",
  "smi": "application/smil+xml",
  "smil": "application/smil+xml",
  "rq": "application/sparql-query",
  "srx": "application/sparql-results+xml",
  "gram": "application/srgs",
  "grxml": "application/srgs+xml",
  "sru": "application/sru+xml",
  "ssdl": "application/ssdl+xml",
  "ssml": "application/ssml+xml",
  "swidtag": "application/swid+xml",
  "tei": "application/tei+xml",
  "teicorpus": "application/tei+xml",
  "tfi": "application/thraud+xml",
  "tsd": "application/timestamped-data",
  "toml": "application/toml",
  "trig": "application/trig",
  "ttml": "application/ttml+xml",
  "ubj": "application/ubjson",
  "rsheet": "application/urc-ressheet+xml",
  "td": "application/urc-targetdesc+xml",
  "vxml": "application/voicexml+xml",
  "wasm": "application/wasm",
  "wgt": "application/widget",
  "hlp": "application/winhlp",
  "wsdl": "application/wsdl+xml",
  "wspolicy": "application/wspolicy+xml",
  "xaml": "application/xaml+xml",
  "xav": "application/xcap-att+xml",
  "xca": "application/xcap-caps+xml",
  "xdf": "application/xcap-diff+xml",
  "xel": "application/xcap-el+xml",
  "xns": "application/xcap-ns+xml",
  "xenc": "application/xenc+xml",
  "xhtml": "application/xhtml+xml",
  "xht": "application/xhtml+xml",
  "xlf": "application/xliff+xml",
  "xml": "application/xml",
  "xsl": "application/xml",
  "xsd": "application/xml",
  "rng": "application/xml",
  "dtd": "application/xml-dtd",
  "xop": "application/xop+xml",
  "xpl": "application/xproc+xml",
  "xslt": "application/xml",
  "xspf": "application/xspf+xml",
  "mxml": "application/xv+xml",
  "xhvml": "application/xv+xml",
  "xvml": "application/xv+xml",
  "xvm": "application/xv+xml",
  "yang": "application/yang",
  "yin": "application/yin+xml",
  "zip": "application/zip",
  "3gpp": "video/3gpp",
  "adp": "audio/adpcm",
  "amr": "audio/amr",
  "au": "audio/basic",
  "snd": "audio/basic",
  "mid": "audio/midi",
  "midi": "audio/midi",
  "kar": "audio/midi",
  "rmi": "audio/midi",
  "mxmf": "audio/mobile-xmf",
  "mp3": "audio/mpeg",
  "m4a": "audio/mp4",
  "mp4a": "audio/mp4",
  "mpga": "audio/mpeg",
  "mp2": "audio/mpeg",
  "mp2a": "audio/mpeg",
  "m2a": "audio/mpeg",
  "m3a": "audio/mpeg",
  "oga": "audio/ogg",
  "ogg": "audio/ogg",
  "spx": "audio/ogg",
  "opus": "audio/ogg",
  "s3m": "audio/s3m",
  "sil": "audio/silk",
  "wav": "audio/wav",
  "weba": "audio/webm",
  "xm": "audio/xm",
  "ttc": "font/collection",
  "otf": "font/otf",
  "ttf": "font/ttf",
  "woff": "font/woff",
  "woff2": "font/woff2",
  "exr": "image/aces",
  "apng": "image/apng",
  "avif": "image/avif",
  "bmp": "image/bmp",
  "cgm": "image/cgm",
  "drle": "image/dicom-rle",
  "emf": "image/emf",
  "fits": "image/fits",
  "g3": "image/g3fax",
  "gif": "image/gif",
  "heic": "image/heic",
  "heics": "image/heic-sequence",
  "heif": "image/heif",
  "heifs": "image/heif-sequence",
  "hej2": "image/hej2k",
  "hsj2": "image/hsj2",
  "ief": "image/ief",
  "jls": "image/jls",
  "jp2": "image/jp2",
  "jpg2": "image/jp2",
  "jpeg": "image/jpeg",
  "jpg": "image/jpeg",
  "jpe": "image/jpeg",
  "jph": "image/jph",
  "jhc": "image/jphc",
  "jpm": "image/jpm",
  "jpx": "image/jpx",
  "jpf": "image/jpx",
  "jxr": "image/jxr",
  "jxra": "image/jxra",
  "jxrs": "image/jxrs",
  "jxs": "image/jxs",
  "jxsc": "image/jxsc",
  "jxsi": "image/jxsi",
  "jxss": "image/jxss",
  "ktx": "image/ktx",
  "ktx2": "image/ktx2",
  "png": "image/png",
  "btif": "image/prs.btif",
  "pti": "image/prs.pti",
  "sgi": "image/sgi",
  "svg": "image/svg+xml",
  "svgz": "image/svg+xml",
  "t38": "image/t38",
  "tif": "image/tiff",
  "tiff": "image/tiff",
  "tfx": "image/tiff-fx",
  "webp": "image/webp",
  "wmf": "image/wmf",
  "disposition-notification": "message/disposition-notification",
  "u8msg": "message/global",
  "u8dsn": "message/global-delivery-status",
  "u8mdn": "message/global-disposition-notification",
  "u8hdr": "message/global-headers",
  "eml": "message/rfc822",
  "mime": "message/rfc822",
  "3mf": "model/3mf",
  "gltf": "model/gltf+json",
  "glb": "model/gltf-binary",
  "igs": "model/iges",
  "iges": "model/iges",
  "msh": "model/mesh",
  "mesh": "model/mesh",
  "silo": "model/mesh",
  "mtl": "model/mtl",
  "obj": "model/obj",
  "stpz": "model/step+zip",
  "stpxz": "model/step-xml+zip",
  "stl": "model/stl",
  "wrl": "model/vrml",
  "vrml": "model/vrml",
  "x3db": "model/x3d+fastinfoset",
  "x3dbz": "model/x3d+binary",
  "x3dv": "model/x3d-vrml",
  "x3dvz": "model/x3d+vrml",
  "x3d": "model/x3d+xml",
  "x3dz": "model/x3d+xml",
  "appcache": "text/cache-manifest",
  "manifest": "text/cache-manifest",
  "ics": "text/calendar",
  "ifb": "text/calendar",
  "coffee": "text/coffeescript",
  "litcoffee": "text/coffeescript",
  "css": "text/css",
  "csv": "text/csv",
  "html": "text/html",
  "htm": "text/html",
  "shtml": "text/html",
  "jade": "text/jade",
  "jsx": "text/jsx",
  "less": "text/less",
  "markdown": "text/markdown",
  "md": "text/markdown",
  "mml": "text/mathml",
  "mdx": "text/mdx",
  "n3": "text/n3",
  "txt": "text/plain",
  "text": "text/plain",
  "conf": "text/plain",
  "def": "text/plain",
  "list": "text/plain",
  "log": "text/plain",
  "in": "text/plain",
  "ini": "text/plain",
  "dsc": "text/prs.lines.tag",
  "rtx": "text/richtext",
  "sgml": "text/sgml",
  "sgm": "text/sgml",
  "shex": "text/shex",
  "slim": "text/slim",
  "slm": "text/slim",
  "spdx": "text/spdx",
  "stylus": "text/stylus",
  "styl": "text/stylus",
  "tsv": "text/tab-separated-values",
  "t": "text/troff",
  "tr": "text/troff",
  "roff": "text/troff",
  "man": "text/troff",
  "me": "text/troff",
  "ms": "text/troff",
  "ttl": "text/turtle",
  "uri": "text/uri-list",
  "uris": "text/uri-list",
  "urls": "text/uri-list",
  "vcard": "text/vcard",
  "vtt": "text/vtt",
  "yaml": "text/yaml",
  "yml": "text/yaml",
  "3gp": "video/3gpp",
  "3g2": "video/3gpp2",
  "h261": "video/h261",
  "h263": "video/h263",
  "h264": "video/h264",
  "m4s": "video/iso.segment",
  "jpgv": "video/jpeg",
  "jpgm": "image/jpm",
  "mj2": "video/mj2",
  "mjp2": "video/mj2",
  "ts": "video/mp2t",
  "mp4": "video/mp4",
  "mp4v": "video/mp4",
  "mpg4": "video/mp4",
  "mpeg": "video/mpeg",
  "mpg": "video/mpeg",
  "mpe": "video/mpeg",
  "m1v": "video/mpeg",
  "m2v": "video/mpeg",
  "ogv": "video/ogg",
  "qt": "video/quicktime",
  "mov": "video/quicktime",
  "webm": "video/webm"
};

function lookup(extn) {
	let tmp = ('' + extn).trim().toLowerCase();
	let idx = tmp.lastIndexOf('.');
	return mimes[!~idx ? tmp : tmp.substring(++idx)];
}

// EXTERNAL MODULE: ./node_modules/data-uri-to-buffer/dist/src/index.js
var dist_src = __webpack_require__(47255);
// EXTERNAL MODULE: external "buffer"
var external_buffer_ = __webpack_require__(14300);
;// CONCATENATED MODULE: ./node_modules/web-encoding/src/lib.mjs
// In node `export { TextEncoder }` throws:
// "Export 'TextEncoder' is not defined in module"
// To workaround we first define constants and then export with as.
const lib_Encoder = TextEncoder
const lib_Decoder = TextDecoder



// EXTERNAL MODULE: ./node_modules/@web-std/stream/src/stream.cjs
var stream = __webpack_require__(29375);
;// CONCATENATED MODULE: ./node_modules/@web-std/stream/src/lib.node.js
// @ts-ignore

const {
  ReadableStream,
  ReadableStreamDefaultReader,
  ReadableStreamBYOBReader,
  ReadableStreamBYOBRequest,
  ReadableByteStreamController,
  ReadableStreamDefaultController,
  TransformStream,
  TransformStreamDefaultController,
  WritableStream,
  WritableStreamDefaultWriter,
  WritableStreamDefaultController,
  ByteLengthQueuingStrategy,
  CountQueuingStrategy,
  TextEncoderStream,
  TextDecoderStream,
} = stream

;// CONCATENATED MODULE: ./node_modules/@web-std/blob/src/package.js



;// CONCATENATED MODULE: ./node_modules/@web-std/blob/src/blob.js


/**
 * @implements {globalThis.Blob}
 */
const WebBlob = class Blob {
  /**
   * @param {BlobPart[]} [init]
   * @param {BlobPropertyBag} [options]
   */
  constructor(init = [], options = {}) {
    /** @type {Uint8Array[]} */
    const parts = []

    let size = 0
    for (const part of init) {
      if (typeof part === "string") {
        const bytes = new lib_Encoder().encode(part)
        parts.push(bytes)
        size += bytes.byteLength
      } else if (part instanceof WebBlob) {
        size += part.size
        // @ts-ignore - `_parts` is marked private so TS will complain about
        // accessing it.
        parts.push(...part._parts)
      } else if (part instanceof ArrayBuffer) {
        parts.push(new Uint8Array(part))
        size += part.byteLength
      } else if (part instanceof Uint8Array) {
        parts.push(part)
        size += part.byteLength
      } else if (ArrayBuffer.isView(part)) {
        const { buffer, byteOffset, byteLength } = part
        parts.push(new Uint8Array(buffer, byteOffset, byteLength))
        size += byteLength
      } else {
        const bytes = new lib_Encoder().encode(String(part))
        parts.push(bytes)
        size += bytes.byteLength
      }
    }

    /** @private */
    this._size = size
    /** @private */
    this._type = readType(options.type)
    /** @private */
    this._parts = parts

    Object.defineProperties(this, {
      _size: { enumerable: false },
      _type: { enumerable: false },
      _parts: { enumerable: false },
    })
  }

  /**
   * A string indicating the MIME type of the data contained in the Blob.
   * If the type is unknown, this string is empty.
   * @type {string}
   */
  get type() {
    return this._type
  }
  /**
   * The size, in bytes, of the data contained in the Blob object.
   * @type {number}
   */
  get size() {
    return this._size
  }

  /**
   * Returns a new Blob object containing the data in the specified range of
   * bytes of the blob on which it's called.
   * @param {number} [start=0] - An index into the Blob indicating the first
   * byte to include in the new Blob. If you specify a negative value, it's
   * treated as an offset from the end of the Blob toward the beginning. For
   * example, `-10` would be the 10th from last byte in the Blob. The default
   * value is `0`. If you specify a value for start that is larger than the
   * size of the source Blob, the returned Blob has size 0 and contains no
   * data.
   * @param {number} [end] - An index into the `Blob` indicating the first byte
   *  that will *not* be included in the new `Blob` (i.e. the byte exactly at
   * this index is not included). If you specify a negative value, it's treated
   * as an offset from the end of the Blob toward the beginning. For example,
   * `-10` would be the 10th from last byte in the `Blob`. The default value is
   * size.
   * @param {string} [type] - The content type to assign to the new Blob;
   * this will be the value of its type property. The default value is an empty
   * string.
   * @returns {Blob}
   */
  slice(start = 0, end = this.size, type = "") {
    const { size, _parts } = this
    let offset = start < 0 ? Math.max(size + start, 0) : Math.min(start, size)

    let limit = end < 0 ? Math.max(size + end, 0) : Math.min(end, size)
    const span = Math.max(limit - offset, 0)
    const blob = new Blob([], { type })

    if (span === 0) {
      return blob
    }

    let blobSize = 0
    const blobParts = []
    for (const part of _parts) {
      const { byteLength } = part
      if (offset > 0 && byteLength <= offset) {
        offset -= byteLength
        limit -= byteLength
      } else {
        const chunk = part.subarray(offset, Math.min(byteLength, limit))
        blobParts.push(chunk)
        blobSize += chunk.byteLength
        // no longer need to take that into account
        offset = 0

        // don't add the overflow to new blobParts
        if (blobSize >= span) {
          break
        }
      }
    }

    blob._parts = blobParts
    blob._size = blobSize

    return blob
  }

  /**
   * Returns a promise that resolves with an ArrayBuffer containing the entire
   * contents of the Blob as binary data.
   * @returns {Promise<ArrayBuffer>}
   */
  // eslint-disable-next-line require-await
  async arrayBuffer() {
    const buffer = new ArrayBuffer(this.size)
    const bytes = new Uint8Array(buffer)
    let offset = 0
    for (const part of this._parts) {
      bytes.set(part, offset)
      offset += part.byteLength
    }
    return buffer
  }

  /**
   * Returns a promise that resolves with a USVString containing the entire
   * contents of the Blob interpreted as UTF-8 text.
   * @returns {Promise<string>}
   */
  // eslint-disable-next-line require-await
  async text() {
    const decoder = new lib_Decoder()
    let text = ""
    for (const part of this._parts) {
      text += decoder.decode(part)
    }
    return text
  }

  /**
   * @returns {BlobStream}
   */
  stream() {
    return new BlobStream(this._parts)
  }

  /**
   * @returns {string}
   */
  toString() {
    return "[object Blob]"
  }

  get [Symbol.toStringTag]() {
    return "Blob"
  }
}

// Marking export as a DOM File object instead of custom class.
/** @type {typeof globalThis.Blob} */
const Blob = WebBlob

/**
 * Blob stream is a `ReadableStream` extension optimized to have minimal
 * overhead when consumed as `AsyncIterable<Uint8Array>`.
 * @extends {ReadableStream<Uint8Array>}
 * @implements {AsyncIterable<Uint8Array>}
 */
class BlobStream extends ReadableStream {
  /**
   * @param {Uint8Array[]} chunks
   */
  constructor(chunks) {
    // @ts-ignore
    super(new BlobStreamController(chunks.values()), { type: "bytes" })
    /** @private */
    this._chunks = chunks
  }

  /**
   * @param {Object} [_options]
   * @property {boolean} [_options.preventCancel]
   * @returns {AsyncIterator<Uint8Array>}
   */
  async *[Symbol.asyncIterator](_options) {
    const reader = this.getReader()
    yield* this._chunks
    reader.releaseLock()
  }
}

class BlobStreamController {
  /**
   * @param {Iterator<Uint8Array>} chunks
   */
  constructor(chunks) {
    this.chunks = chunks
  }

  /**
   * @param {ReadableStreamDefaultController} controller
   */
  start(controller) {
    this.work(controller)
    this.isWorking = false
    this.isCancelled = false
  }
  /**
   *
   * @param {ReadableStreamDefaultController} controller
   */
  async work(controller) {
    const { chunks } = this

    this.isWorking = true
    while (!this.isCancelled && (controller.desiredSize || 0) > 0) {
      let next = null
      try {
        next = chunks.next()
      } catch (error) {
        controller.error(error)
        break
      }

      if (next) {
        if (!next.done && !this.isCancelled) {
          controller.enqueue(next.value)
        } else {
          controller.close()
        }
      }
    }

    this.isWorking = false
  }

  /**
   * @param {ReadableStreamDefaultController} controller
   */
  pull(controller) {
    if (!this.isWorking) {
      this.work(controller)
    }
  }
  cancel() {
    this.isCancelled = true
  }
}

/**
 * @param {string} [input]
 * @returns {string}
 */
const readType = (input = "") => {
  const type = String(input).toLowerCase()
  return /[^\u0020-\u007E]/.test(type) ? "" : type
}



;// CONCATENATED MODULE: ./node_modules/@web-std/blob/src/lib.node.js

// import { Blob as NodeBlob } from "./blob.node.js"
;

/** @type {typeof globalThis.Blob} */
// Our first choise is to use global `Blob` because it may be available e.g. in
// electron renderrer process. If not available fall back to node native
// implementation, if also not available use our implementation.
const lib_node_Blob =
  globalThis.Blob || 
  // Disable node native blob until impractical perf issue is fixed
  // @see https://github.com/nodejs/node/issues/42108
  // NodeBlob ||
  Blob

;// CONCATENATED MODULE: ./node_modules/@web-std/fetch/src/errors/base.js


class FetchBaseError extends Error {
	/**
	 * @param {string} message 
	 * @param {string} type 
	 */
	constructor(message, type) {
		super(message);
		// Hide custom error implementation details from end-users
		Error.captureStackTrace(this, this.constructor);

		this.type = type;
	}

	get name() {
		return this.constructor.name;
	}

	get [Symbol.toStringTag]() {
		return this.constructor.name;
	}
}


;// CONCATENATED MODULE: ./node_modules/@web-std/fetch/src/errors/fetch-error.js



/**
 * @typedef {{
 * address?: string
 * code: string
 * dest?: string
 * errno: number
 * info?: object
 * message: string
 * path?: string
 * port?: number
 * syscall: string
 * }} SystemError
*/

/**
 * FetchError interface for operational errors
 */
class FetchError extends FetchBaseError {
	/**
	 * @param  {string} message -      Error message for human
	 * @param  {string} type -        Error type for machine
	 * @param  {SystemError} [systemError] - For Node.js system error
	 */
	constructor(message, type, systemError) {
		super(message, type);
		// When err.type is `system`, err.erroredSysCall contains system error and err.code contains system error code
		if (systemError) {
			// eslint-disable-next-line no-multi-assign
			this.code = this.errno = systemError.code;
			this.erroredSysCall = systemError.syscall;
		}
	}
}

;// CONCATENATED MODULE: ./node_modules/@web3-storage/multipart-parser/esm/src/utils.js
function stringToArray(s) {
  const utf8 = unescape(encodeURIComponent(s));
  return Uint8Array.from(utf8, (_, i) => utf8.charCodeAt(i));
}
function utils_arrayToString(a) {
  const utf8 = String.fromCharCode.apply(null, a);
  return decodeURIComponent(escape(utf8));
}
function utils_mergeArrays(...arrays) {
  const out = new Uint8Array(arrays.reduce((total, arr) => total + arr.length, 0));
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.length;
  }
  return out;
}
function arraysEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}
;// CONCATENATED MODULE: ./node_modules/@web3-storage/multipart-parser/esm/src/search.js

function search_coerce(a) {
  if (a instanceof Uint8Array) {
    return index => a[index];
  }
  return a;
}
function jsmemcmp(buf1, pos1, buf2, pos2, len) {
  const fn1 = search_coerce(buf1);
  const fn2 = search_coerce(buf2);
  for (let i = 0; i < len; ++i) {
    if (fn1(pos1 + i) !== fn2(pos2 + i)) {
      return false;
    }
  }
  return true;
}
function createOccurenceTable(s) {
  const table = new Array(256).fill(s.length);
  if (s.length > 1) {
    for (let i = 0; i < s.length - 1; i++) {
      table[s[i]] = s.length - 1 - i;
    }
  }
  return table;
}
const MATCH = Symbol('Match');
class StreamSearch {
  constructor(needle) {
    this._lookbehind = new Uint8Array();
    if (typeof needle === 'string') {
      this._needle = needle = stringToArray(needle);
    } else {
      this._needle = needle;
    }
    this._lastChar = needle[needle.length - 1];
    this._occ = createOccurenceTable(needle);
  }
  feed(chunk) {
    let pos = 0;
    let tokens;
    const allTokens = [];
    while (pos !== chunk.length) {
      ;
      [pos, ...tokens] = this._feed(chunk, pos);
      allTokens.push(...tokens);
    }
    return allTokens;
  }
  end() {
    const tail = this._lookbehind;
    this._lookbehind = new Uint8Array();
    return tail;
  }
  _feed(data, bufPos) {
    const tokens = [];
    let pos = -this._lookbehind.length;
    if (pos < 0) {
      while (pos < 0 && pos <= data.length - this._needle.length) {
        const ch = this._charAt(data, pos + this._needle.length - 1);
        if (ch === this._lastChar && this._memcmp(data, pos, this._needle.length - 1)) {
          if (pos > -this._lookbehind.length) {
            tokens.push(this._lookbehind.slice(0, this._lookbehind.length + pos));
          }
          tokens.push(MATCH);
          this._lookbehind = new Uint8Array();
          return [
            pos + this._needle.length,
            ...tokens
          ];
        } else {
          pos += this._occ[ch];
        }
      }
      if (pos < 0) {
        while (pos < 0 && !this._memcmp(data, pos, data.length - pos)) {
          pos++;
        }
      }
      if (pos >= 0) {
        tokens.push(this._lookbehind);
        this._lookbehind = new Uint8Array();
      } else {
        const bytesToCutOff = this._lookbehind.length + pos;
        if (bytesToCutOff > 0) {
          tokens.push(this._lookbehind.slice(0, bytesToCutOff));
          this._lookbehind = this._lookbehind.slice(bytesToCutOff);
        }
        this._lookbehind = Uint8Array.from(new Array(this._lookbehind.length + data.length), (_, i) => this._charAt(data, i - this._lookbehind.length));
        return [
          data.length,
          ...tokens
        ];
      }
    }
    pos += bufPos;
    while (pos <= data.length - this._needle.length) {
      const ch = data[pos + this._needle.length - 1];
      if (ch === this._lastChar && data[pos] === this._needle[0] && jsmemcmp(this._needle, 0, data, pos, this._needle.length - 1)) {
        if (pos > bufPos) {
          tokens.push(data.slice(bufPos, pos));
        }
        tokens.push(MATCH);
        return [
          pos + this._needle.length,
          ...tokens
        ];
      } else {
        pos += this._occ[ch];
      }
    }
    if (pos < data.length) {
      while (pos < data.length && (data[pos] !== this._needle[0] || !jsmemcmp(data, pos, this._needle, 0, data.length - pos))) {
        ++pos;
      }
      if (pos < data.length) {
        this._lookbehind = data.slice(pos);
      }
    }
    if (pos > 0) {
      tokens.push(data.slice(bufPos, pos < data.length ? pos : data.length));
    }
    return [
      data.length,
      ...tokens
    ];
  }
  _charAt(data, pos) {
    if (pos < 0) {
      return this._lookbehind[this._lookbehind.length + pos];
    }
    return data[pos];
  }
  _memcmp(data, pos, len) {
    return jsmemcmp(this._charAt.bind(this, data), pos, this._needle, 0, len);
  }
}
class ReadableStreamSearch {
  constructor(needle, _readableStream) {
    this._readableStream = _readableStream;
    this._search = new StreamSearch(needle);
  }
  async *[Symbol.asyncIterator]() {
    const reader = this._readableStream.getReader();
    try {
      while (true) {
        const result = await reader.read();
        if (result.done) {
          break;
        }
        yield* this._search.feed(result.value);
      }
      const tail = this._search.end();
      if (tail.length) {
        yield tail;
      }
    } finally {
      reader.releaseLock();
    }
  }
}
const EOQ = Symbol('End of Queue');
class QueueableStreamSearch {
  constructor(needle) {
    this._chunksQueue = [];
    this._closed = false;
    this._search = new StreamSearch(needle);
  }
  push(...chunks) {
    if (this._closed) {
      throw new Error('cannot call push after close');
    }
    this._chunksQueue.push(...chunks);
    if (this._notify) {
      this._notify();
    }
  }
  close() {
    if (this._closed) {
      throw new Error('close was already called');
    }
    this._closed = true;
    this._chunksQueue.push(EOQ);
    if (this._notify) {
      this._notify();
    }
  }
  async *[Symbol.asyncIterator]() {
    while (true) {
      let chunk;
      while (!(chunk = this._chunksQueue.shift())) {
        await new Promise(resolve => this._notify = resolve);
        this._notify = undefined;
      }
      if (chunk === EOQ) {
        break;
      }
      yield* this._search.feed(chunk);
    }
    const tail = this._search.end();
    if (tail.length) {
      yield tail;
    }
  }
}
function splitChunks(chunks, needle) {
  const search = new StreamSearch(needle);
  const outchunks = [[]];
  for (const chunk of chunks) {
    for (const token of search.feed(chunk)) {
      if (token === MATCH) {
        outchunks.push([]);
      } else {
        outchunks[outchunks.length - 1].push(token);
      }
    }
  }
  const end = search.end();
  outchunks[outchunks.length - 1].push(end);
  return outchunks.map(chunks => mergeArrays(...chunks));
}
function split(buf, needle) {
  return splitChunks([buf], needle);
}
async function* chunksIterator(iter) {
  let chunks = [];
  for await (const value of iter) {
    if (value === MATCH) {
      yield chunks;
      chunks = [];
    } else {
      chunks.push(value);
    }
  }
  yield chunks;
}
async function* stringIterator(iter) {
  for await (const chunk of chunksIterator(iter)) {
    yield chunk.map(arrayToString).join('');
  }
}
async function allStrings(iter) {
  const segments = [];
  for await (const value of stringIterator(iter)) {
    segments.push(value);
  }
  return segments;
}
async function* arrayIterator(iter) {
  for await (const chunk of chunksIterator(iter)) {
    yield mergeArrays(...chunk);
  }
}

;// CONCATENATED MODULE: ./node_modules/@web3-storage/multipart-parser/esm/src/index.js


const mergeArrays2 = Function.prototype.apply.bind(utils_mergeArrays, undefined);
const dash = stringToArray('--');
const CRLF = stringToArray('\r\n');
function parseContentDisposition(header) {
  const parts = header.split(';').map(part => part.trim());
  if (parts.shift() !== 'form-data') {
    throw new Error('malformed content-disposition header: missing "form-data" in `' + JSON.stringify(parts) + '`');
  }
  const out = {};
  for (const part of parts) {
    const kv = part.split('=', 2);
    if (kv.length !== 2) {
      throw new Error('malformed content-disposition header: key-value pair not found - ' + part + ' in `' + header + '`');
    }
    const [name, value] = kv;
    if (value[0] === '"' && value[value.length - 1] === '"') {
      out[name] = value.slice(1, -1).replace(/\\"/g, '"');
    } else if (value[0] !== '"' && value[value.length - 1] !== '"') {
      out[name] = value;
    } else if (value[0] === '"' && value[value.length - 1] !== '"' || value[0] !== '"' && value[value.length - 1] === '"') {
      throw new Error('malformed content-disposition header: mismatched quotations in `' + header + '`');
    }
  }
  if (!out.name) {
    throw new Error('malformed content-disposition header: missing field name in `' + header + '`');
  }
  return out;
}
function parsePartHeaders(lines) {
  const entries = [];
  let disposition = false;
  let line;
  while (typeof (line = lines.shift()) !== 'undefined') {
    const colon = line.indexOf(':');
    if (colon === -1) {
      throw new Error('malformed multipart-form header: missing colon');
    }
    const header = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    switch (header) {
    case 'content-disposition':
      disposition = true;
      entries.push(...Object.entries(parseContentDisposition(value)));
      break;
    case 'content-type':
      entries.push([
        'contentType',
        value
      ]);
    }
  }
  if (!disposition) {
    throw new Error('malformed multipart-form header: missing content-disposition');
  }
  return Object.fromEntries(entries);
}
async function readHeaderLines(it, needle) {
  let firstChunk = true;
  let lastTokenWasMatch = false;
  const headerLines = [[]];
  const crlfSearch = new StreamSearch(CRLF);
  for (;;) {
    const result = await it.next();
    if (result.done) {
      throw new Error('malformed multipart-form data: unexpected end of stream');
    }
    if (firstChunk && result.value !== MATCH && arraysEqual(result.value.slice(0, 2), dash)) {
      return [
        undefined,
        new Uint8Array()
      ];
    }
    let chunk;
    if (result.value !== MATCH) {
      chunk = result.value;
    } else if (!lastTokenWasMatch) {
      chunk = needle;
    } else {
      throw new Error('malformed multipart-form data: unexpected boundary');
    }
    if (!chunk.length) {
      continue;
    }
    if (firstChunk) {
      firstChunk = false;
    }
    const tokens = crlfSearch.feed(chunk);
    for (const [i, token] of tokens.entries()) {
      const isMatch = token === MATCH;
      if (!isMatch && !token.length) {
        continue;
      }
      if (lastTokenWasMatch && isMatch) {
        tokens.push(crlfSearch.end());
        return [
          headerLines.filter(chunks => chunks.length).map(mergeArrays2).map(utils_arrayToString),
          utils_mergeArrays(...tokens.slice(i + 1).map(token => token === MATCH ? CRLF : token))
        ];
      }
      if (lastTokenWasMatch = isMatch) {
        headerLines.push([]);
      } else {
        headerLines[headerLines.length - 1].push(token);
      }
    }
  }
}
async function* streamMultipart(body, boundary) {
  const needle = utils_mergeArrays(dash, stringToArray(boundary));
  const it = new ReadableStreamSearch(needle, body)[Symbol.asyncIterator]();
  for (;;) {
    const result = await it.next();
    if (result.done) {
      return;
    }
    if (result.value === MATCH) {
      break;
    }
  }
  const crlfSearch = new StreamSearch(CRLF);
  for (;;) {
    const [headerLines, tail] = await readHeaderLines(it, needle);
    if (!headerLines) {
      return;
    }
    async function nextToken() {
      const result = await it.next();
      if (result.done) {
        throw new Error('malformed multipart-form data: unexpected end of stream');
      }
      return result;
    }
    let trailingCRLF = false;
    function feedChunk(chunk) {
      const chunks = [];
      for (const token of crlfSearch.feed(chunk)) {
        if (trailingCRLF) {
          chunks.push(CRLF);
        }
        if (!(trailingCRLF = token === MATCH)) {
          chunks.push(token);
        }
      }
      return utils_mergeArrays(...chunks);
    }
    let done = false;
    async function nextChunk() {
      const result = await nextToken();
      let chunk;
      if (result.value !== MATCH) {
        chunk = result.value;
      } else if (!trailingCRLF) {
        chunk = CRLF;
      } else {
        done = true;
        return { value: crlfSearch.end() };
      }
      return { value: feedChunk(chunk) };
    }
    const bufferedChunks = [{ value: feedChunk(tail) }];
    yield {
      ...parsePartHeaders(headerLines),
      data: {
        [Symbol.asyncIterator]() {
          return this;
        },
        async next() {
          for (;;) {
            const result = bufferedChunks.shift();
            if (!result) {
              break;
            }
            if (result.value.length > 0) {
              return result;
            }
          }
          for (;;) {
            if (done) {
              return {
                done,
                value: undefined
              };
            }
            const result = await nextChunk();
            if (result.value.length > 0) {
              return result;
            }
          }
        }
      }
    };
    while (!done) {
      bufferedChunks.push(await nextChunk());
    }
  }
}
async function* iterateMultipart(body, boundary) {
  for await (const part of streamMultipart(body, boundary)) {
    const chunks = [];
    for await (const chunk of part.data) {
      chunks.push(chunk);
    }
    yield {
      ...part,
      data: utils_mergeArrays(...chunks)
    };
  }
}
;// CONCATENATED MODULE: ./node_modules/@web-std/form-data/src/form-data.js
/**
 * @implements {globalThis.FormData}
 */
class form_data_FormData {
  /**
   * @param {HTMLFormElement} [form]
   */
  constructor(form) {
    /**
     * @private
     * @readonly
     * @type {Array<[string, FormDataEntryValue]>}
     */
    this._entries = []

    Object.defineProperty(this, "_entries", { enumerable: false })

    if (isHTMLFormElement(form)) {
      for (const element of form.elements) {
        if (isSelectElement(element)) {
          for (const option of element.options) {
            if (option.selected) {
              this.append(element.name, option.value);
            }
          }
        } else if (
          isInputElement(element) &&
          (element.checked || !["radio", "checkbox"].includes(element.type)) &&
          element.name
        ) {
          this.append(element.name, element.value);
        }
      }
    }
  }
  get [Symbol.toStringTag]() {
    return "FormData"
  }

  /**
   * Appends a new value onto an existing key inside a FormData object, or adds
   * the key if it does not already exist.
   *
   * The difference between `set` and `append` is that if the specified key
   * already exists, `set` will overwrite all existing values with the new one,
   * whereas `append` will append the new value onto the end of the existing
   * set of values.
   *
   * @param {string} name
   * @param {string|Blob|File} value - The name of the field whose data is
   * contained in value.
   * @param {string} [filename] - The filename reported to the server, when a
   * value is a `Blob` or a `File`. The default filename for a `Blob` objects is
   * `"blob"`. The default filename for a `File` is the it's name.
   */
  append(
    name,
    value = panic(
      new TypeError("FormData.append: requires at least 2 arguments")
    ),
    filename
  ) {
    this._entries.push([name, toEntryValue(value, filename)])
  }

  /**
   * Deletes a key and all its values from a FormData object.
   *
   * @param {string} name
   */
  delete(
    name = panic(new TypeError("FormData.delete: requires string argument"))
  ) {
    const entries = this._entries
    let index = 0
    while (index < entries.length) {
      const [entryName] = /** @type {[string, FormDataEntryValue]}*/ (
        entries[index]
      )
      if (entryName === name) {
        entries.splice(index, 1)
      } else {
        index++
      }
    }
  }

  /**
   * Returns the first value associated with a given key from within a
   * FormData object.
   *
   * @param {string} name
   * @returns {FormDataEntryValue|null}
   */

  get(name = panic(new TypeError("FormData.get: requires string argument"))) {
    for (const [entryName, value] of this._entries) {
      if (entryName === name) {
        return value
      }
    }
    return null
  }

  /**
   * Returns an array of all the values associated with a given key from within
   * a FormData.
   *
   * @param {string} name
   * @returns {FormDataEntryValue[]}
   */
  getAll(
    name = panic(new TypeError("FormData.getAll: requires string argument"))
  ) {
    const values = []
    for (const [entryName, value] of this._entries) {
      if (entryName === name) {
        values.push(value)
      }
    }
    return values
  }

  /**
   * Returns a boolean stating whether a FormData object contains a certain key.
   *
   * @param {string} name
   */

  has(name = panic(new TypeError("FormData.has: requires string argument"))) {
    for (const [entryName] of this._entries) {
      if (entryName === name) {
        return true
      }
    }
    return false
  }

  /**
   * Sets a new value for an existing key inside a FormData object, or adds the
   * key/value if it does not already exist.
   *
   * @param {string} name
   * @param {string|Blob|File} value
   * @param {string} [filename]
   */

  set(
    name,
    value = panic(new TypeError("FormData.set: requires at least 2 arguments")),
    filename
  ) {
    let index = 0
    const { _entries: entries } = this
    const entryValue = toEntryValue(value, filename)
    let wasSet = false
    while (index < entries.length) {
      const entry = /** @type {[string, FormDataEntryValue]}*/ (entries[index])
      if (entry[0] === name) {
        if (wasSet) {
          entries.splice(index, 1)
        } else {
          wasSet = true
          entry[1] = entryValue
          index++
        }
      } else {
        index++
      }
    }

    if (!wasSet) {
      entries.push([name, entryValue])
    }
  }

  /**
   * Method returns an iterator allowing to go through all key/value pairs
   * contained in this object.
   */
  entries() {
    return this._entries.values()
  }

  /**
   * Returns an iterator allowing to go through all keys of the key/value pairs
   * contained in this object.
   *
   * @returns {IterableIterator<string>}
   */
  *keys() {
    for (const [name] of this._entries) {
      yield name
    }
  }

  /**
   * Returns an iterator allowing to go through all values contained in this
   * object.
   *
   * @returns {IterableIterator<FormDataEntryValue>}
   */
  *values() {
    for (const [_, value] of this._entries) {
      yield value
    }
  }

  [Symbol.iterator]() {
    return this._entries.values()
  }

  /**
   * @param {(value: FormDataEntryValue, key: string, parent: globalThis.FormData) => void} fn
   * @param {any} [thisArg]
   * @returns {void}
   */
  forEach(fn, thisArg) {
    for (const [key, value] of this._entries) {
      fn.call(thisArg, value, key, this)
    }
  }
}

/**
 * @param {any} value
 * @returns {value is HTMLFormElement}
 */
const isHTMLFormElement = value =>
  Object.prototype.toString.call(value) === "[object HTMLFormElement]"

/**
 * @param {string|Blob|File} value
 * @param {string} [filename]
 * @returns {FormDataEntryValue}
 */
const toEntryValue = (value, filename) => {
  if (isFile(value)) {
    return filename != null ? new BlobFile([value], filename, value) : value
  } else if (form_data_isBlob(value)) {
    return new BlobFile([value], filename != null ? filename : "blob")
  } else {
    if (filename != null && filename != "") {
      throw new TypeError(
        "filename is only supported when value is Blob or File"
      )
    }
    return `${value}`
  }
}

/**
 * @param {any} value
 * @returns {value is File}
 */
const isFile = value =>
  Object.prototype.toString.call(value) === "[object File]" &&
  typeof value.name === "string"

/**
 * @param {any} value
 * @returns {value is Blob}
 */
const form_data_isBlob = value =>
  Object.prototype.toString.call(value) === "[object Blob]"

/**
 * Simple `File` implementation that just wraps a given blob.
 * @implements {globalThis.File}
 */
const BlobFile = class File {
  /**
   * @param {[Blob]} parts
   * @param {string} name
   * @param {FilePropertyBag} [options]
   */
  constructor([blob], name, { lastModified = Date.now() } = {}) {
    this.blob = blob
    this.name = name
    this.lastModified = lastModified
  }
  get webkitRelativePath() {
    return ""
  }
  get size() {
    return this.blob.size
  }
  get type() {
    return this.blob.type
  }
  /**
   *
   * @param {number} [start]
   * @param {number} [end]
   * @param {string} [contentType]
   */
  slice(start, end, contentType) {
    return this.blob.slice(start, end, contentType)
  }
  stream() {
    return this.blob.stream()
  }
  text() {
    return this.blob.text()
  }
  arrayBuffer() {
    return this.blob.arrayBuffer()
  }
  get [Symbol.toStringTag]() {
    return "File"
  }
}

/**
 * @param {*} error
 * @returns {never}
 */
const panic = error => {
  throw error
}

/**
 *
 * @param {Element} element
 * @returns {element is HTMLSelectElement}
 */
function isSelectElement(element) {
  return element.tagName === "SELECT";
}

/**
 *
 * @param {Element} element
 * @returns {element is HTMLInputElement}
 */
function isInputElement(element) {
  return element.tagName === "INPUT" || element.tagName === "TEXTAREA";
}

;// CONCATENATED MODULE: ./node_modules/@web-std/form-data/src/lib.node.js
// @ts-check


;

// Electron-renderer should get the browser implementation instead of node
// which is why we check global first.
const lib_node_FormData =
  typeof globalThis.FormData === "function"
    ? globalThis.FormData
    : form_data_FormData

;// CONCATENATED MODULE: ./node_modules/@web-std/file/src/package.js


;// CONCATENATED MODULE: ./node_modules/@web-std/file/src/file.js


/**
 * @implements {globalThis.File}
 */
class File extends lib_node_Blob {
  /**
   *
   * @param {BlobPart[]} init
   * @param {string} name - A USVString representing the file name or the path
   * to the file.
   * @param {FilePropertyBag} [options]
   */
  constructor(
    init,
    name = file_panic(new TypeError("File constructor requires name argument")),
    options = {}
  ) {
    super(init, options)
    // Per File API spec https://w3c.github.io/FileAPI/#file-constructor
    // Every "/" character of file name must be replaced with a ":".
    /** @private */
    this._name = name
    // It appears that browser do not follow the spec here.
    // String(name).replace(/\//g, ":")
    /** @private */
    this._lastModified = options.lastModified || Date.now()
  }

  /**
   * The name of the file referenced by the File object.
   * @type {string}
   */
  get name() {
    return this._name
  }

  /**
   * The path the URL of the File is relative to.
   * @type {string}
   */
  get webkitRelativePath() {
    return ""
  }

  /**
   * Returns the last modified time of the file, in millisecond since the UNIX
   * epoch (January 1st, 1970 at Midnight).
   * @returns {number}
   */
  get lastModified() {
    return this._lastModified
  }

  get [Symbol.toStringTag]() {
    return "File"
  }
}

/**
 * @param {*} error
 * @returns {never}
 */
const file_panic = error => {
  throw error
}

;// CONCATENATED MODULE: ./node_modules/@web-std/file/src/lib.node.js


;


// Electron-renderer should get the browser implementation instead of node
// Browser configuration is not enough

// Marking export as a DOM File object instead of custom class.
/** @type {typeof globalThis.File} */
const lib_node_File = typeof globalThis.File === "function" ? globalThis.File : File



;// CONCATENATED MODULE: ./node_modules/@web-std/fetch/src/utils/is.js


/**
 * Is.js
 *
 * Object type checks.
 */

const NAME = Symbol.toStringTag;

/**
 * Check if `obj` is a URLSearchParams object
 * ref: https://github.com/node-fetch/node-fetch/issues/296#issuecomment-307598143
 *
 * @param  {any} object
 * @return {obj is URLSearchParams}
 */
const isURLSearchParameters = (object) => {
	return (
		typeof object === "object" &&
		typeof object.append === "function" &&
		typeof object.delete === "function" &&
		typeof object.get === "function" &&
		typeof object.getAll === "function" &&
		typeof object.has === "function" &&
		typeof object.set === "function" &&
		typeof object.sort === "function" &&
		object[NAME] === "URLSearchParams"
	);
};

/**
 * Check if `object` is a W3C `Blob` object (which `File` inherits from)
 *
 * @param  {*} object
 * @return {object is Blob}
 */
const is_isBlob = (object) => {
	return (
		typeof object === "object" &&
		typeof object.arrayBuffer === "function" &&
		typeof object.type === "string" &&
		typeof object.stream === "function" &&
		typeof object.constructor === "function" &&
		/^(Blob|File)$/.test(object[NAME])
	);
};

/**
 * Check if `obj` is a spec-compliant `FormData` object
 *
 * @param {*} object
 * @return {object is FormData}
 */
function isFormData(object) {
	return (
		typeof object === "object" &&
		typeof object.append === "function" &&
		typeof object.set === "function" &&
		typeof object.get === "function" &&
		typeof object.getAll === "function" &&
		typeof object.delete === "function" &&
		typeof object.keys === "function" &&
		typeof object.values === "function" &&
		typeof object.entries === "function" &&
		typeof object.constructor === "function" &&
		object[NAME] === "FormData"
	);
}

/**
 * Detect form data input from form-data module
 *
 * @param {any} value
 * @returns {value is Stream & {getBoundary():string, hasKnownLength():boolean, getLengthSync():number|null}}
 */
const isMultipartFormDataStream = (value) => {
	return (
		value instanceof external_stream_ === true &&
		typeof value.getBoundary === "function" &&
		typeof value.hasKnownLength === "function" &&
		typeof value.getLengthSync === "function"
	);
};

/**
 * Check if `obj` is an instance of AbortSignal.
 *
 * @param  {any} object
 * @return {obj is AbortSignal}
 */
const isAbortSignal = (object) => {
	return (
		typeof object === "object" &&
		(object[NAME] === "AbortSignal" || object[NAME] === "EventTarget")
	);
};

/**
 * Check if `value` is a ReadableStream.
 *
 * @param {*} value
 * @returns {value is ReadableStream}
 */
const is_isReadableStream = (value) => {
	return (
		typeof value === "object" &&
		typeof value.getReader === "function" &&
		typeof value.cancel === "function" &&
		typeof value.tee === "function"
	);
};

/**
 *
 * @param {any} value
 * @returns {value is Iterable<unknown>}
 */
const is_isIterable = (value) => value && Symbol.iterator in value;

;// CONCATENATED MODULE: ./node_modules/@web-std/fetch/src/utils/form-data.js





const carriage = '\r\n';
const dashes = '-'.repeat(2);
const carriageLength = Buffer.byteLength(carriage);

/**
 * @param {string} boundary
 */
const getFooter = boundary => `${dashes}${boundary}${dashes}${carriage.repeat(2)}`;

/**
 * @param {string} boundary
 * @param {string} name
 * @param {*} field
 *
 * @return {string}
 */
function getHeader(boundary, name, field) {
	let header = '';

	header += `${dashes}${boundary}${carriage}`;
	header += `Content-Disposition: form-data; name="${name}"`;

	if (is_isBlob(field)) {
		const { name = 'blob', type } = /** @type {Blob & {name?:string}} */ (field);
		header += `; filename="${name}"${carriage}`;
		header += `Content-Type: ${type || 'application/octet-stream'}`;
	}

	return `${header}${carriage.repeat(2)}`;
}

/**
 * @return {string}
 */
const getBoundary = () => (0,external_crypto_.randomBytes)(8).toString('hex');

/**
 * @param {FormData} form
 * @param {string} boundary
 */
async function * formDataIterator(form, boundary) {
	const encoder = new TextEncoder();
	for (const [name, value] of form) {
		yield encoder.encode(getHeader(boundary, name, value));

		if (is_isBlob(value)) {
			// @ts-ignore - we know our streams implement aysnc iteration
			yield * value.stream();
		} else {
			yield encoder.encode(value);
		}

		yield encoder.encode(carriage);
	}

	yield encoder.encode(getFooter(boundary));
}

/**
 * @param {FormData} form
 * @param {string} boundary
 */
function getFormDataLength(form, boundary) {
	let length = 0;

	for (const [name, value] of form) {
		length += Buffer.byteLength(getHeader(boundary, name, value));

		if (is_isBlob(value)) {
			length += value.size;
		} else {
			length += Buffer.byteLength(String(value));
		}

		length += carriageLength;
	}

	length += Buffer.byteLength(getFooter(boundary));

	return length;
}

/**
 * @param {Body & {headers?:Headers}} source
 */
const toFormData = async (source) => {
  let { body, headers } = source;
  const contentType = headers?.get('Content-Type') || ''

  if (contentType.startsWith('application/x-www-form-urlencoded') && body != null) {
	const form = new lib_node_FormData();
	let bodyText = await source.text();
	new URLSearchParams(bodyText).forEach((v, k) => form.append(k, v));
	return form;
  }

  const [type, boundary] = contentType.split(/\s*;\s*boundary=/)
  if (type === 'multipart/form-data' && boundary != null && body != null) {
    const form = new lib_node_FormData()
    const parts = iterateMultipart(body, boundary)
    for await (const { name, data, filename, contentType } of parts) {
      if (typeof filename === 'string') {
        form.append(name, new lib_node_File([data], filename, { type: contentType }))
      } else if (typeof filename !== 'undefined') {
        form.append(name, new lib_node_File([], '', { type: contentType }))
      } else {
        form.append(name, new TextDecoder().decode(data), filename)
      }
    }
    return form
  } else {
    throw new TypeError('Could not parse content as FormData.')
  }
}

;// CONCATENATED MODULE: ./node_modules/@web-std/fetch/src/utils/utf8.js


const encoder = new external_util_.TextEncoder();
const decoder = new external_util_.TextDecoder();

/**
 * @param {string} text
 */
const utf8_encode = text => encoder.encode(text);

/**
 * @param {Uint8Array} bytes
 */
const utf8_decode = bytes => decoder.decode(bytes);

;// CONCATENATED MODULE: ./node_modules/@web-std/fetch/src/body.js
// @ts-check
/**
 * Body.js
 *
 * Body interface provides common methods for Request and Response
 */











const {readableHighWaterMark} = new external_stream_.Readable();

const INTERNALS = Symbol('Body internals');

/**
 * Body mixin
 *
 * Ref: https://fetch.spec.whatwg.org/#body
 * @implements {globalThis.Body}
 */

class Body {
	/**
	 * @param {BodyInit|Stream|null} body
	 * @param {{size?:number}} options
	 */
	constructor(body, {
		size = 0
	} = {}) {
		const state = {
			/** @type {null|ReadableStream<Uint8Array>} */
			body: null,
			/** @type {string|null} */
			type: null,
			/** @type {number|null} */
			size: null,
			/** @type {null|string} */
			boundary: null,
			disturbed: false,
			/** @type {null|Error} */
			error: null
		};
		/** @private */
		this[INTERNALS] = state;

		if (body === null) {
			// Body is undefined or null
			state.body = null;
			state.size = 0;
		} else if (isURLSearchParameters(body)) {
		// Body is a URLSearchParams
			const bytes = utf8_encode(body.toString());
			state.body = body_fromBytes(bytes);
			state.size = bytes.byteLength;
			state.type = 'application/x-www-form-urlencoded;charset=UTF-8';
		} else if (is_isBlob(body)) {
			// Body is blob
			state.size = body.size;
			state.type = body.type || null;
			state.body = body.stream();
		} else if (body instanceof Uint8Array) {
			// Body is Buffer
			state.body = body_fromBytes(body);
			state.size = body.byteLength;
		} else if (external_util_.types.isAnyArrayBuffer(body)) {
			// Body is ArrayBuffer
			const bytes = new Uint8Array(body);
			state.body = body_fromBytes(bytes);
			state.size = bytes.byteLength;
		} else if (ArrayBuffer.isView(body)) {
			// Body is ArrayBufferView
			const bytes = new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
			state.body = body_fromBytes(bytes);
			state.size = bytes.byteLength;
		} else if (is_isReadableStream(body)) {
			// Body is stream
			state.body = body;
		} else if (isFormData(body)) {
			// Body is an instance of formdata-node
			const boundary = `NodeFetchFormDataBoundary${getBoundary()}`;
			state.type = `multipart/form-data; boundary=${boundary}`;
			state.size = getFormDataLength(body, boundary);
			state.body = fromAsyncIterable(formDataIterator(body, boundary));
		} else if (isMultipartFormDataStream(body)) {
			state.type = `multipart/form-data; boundary=${body.getBoundary()}`;
			state.size = body.hasKnownLength() ? body.getLengthSync() : null;
			state.body = body_fromStream(body);
		} else if (body instanceof external_stream_) {
			state.body = body_fromStream(body);
		} else {
			// None of the above
			// coerce to string then buffer
			const bytes = utf8_encode(String(body));
			state.type = 'text/plain;charset=UTF-8';
			state.size = bytes.byteLength;
			state.body = body_fromBytes(bytes);
		}

		this.size = size;

		// if (body instanceof Stream) {
		// 	body.on('error', err => {
		// 		const error = err instanceof FetchBaseError ?
		// 			err :
		// 			new FetchError(`Invalid response body while trying to fetch ${this.url}: ${err.message}`, 'system', err);
		// 		this[INTERNALS].error = error;
		// 	});
		// }
	}

	/** @type {Headers} */
	/* c8 ignore next 3 */
	get headers() {
		throw new TypeError(`'get headers' called on an object that does not implements interface.`)
	}

	get body() {
		return this[INTERNALS].body;
	}

	get bodyUsed() {
		return this[INTERNALS].disturbed;
	}

	/**
	 * Decode response as ArrayBuffer
	 *
	 * @return {Promise<ArrayBuffer>}
	 */
	async arrayBuffer() {
		const {buffer, byteOffset, byteLength} = await consumeBody(this);
		return buffer.slice(byteOffset, byteOffset + byteLength);
	}

	/**
	 * Return raw response as Blob
	 *
	 * @return Promise
	 */
	async blob() {
		const ct = (this.headers && this.headers.get('content-type')) || (this[INTERNALS].body && this[INTERNALS].type) || '';
		const buf = await consumeBody(this);

		return new lib_node_Blob([buf], {
			type: ct
		});
	}

	/**
	 * Decode response as json
	 *
	 * @return  Promise
	 */
	async json() {
		return JSON.parse(await this.text());
	}

	/**
	 * Decode response as text
	 *
	 * @return  Promise
	 */
	async text() {
		const buffer = await consumeBody(this);
		return utf8_decode(buffer);
	}

	/**
	 * @returns {Promise<FormData>}
	 */

	async formData() {
		return toFormData(this)
	}
}

// In browsers, all properties are enumerable.
Object.defineProperties(Body.prototype, {
	body: {enumerable: true},
	bodyUsed: {enumerable: true},
	arrayBuffer: {enumerable: true},
	blob: {enumerable: true},
	json: {enumerable: true},
	text: {enumerable: true},
	formData: {enumerable: true}
});

/**
 * Consume and convert an entire Body to a Buffer.
 *
 * Ref: https://fetch.spec.whatwg.org/#concept-body-consume-body
 *
 * @param {Body & {url?:string}} data
 * @return {Promise<Uint8Array>}
 */
async function consumeBody(data) {
	const state = data[INTERNALS];
	if (state.disturbed) {
		throw new TypeError(`body used already for: ${data.url}`);
	}

	state.disturbed = true;

	if (state.error) {
		throw state.error;
	}

	const {body} = state;

	// Body is null
	if (body === null) {
		return new Uint8Array(0);
	}

	// Body is stream
	// get ready to actually consume the body
	/** @type {[Uint8Array|null, Uint8Array[], number]} */
	const [buffer, chunks, limit] = data.size > 0 ?
		[new Uint8Array(data.size), [], data.size] :
		[null, [], Infinity];
	let offset = 0;

	const source = streamIterator(body);
	try {
		for await (const chunk of source) {
			const bytes = chunk instanceof Uint8Array ?
				chunk :
				Buffer.from(chunk);

			if (offset + bytes.byteLength > limit) {
				const error = new FetchError(`content size at ${data.url} over limit: ${limit}`, 'max-size');
				source.throw(error);
				throw error;
			} else if (buffer) {
				buffer.set(bytes, offset);
			} else {
				chunks.push(bytes);
			}

			offset += bytes.byteLength;
		}

		if (buffer) {
			if (offset < buffer.byteLength) {
				throw new FetchError(`Premature close of server response while trying to fetch ${data.url}`, 'premature-close');
			} else {
				return buffer;
			}
		} else {
			return writeBytes(new Uint8Array(offset), chunks);
		}
	} catch (error) {
		if (error instanceof FetchBaseError) {
			throw error;
		// @ts-expect-error - we know it will have a name
		} else if (error && error.name === 'AbortError') {
			throw error;
		} else {
			const e = /** @type {import('./errors/fetch-error').SystemError} */(error)
			// Other errors, such as incorrect content-encoding
			throw new FetchError(`Invalid response body while trying to fetch ${data.url}: ${e.message}`, 'system', e);
		}
	}
}

/**
 * Clone body given Res/Req instance
 *
 * @param {Body} instance       Response or Request instance
 * @return {ReadableStream<Uint8Array> | null}
 */
const clone = instance => {
	const {body} = instance;

	// Don't allow cloning a used body
	if (instance.bodyUsed) {
		throw new Error('cannot clone body after it is used');
	}

	if (!body) {
		return null;
	}

	const [left, right] = body.tee();
	instance[INTERNALS].body = left;
	return right;
};

/**
 * Performs the operation "extract a `Content-Type` value from |object|" as
 * specified in the specification:
 * https://fetch.spec.whatwg.org/#concept-bodyinit-extract
 *
 * This function assumes that instance.body is present.
 *
 * @param {Body} source Any options.body input
 * @returns {string | null}
 */
const extractContentType = source => source[INTERNALS].type;

/**
 * The Fetch Standard treats this as if "total bytes" is a property on the body.
 * For us, we have to explicitly get it with a function.
 *
 * ref: https://fetch.spec.whatwg.org/#concept-body-total-bytes
 *
 * @param {Body} source - Body object from the Body instance.
 * @returns {number | null}
 */
const getTotalBytes = source => source[INTERNALS].size;

/**
 * Write a Body to a Node.js WritableStream (e.g. http.Request) object.
 *
 * @param {Stream.Writable} dest - The stream to write to.
 * @param {Body} source - Body object from the Body instance.
 * @returns {void}
 */
const body_writeToStream = (dest, {body}) => {
	if (body === null) {
		// Body is null
		dest.end();
	} else {
		external_stream_.Readable.from(streamIterator(body)).pipe(dest);
	}
};

/**
 * @template T
 * @implements {AsyncGenerator<T, void, void>}
 */
class StreamIterableIterator {
	/**
	 * @param {ReadableStream<T>} stream
	 */
	constructor(stream) {
		this.stream = stream;
		this.reader = null;
	}

	/**
	 * @returns {AsyncGenerator<T, void, void>}
	 */
	[Symbol.asyncIterator]() {
		return this;
	}

	getReader() {
		if (this.reader) {
			return this.reader;
		}

		const reader = this.stream.getReader();
		this.reader = reader;
		return reader;
	}

	/**
	 * @returns {Promise<IteratorResult<T, void>>}
	 */
	next() {
		return /** @type {Promise<IteratorResult<T, void>>} */ (this.getReader().read());
	}

	/**
	 * @returns {Promise<IteratorResult<T, void>>}
	 */
	async return() {
		if (this.reader) {
			await this.reader.cancel();
		}

		return {done: true, value: undefined};
	}

	/**
	 * 
	 * @param {any} error 
	 * @returns {Promise<IteratorResult<T, void>>}
	 */
	async throw(error) {
		await this.getReader().cancel(error);
		return {done: true, value: undefined};
	}
}

/**
 * @template T
 * @param {ReadableStream<T>} stream
 */
const streamIterator = stream => new StreamIterableIterator(stream);

/**
 * @param {Uint8Array} buffer
 * @param {Uint8Array[]} chunks
 */
const writeBytes = (buffer, chunks) => {
	let offset = 0;
	for (const chunk of chunks) {
		buffer.set(chunk, offset);
		offset += chunk.byteLength;
	}

	return buffer;
};

/**
 * @param {Uint8Array} bytes
 * @returns {ReadableStream<Uint8Array>}
 */
// @ts-ignore
const body_fromBytes = bytes => new ReadableStream({
	start(controller) {
		controller.enqueue(bytes);
		controller.close();
	}
});

/**
 * @param {AsyncIterable<Uint8Array>} content
 * @returns {ReadableStream<Uint8Array>}
 */
const fromAsyncIterable = content =>
	// @ts-ignore
	new ReadableStream(new AsyncIterablePump(content));

/**
 * @implements {UnderlyingSource<Uint8Array>}
 */
class AsyncIterablePump {
	/**
	 * @param {AsyncIterable<Uint8Array>} source
	 */
	constructor(source) {
		this.source = source[Symbol.asyncIterator]();
	}

	/**
	 * @param {ReadableStreamController<Uint8Array>} controller
	 */
	async pull(controller) {
		try {
			while (controller.desiredSize || 0 > 0) {
				// eslint-disable-next-line no-await-in-loop
				const next = await this.source.next();
				if (next.done) {
					controller.close();
					break;
				} else {
					controller.enqueue(next.value);
				}
			}
		} catch (error) {
			controller.error(error);
		}
	}

	/**
	 * @param {any} [reason]
	 */
	cancel(reason) {
		if (reason) {
			if (typeof this.source.throw === 'function') {
				this.source.throw(reason);
			} else if (typeof this.source.return === 'function') {
				this.source.return();
			}
		} else if (typeof this.source.return === 'function') {
			this.source.return();
		}
	}
}

/**
 * @param {Stream & {readableHighWaterMark?:number}} source
 * @returns {ReadableStream<Uint8Array>}
 */
const body_fromStream = source => {
	const pump = new StreamPump(source);
	const stream = new ReadableStream(pump, pump);
	return stream;
};

/**
 * @implements {UnderlyingSource<Uint8Array>}
 * @implements {QueuingStrategy<Uint8Array>}
 */
class StreamPump {
	/**
	 * @param {Stream & {
	 * 	readableHighWaterMark?: number
	 * 	readable?:boolean,
	 * 	resume?: () => void,
	 * 	pause?: () => void
	 * 	destroy?: (error?:Error) => void
	 * }} stream
	 */
	constructor(stream) {
		this.highWaterMark = stream.readableHighWaterMark || readableHighWaterMark;
		this.accumalatedSize = 0;
		this.stream = stream;
		this.enqueue = this.enqueue.bind(this);
		this.error = this.error.bind(this);
		this.close = this.close.bind(this);
	}

	/**
	 * @param {Uint8Array} [chunk]
	 */
	size(chunk) {
		return chunk?.byteLength || 0;
	}

	/**
	 * @param {ReadableStreamController<Uint8Array>} controller
	 */
	start(controller) {
		this.controller = controller;
		this.stream.on('data', this.enqueue);
		this.stream.once('error', this.error);
		this.stream.once('end', this.close);
		this.stream.once('close', this.close);
	}

	pull() {
		this.resume();
	}

	/**
	 * @param {any} [reason]
	 */
	cancel(reason) {
		if (this.stream.destroy) {
			this.stream.destroy(reason);
		}

		this.stream.off('data', this.enqueue);
		this.stream.off('error', this.error);
		this.stream.off('end', this.close);
		this.stream.off('close', this.close);
	}

	/**
	 * @param {Uint8Array|string} chunk
	 */
	enqueue(chunk) {
		if (this.controller) {
			try {
				const bytes = chunk instanceof Uint8Array ?
					chunk :
					Buffer.from(chunk);

				const available = (this.controller.desiredSize || 0) - bytes.byteLength;
				this.controller.enqueue(bytes);
				if (available <= 0) {
					this.pause();
				}
			} catch {
				this.controller.error(new Error('Could not create Buffer, chunk must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object'));
				this.cancel();
			}
		}
	}

	pause() {
		if (this.stream.pause) {
			this.stream.pause();
		}
	}

	resume() {
		if (this.stream.readable && this.stream.resume) {
			this.stream.resume();
		}
	}

	close() {
		if (this.controller) {
			this.controller.close();
			delete this.controller;
		}
	}

	/**
	 * @param {Error} error 
	 */
	error(error) {
		if (this.controller) {
			this.controller.error(error);
			delete this.controller;
		}
	}
}

;// CONCATENATED MODULE: ./node_modules/@web-std/fetch/src/headers.js
/**
 * Headers.js
 *
 * Headers class offers convenient helpers
 */





const validators = /** @type {{validateHeaderName?:(name:string) => any, validateHeaderValue?:(name:string, value:string) => any}} */
(external_http_)

const validateHeaderName = typeof validators.validateHeaderName === 'function' ?
	validators.validateHeaderName :
	/**
	 * @param {string} name 
	 */
	name => {
		if (!/^[\^`\-\w!#$%&'*+.|~]+$/.test(name)) {
			const err = new TypeError(`Header name must be a valid HTTP token [${name}]`);
			Object.defineProperty(err, 'code', {value: 'ERR_INVALID_HTTP_TOKEN'});
			throw err;
		}
	};

const validateHeaderValue = typeof validators.validateHeaderValue === 'function' ?
	validators.validateHeaderValue :
	/**
	 * @param {string} name 
	 * @param {string} value 
	 */
	(name, value) => {
		if (/[^\t\u0020-\u007E\u0080-\u00FF]/.test(value)) {
			const err = new TypeError(`Invalid character in header content ["${name}"]`);
			Object.defineProperty(err, 'code', {value: 'ERR_INVALID_CHAR'});
			throw err;
		}
	};

/**
 * @typedef {Headers | Record<string, string> | Iterable<readonly [string, string]> | Iterable<Iterable<string>>} HeadersInit
 */

/**
 * This Fetch API interface allows you to perform various actions on HTTP request and response headers.
 * These actions include retrieving, setting, adding to, and removing.
 * A Headers object has an associated header list, which is initially empty and consists of zero or more name and value pairs.
 * You can add to this using methods like append() (see Examples.)
 * In all methods of this interface, header names are matched by case-insensitive byte sequence.
 *
 * @implements {globalThis.Headers}
 */
class Headers extends URLSearchParams {
	/**
	 * Headers class
	 *
	 * @constructor
	 * @param {HeadersInit} [init] - Response headers
	 */
	constructor(init) {
		// Validate and normalize init object in [name, value(s)][]
		/** @type {string[][]} */
		let result = [];
		if (init instanceof Headers) {
			const raw = init.raw();
			for (const [name, values] of Object.entries(raw)) {
				result.push(...values.map(value => [name, value]));
			}
		} else if (init == null) { // eslint-disable-line no-eq-null, eqeqeq
			// No op
		} else if (is_isIterable(init)) {
			// Sequence<sequence<ByteString>>
			// Note: per spec we have to first exhaust the lists then process them
			result = [...init]
				.map(pair => {
					if (
						typeof pair !== 'object' || external_util_.types.isBoxedPrimitive(pair)
					) {
						throw new TypeError('Each header pair must be an iterable object');
					}

					return [...pair];
				}).map(pair => {
					if (pair.length !== 2) {
						throw new TypeError('Each header pair must be a name/value tuple');
					}

					return [...pair];
				});
		} else if (typeof init === "object" && init !== null) {
			// Record<ByteString, ByteString>
			result.push(...Object.entries(init));
		} else {
			throw new TypeError('Failed to construct \'Headers\': The provided value is not of type \'(sequence<sequence<ByteString>> or record<ByteString, ByteString>)');
		}

		// Validate and lowercase
		result =
			result.length > 0 ?
				result.map(([name, value]) => {
					validateHeaderName(name);
					validateHeaderValue(name, String(value));
					return [String(name).toLowerCase(), String(value)];
				}) :
				[];

		super(result);

		// Returning a Proxy that will lowercase key names, validate parameters and sort keys
		// eslint-disable-next-line no-constructor-return
		return new Proxy(this, {
			get(target, p, receiver) {
				switch (p) {
					case 'append':
					case 'set':
						/**
						 * @param {string} name
						 * @param {string} value
						 */
						return (name, value) => {
							validateHeaderName(name);
							validateHeaderValue(name, String(value));
							return URLSearchParams.prototype[p].call(
								receiver,
								String(name).toLowerCase(),
								String(value)
							);
						};

					case 'delete':
					case 'has':
					case 'getAll':
						/**
						 * @param {string} name
						 */
						return name => {
							validateHeaderName(name);
							// @ts-ignore
							return URLSearchParams.prototype[p].call(
								receiver,
								String(name).toLowerCase()
							);
						};

					case 'keys':
						return () => {
							target.sort();
							return new Set(URLSearchParams.prototype.keys.call(target)).keys();
						};

					default:
						return Reflect.get(target, p, receiver);
				}
			}
			/* c8 ignore next */
		});
	}

	get [Symbol.toStringTag]() {
		return this.constructor.name;
	}

	toString() {
		return Object.prototype.toString.call(this);
	}

	/**
	 * 
	 * @param {string} name 
	 */
	get(name) {
		const values = this.getAll(name);
		if (values.length === 0) {
			return null;
		}

		let value = values.join(', ');
		if (/^content-encoding$/i.test(name)) {
			value = value.toLowerCase();
		}

		return value;
	}

	/**
	 * @param {(value: string, key: string, parent: this) => void} callback 
	 * @param {any} thisArg 
	 * @returns {void}
	 */
	forEach(callback, thisArg = undefined) {
		for (const name of this.keys()) {
			if (name.toLowerCase() === 'set-cookie') {
				let cookies = this.getAll(name);
				while (cookies.length > 0) {
					Reflect.apply(callback, thisArg, [cookies.shift(), name, this])
				}
			} else {
				Reflect.apply(callback, thisArg, [this.get(name), name, this]);
			}
		}
	}

	/**
	 * @returns {IterableIterator<string>}
	 */
	* values() {
		for (const name of this.keys()) {
			if (name.toLowerCase() === 'set-cookie') {
				let cookies = this.getAll(name);
				while (cookies.length > 0) {
					yield /** @type {string} */(cookies.shift());
				}
			} else {
				yield /** @type {string} */(this.get(name));
			}
		}
	}

	/**
	 * @returns {IterableIterator<[string, string]>}
	 */
	* entries() {
		for (const name of this.keys()) {
			if (name.toLowerCase() === 'set-cookie') {
				let cookies = this.getAll(name);
				while (cookies.length > 0) {
					yield [name, /** @type {string} */(cookies.shift())];
				}
			} else {
				yield [name, /** @type {string} */(this.get(name))];
			}
		}
	}

	[Symbol.iterator]() {
		return this.entries();
	}

	/**
	 * Node-fetch non-spec method
	 * returning all headers and their values as array
	 * @returns {Record<string, string[]>}
	 */
	raw() {
		return [...this.keys()].reduce((result, key) => {
			result[key] = this.getAll(key);
			return result;
		}, /** @type {Record<string, string[]>} */({}));
	}

	/**
	 * For better console.log(headers) and also to convert Headers into Node.js Request compatible format
	 */
	[Symbol.for('nodejs.util.inspect.custom')]() {
		return [...this.keys()].reduce((result, key) => {
			const values = this.getAll(key);
			// Http.request() only supports string as Host header.
			// This hack makes specifying custom Host header possible.
			if (key === 'host') {
				result[key] = values[0];
			} else {
				result[key] = values.length > 1 ? values : values[0];
			}

			return result;
		}, /** @type {Record<string, string|string[]>} */({}));
	}
}

/**
 * Re-shaping object for Web IDL tests
 * Only need to do it for overridden methods
 */
Object.defineProperties(
	Headers.prototype,
	['get', 'entries', 'forEach', 'values'].reduce((result, property) => {
		result[property] = {enumerable: true};
		return result;
	}, /** @type {Record<string, {enumerable:true}>} */ ({}))
);

/**
 * Create a Headers object from an http.IncomingMessage.rawHeaders, ignoring those that do
 * not conform to HTTP grammar productions.
 * @param {import('http').IncomingMessage['rawHeaders']} headers
 */
function fromRawHeaders(headers = []) {
	return new Headers(
		headers
			// Split into pairs
			.reduce((result, value, index, array) => {
				if (index % 2 === 0) {
					result.push(array.slice(index, index + 2));
				}

				return result;
			}, /** @type {string[][]} */([]))
			.filter(([name, value]) => {
				try {
					validateHeaderName(name);
					validateHeaderValue(name, String(value));
					return true;
				} catch {
					return false;
				}
			})

	);
}

;// CONCATENATED MODULE: ./node_modules/@web-std/fetch/src/utils/is-redirect.js
const redirectStatus = new Set([301, 302, 303, 307, 308]);

/**
 * Redirect code matching
 *
 * @param {number} code - Status code
 * @return {boolean}
 */
const isRedirect = code => {
	return redirectStatus.has(code);
};

;// CONCATENATED MODULE: ./node_modules/@web-std/fetch/src/response.js
/**
 * Response.js
 *
 * Response class provides content decoding
 */





const response_INTERNALS = Symbol('Response internals');

/**
 * Response class
 * 
 * @typedef {Object} Ext
 * @property {number} [size]
 * @property {string} [url]
 * @property {number} [counter]
 * @property {number} [highWaterMark]
 * 
 * @implements {globalThis.Response}
 */
class Response extends Body {
	/**
	 * @param {BodyInit|import('stream').Stream|null} [body] - Readable stream
	 * @param {ResponseInit & Ext} [options] - Response options
	 */
	constructor(body = null, options = {}) {
		super(body, options);

		const status = options.status || 200;
		const headers = new Headers(options.headers);

		if (body !== null && !headers.has('Content-Type')) {
			const contentType = extractContentType(this);
			if (contentType) {
				headers.append('Content-Type', contentType);
			}
		}

		/**
		 * @private
		*/
		this[response_INTERNALS] = {
			url: options.url,
			status,
			statusText: options.statusText || '',
			headers,
			counter: options.counter || 0,
			highWaterMark: options.highWaterMark
		};
	}

	/**
	 * @type {ResponseType}
	 */
	get type() {
		return "default"
	}

	get url() {
		return this[response_INTERNALS].url || '';
	}

	get status() {
		return this[response_INTERNALS].status;
	}

	/**
	 * Convenience property representing if the request ended normally
	 */
	get ok() {
		return this[response_INTERNALS].status >= 200 && this[response_INTERNALS].status < 300;
	}

	get redirected() {
		return this[response_INTERNALS].counter > 0;
	}

	get statusText() {
		return this[response_INTERNALS].statusText;
	}

	/**
	 * @type {Headers}
	 */
	get headers() {
		return this[response_INTERNALS].headers;
	}

	get highWaterMark() {
		return this[response_INTERNALS].highWaterMark;
	}

	/**
	 * Clone this response
	 *
	 * @returns {Response}
	 */
	clone() {
		return new Response(clone(this), {
			url: this.url,
			status: this.status,
			statusText: this.statusText,
			headers: this.headers,
			size: this.size
		});
	}

	/**
	 * @param {string} url    The URL that the new response is to originate from.
	 * @param {number} status An optional status code for the response (e.g., 302.)
	 * @returns {Response}    A Response object.
	 */
	static redirect(url, status = 302) {
		if (!isRedirect(status)) {
			throw new RangeError('Failed to execute "redirect" on "response": Invalid status code');
		}

		return new Response(null, {
			headers: {
				location: new URL(url).toString()
			},
			status
		});
	}

	get [Symbol.toStringTag]() {
		return 'Response';
	}
}

Object.defineProperties(Response.prototype, {
	url: {enumerable: true},
	status: {enumerable: true},
	ok: {enumerable: true},
	redirected: {enumerable: true},
	statusText: {enumerable: true},
	headers: {enumerable: true},
	clone: {enumerable: true}
});


// EXTERNAL MODULE: external "url"
var external_url_ = __webpack_require__(57310);
// EXTERNAL MODULE: ./node_modules/abort-controller/dist/abort-controller.js
var abort_controller = __webpack_require__(8541);
;// CONCATENATED MODULE: ./node_modules/@web-std/fetch/src/utils/get-search.js
/**
 * @param {URL} parsedURL 
 * @returns {string}
 */
const getSearch = parsedURL => {
	if (parsedURL.search) {
		return parsedURL.search;
	}

	const lastOffset = parsedURL.href.length - 1;
	const hash = parsedURL.hash || (parsedURL.href[lastOffset] === '#' ? '#' : '');
	return parsedURL.href[lastOffset - hash.length] === '?' ? '?' : '';
};

;// CONCATENATED MODULE: ./node_modules/@web-std/fetch/src/request.js

/**
 * Request.js
 *
 * Request class contains server only options
 *
 * All spec algorithm step numbers are based on https://fetch.spec.whatwg.org/commit-snapshots/ae716822cb3a61843226cd090eefc6589446c1d2/.
 */








const request_INTERNALS = Symbol('Request internals');

const forbiddenMethods = new Set(["CONNECT", "TRACE", "TRACK"]);
const normalizedMethods = new Set(["DELETE", "GET", "HEAD", "OPTIONS", "POST", "PUT"]);

/**
 * Check if `obj` is an instance of Request.
 *
 * @param  {any} object
 * @return {object is Request}
 */
const isRequest = object => {
	return (
		typeof object === 'object' &&
		typeof object[request_INTERNALS] === 'object'
	);
};


/**
 * Request class
 * @implements {globalThis.Request}
 *
 * @typedef {Object} RequestState
 * @property {string} method
 * @property {RequestRedirect} redirect
 * @property {globalThis.Headers} headers
 * @property {RequestCredentials} credentials
 * @property {URL} parsedURL
 * @property {AbortSignal|null} signal
 *
 * @typedef {Object} RequestExtraOptions
 * @property {number} [follow]
 * @property {boolean} [compress]
 * @property {number} [size]
 * @property {number} [counter]
 * @property {Agent} [agent]
 * @property {number} [highWaterMark]
 * @property {boolean} [insecureHTTPParser]
 *
 * @typedef {((url:URL) => import('http').Agent | import('https').Agent) | import('http').Agent | import('https').Agent} Agent
 *
 * @typedef {Object} RequestOptions
 * @property {string} [method]
 * @property {ReadableStream<Uint8Array>|null} [body]
 * @property {globalThis.Headers} [headers]
 * @property {RequestRedirect} [redirect]
 *
 */
class Request extends Body {
	/**
	 * @param {string|Request|URL} info  Url or Request instance
	 * @param {RequestInit & RequestExtraOptions} init   Custom options
	 */
	constructor(info, init = {}) {
		let parsedURL;
		/** @type {RequestOptions & RequestExtraOptions} */
		let settings

		// Normalize input and force URL to be encoded as UTF-8 (https://github.com/node-fetch/node-fetch/issues/245)
		if (isRequest(info)) {
			parsedURL = new URL(info.url);
			settings = (info)
		} else {
			parsedURL = new URL(info);
			settings = {};
		}



		// Normalize method: https://fetch.spec.whatwg.org/#methods
		let method = init.method || settings.method || 'GET';
		if (forbiddenMethods.has(method.toUpperCase())) {
			throw new TypeError(`Failed to construct 'Request': '${method}' HTTP method is unsupported.`)
		} else if (normalizedMethods.has(method.toUpperCase())) {
			method = method.toUpperCase();
		}

		const inputBody = init.body != null
			? init.body
			: (isRequest(info) && info.body !== null)
			? clone(info)
			: null;

		// eslint-disable-next-line no-eq-null, eqeqeq
		if (inputBody != null && (method === 'GET' || method === 'HEAD')) {
			throw new TypeError('Request with GET/HEAD method cannot have body');
		}

		super(inputBody, {
			size: init.size || settings.size || 0
		});
		const input = settings


		const headers = /** @type {globalThis.Headers} */
			(new Headers(init.headers || input.headers || {}));

		if (inputBody !== null && !headers.has('Content-Type')) {
			const contentType = extractContentType(this);
			if (contentType) {
				headers.append('Content-Type', contentType);
			}
		}

		let signal = 'signal' in init
			? init.signal
			: isRequest(input)
			? input.signal
			: null;

		// eslint-disable-next-line no-eq-null, eqeqeq
		if (signal != null && !isAbortSignal(signal)) {
			throw new TypeError('Expected signal to be an instanceof AbortSignal or EventTarget');
		}
		
		if (!signal) {
			let AbortControllerConstructor = typeof AbortController != "undefined"
			? AbortController
			: abort_controller.AbortController;
			/** @type {any} */
			let newSignal = new AbortControllerConstructor().signal;
			signal = newSignal;
		}

		/** @type {RequestState} */
		this[request_INTERNALS] = {
			method,
			redirect: init.redirect || input.redirect || 'follow',
			headers,
			credentials: init.credentials || 'same-origin',
			parsedURL,
			signal: signal || null
		};

		/** @type {boolean} */
		this.keepalive

		// Node-fetch-only options
		/** @type {number} */
		this.follow = init.follow === undefined ? (input.follow === undefined ? 20 : input.follow) : init.follow;
		/** @type {boolean} */
		this.compress = init.compress === undefined ? (input.compress === undefined ? true : input.compress) : init.compress;
		/** @type {number} */
		this.counter = init.counter || input.counter || 0;
		/** @type {Agent|undefined} */
		this.agent = init.agent || input.agent;
		/** @type {number} */
		this.highWaterMark = init.highWaterMark || input.highWaterMark || 16384;
		/** @type {boolean} */
		this.insecureHTTPParser = init.insecureHTTPParser || input.insecureHTTPParser || false;
	}

	/**
	 * @type {RequestCache}
	 */
	get cache() {
		return "default"
	}

	/**
	 * @type {RequestCredentials}
	 */

	get credentials() {
		return this[request_INTERNALS].credentials
	}

	/**
	 * @type {RequestDestination}
	 */
	get destination() {
		return ""
	}

	get integrity() {
		return ""
	}

	/** @type {RequestMode} */
	get mode() {
		return "cors"
	}

	/** @type {string} */
	get referrer() {
		return  ""
	}

	/** @type {ReferrerPolicy} */
	get referrerPolicy() {
		return ""
	}
	get method() {
		return this[request_INTERNALS].method;
	}

	/**
	 * @type {string}
	 */
	get url() {
		return (0,external_url_.format)(this[request_INTERNALS].parsedURL);
	}

	/**
	 * @type {globalThis.Headers}
	 */
	get headers() {
		return this[request_INTERNALS].headers;
	}

	get redirect() {
		return this[request_INTERNALS].redirect;
	}

	/**
	 * @returns {AbortSignal}
	 */
	get signal() {
		// @ts-ignore
		return this[request_INTERNALS].signal;
	}

	/**
	 * Clone this request
	 *
	 * @return  {globalThis.Request}
	 */
	clone() {
		return new Request(this);
	}

	get [Symbol.toStringTag]() {
		return 'Request';
	}
}

Object.defineProperties(Request.prototype, {
	method: {enumerable: true},
	url: {enumerable: true},
	headers: {enumerable: true},
	redirect: {enumerable: true},
	clone: {enumerable: true},
	signal: {enumerable: true}
});

/**
 * Convert a Request to Node.js http request options.
 * The options object to be passed to http.request
 *
 * @param {Request & Record<INTERNALS, RequestState>} request -  A Request instance
 */
const getNodeRequestOptions = request => {
	const {parsedURL} = request[request_INTERNALS];
	const headers = new Headers(request[request_INTERNALS].headers);

	// Fetch step 1.3
	if (!headers.has('Accept')) {
		headers.set('Accept', '*/*');
	}

	// HTTP-network-or-cache fetch steps 2.4-2.7
	let contentLengthValue = null;
	if (request.body === null && /^(post|put)$/i.test(request.method)) {
		contentLengthValue = '0';
	}

	if (request.body !== null) {
		const totalBytes = getTotalBytes(request);
		// Set Content-Length if totalBytes is a number (that is not NaN)
		if (typeof totalBytes === 'number' && !Number.isNaN(totalBytes)) {
			contentLengthValue = String(totalBytes);
		}
	}

	if (contentLengthValue) {
		headers.set('Content-Length', contentLengthValue);
	}

	// HTTP-network-or-cache fetch step 2.11
	if (!headers.has('User-Agent')) {
		headers.set('User-Agent', 'node-fetch');
	}

	// HTTP-network-or-cache fetch step 2.15
	if (request.compress && !headers.has('Accept-Encoding')) {
		headers.set('Accept-Encoding', 'gzip,deflate,br');
	}

	let {agent} = request;
	if (typeof agent === 'function') {
		agent = agent(parsedURL);
	}

	if (!headers.has('Connection') && !agent) {
		headers.set('Connection', 'close');
	}

	// HTTP-network fetch step 4.2
	// chunked encoding is handled by Node.js

	const search = getSearch(parsedURL);

	// Manually spread the URL object instead of spread syntax
	const requestOptions = {
		path: parsedURL.pathname + search,
		pathname: parsedURL.pathname,
		hostname: parsedURL.hostname,
		protocol: parsedURL.protocol,
		port: parsedURL.port,
		hash: parsedURL.hash,
		search: parsedURL.search,
		// @ts-ignore - it does not has a query
		query: parsedURL.query,
		href: parsedURL.href,
		method: request.method,
		// @ts-ignore - not sure what this supposed to do
		headers: headers[Symbol.for('nodejs.util.inspect.custom')](),
		insecureHTTPParser: request.insecureHTTPParser,
		agent
	};

	return requestOptions;
};

;// CONCATENATED MODULE: ./node_modules/@web-std/fetch/src/errors/abort-error.js


/**
 * AbortError interface for cancelled requests
 */
class AbortError extends FetchBaseError {
	/**
	 * @param {string} message 
	 * @param {string} [type]
	 */
	constructor(message, type = 'aborted') {
		super(message, type);
	}
}

;// CONCATENATED MODULE: ./node_modules/@web-std/fetch/src/fetch.js
/**
 * Index.js
 *
 * a request API compatible with window.fetch
 *
 * All spec algorithm step numbers are based on https://fetch.spec.whatwg.org/commit-snapshots/ae716822cb3a61843226cd090eefc6589446c1d2/.
 */























const supportedSchemas = new Set(['data:', 'http:', 'https:', 'file:']);

/**
 * Fetch function
 *
 * @param   {string | URL | import('./request.js').default} url - Absolute url or Request instance
 * @param   {RequestInit & import('./request.js').RequestExtraOptions} [options_] - Fetch options
 * @return  {Promise<import('./response.js').default>}
 */
async function fetch(url, options_ = {}) {
	return new Promise((resolve, reject) => {
		// Build request object
		const request = new Request(url, options_);
		const options = getNodeRequestOptions(request);
		if (!supportedSchemas.has(options.protocol)) {
			throw new TypeError(`node-fetch cannot load ${url}. URL scheme "${options.protocol.replace(/:$/, '')}" is not supported.`);
		}

		if (options.protocol === 'data:') {
			const data = dist_src(request.url.toString());
			const response = new Response(data, {headers: {'Content-Type': data.typeFull}});
			resolve(response);
			return;
		}

		if (options.protocol === 'file:') {
			const stream = external_fs_.createReadStream(new URL(request.url))
			const type = lookup(request.url) || 'application/octet-stream'
			const response = new Response(stream, {headers: {'Content-Type': type }});
			resolve(response);
			return;
		}

		// Wrap http.request into fetch
		const send = (options.protocol === 'https:' ? external_https_ : external_http_).request;
		const {signal} = request;
		/** @type {Response|null} */
		let response = null;
		/** @type {import('http').IncomingMessage|null} */
		let response_ = null;

		const abort = () => {
			const error = new AbortError('The operation was aborted.');
			reject(error);
			if (request.body) {
				request.body.cancel(error);
			}

			if (!response_) {
				return;
			}

			response_.emit('error', error);
		};

		if (signal && signal.aborted) {
			abort();
			return;
		}

		const abortAndFinalize = () => {
			abort();
			finalize();
		};

		// Send request
		const request_ = send(options);

		if (signal) {
			signal.addEventListener('abort', abortAndFinalize);
		}

		const finalize = () => {
			request_.abort();
			if (signal) {
				signal.removeEventListener('abort', abortAndFinalize);
			}
		};

		request_.on('error', err => {
			// @ts-expect-error - err may not be SystemError
			reject(new FetchError(`request to ${request.url} failed, reason: ${err.message}`, 'system', err));
			finalize();
		});

		fixResponseChunkedTransferBadEnding(request_, err => {
			if (signal && signal.aborted) {
				return
			}

			response_?.emit("error", err);
		});

		/* c8 ignore next 18 */
		if (parseInt(process.version.substring(1)) < 14) {
			// Before Node.js 14, pipeline() does not fully support async iterators and does not always
			// properly handle when the socket close/end events are out of order.
			request_.on('socket', s => {
				s.prependListener('close', hadError => {
					// if a data listener is still present we didn't end cleanly
					const hasDataListener = s.listenerCount('data') > 0

					// if end happened before close but the socket didn't emit an error, do it now
					if (response && hasDataListener && !hadError && !(signal && signal.aborted)) {
						const err = Object.assign(new Error('Premature close'), {
							code: 'ERR_STREAM_PREMATURE_CLOSE'
						});
						response_?.emit('error', err);
					}
				});
			});
		}

		request_.on('response', incoming => {
			response_ = incoming;
			request_.setTimeout(0);
			const headers = fromRawHeaders(response_.rawHeaders);

			// HTTP fetch step 5
			if (isRedirect(Number(response_.statusCode))) {
				// HTTP fetch step 5.2
				const location = headers.get('Location');

				// HTTP fetch step 5.3
				const locationURL = location === null ? null : new URL(location, request.url);

				// HTTP fetch step 5.5
				switch (request.redirect) {
					case 'error':
						reject(new FetchError(`uri requested responds with a redirect, redirect mode is set to error: ${request.url}`, 'no-redirect'));
						finalize();
						return;
					case 'manual':
						// Node-fetch-specific step: make manual redirect a bit easier to use by setting the Location header value to the resolved URL.
						if (locationURL !== null) {
							headers.set('Location', locationURL.toString());
						}

						break;
					case 'follow': {
						// HTTP-redirect fetch step 2
						if (locationURL === null) {
							break;
						}

						// HTTP-redirect fetch step 5
						if (request.counter >= request.follow) {
							reject(new FetchError(`maximum redirect reached at: ${request.url}`, 'max-redirect'));
							finalize();
							return;
						}

						// HTTP-redirect fetch step 6 (counter increment)
						// Create a new Request object.
						const requestOptions = {
							headers: new Headers(request.headers),
							follow: request.follow,
							counter: request.counter + 1,
							agent: request.agent,
							compress: request.compress,
							method: request.method,
							// Note: We can not use `request.body` because send would have
							// consumed it already.
							body: options_.body,
							signal: signal,
							size: request.size
						};

						// HTTP-redirect fetch step 9
						const isStreamBody =
							requestOptions.body instanceof ReadableStream ||
							requestOptions.body instanceof external_stream_.Readable;
						if (response_.statusCode !== 303 && isStreamBody) {
							reject(new FetchError('Cannot follow redirect with body being a readable stream', 'unsupported-redirect'));
							finalize();
							return;
						}

						// HTTP-redirect fetch step 11
						if (response_.statusCode === 303 || ((response_.statusCode === 301 || response_.statusCode === 302) && request.method === 'POST')) {
							requestOptions.method = 'GET';
							requestOptions.body = undefined;
							requestOptions.headers.delete('content-length');
						}

						// HTTP-redirect fetch step 15
						fetch(new Request(locationURL.href, requestOptions)).then(resolve, reject);
						finalize();
						return;
					}

					default:
						return reject(new TypeError(`Redirect option '${request.redirect}' is not a valid value of RequestRedirect`));
				}
			}

			// Prepare response
			if (signal) {
				response_.once('end', () => {
					signal.removeEventListener('abort', abortAndFinalize);
				});
			}

			let body = (0,external_stream_.pipeline)(response_, new external_stream_.PassThrough(), reject);
			// see https://github.com/nodejs/node/pull/29376
			/* c8 ignore next 3 */
			if (process.version < 'v12.10') {
				response_.on('aborted', abortAndFinalize);
			}

			const responseOptions = {
				url: request.url,
				status: response_.statusCode,
				statusText: response_.statusMessage,
				headers,
				size: request.size,
				counter: request.counter,
				highWaterMark: request.highWaterMark
			};

			// HTTP-network fetch step 12.1.1.3
			const codings = headers.get('Content-Encoding');

			// HTTP-network fetch step 12.1.1.4: handle content codings

			// in following scenarios we ignore compression support
			// 1. compression support is disabled
			// 2. HEAD request
			// 3. no Content-Encoding header
			// 4. no content response (204)
			// 5. content not modified response (304)
			if (!request.compress || request.method === 'HEAD' || codings === null || response_.statusCode === 204 || response_.statusCode === 304) {
				response = new Response(body, responseOptions);
				resolve(response);
				return;
			}

			// For Node v6+
			// Be less strict when decoding compressed responses, since sometimes
			// servers send slightly invalid responses that are still accepted
			// by common browsers.
			// Always using Z_SYNC_FLUSH is what cURL does.
			const zlibOptions = {
				flush: external_zlib_.Z_SYNC_FLUSH,
				finishFlush: external_zlib_.Z_SYNC_FLUSH
			};

			// For gzip
			if (codings === 'gzip' || codings === 'x-gzip') {
				body = (0,external_stream_.pipeline)(body, external_zlib_.createGunzip(zlibOptions), reject);
				response = new Response(fromAsyncIterable(body), responseOptions);
				resolve(response);
				return;
			}

			// For deflate
			if (codings === 'deflate' || codings === 'x-deflate') {
				// Handle the infamous raw deflate response from old servers
				// a hack for old IIS and Apache servers
				const raw = (0,external_stream_.pipeline)(response_, new external_stream_.PassThrough(), reject);
				raw.once('data', chunk => {
					// See http://stackoverflow.com/questions/37519828
					if ((chunk[0] & 0x0F) === 0x08) {
						body = (0,external_stream_.pipeline)(body, external_zlib_.createInflate(), reject);
					} else {
						body = (0,external_stream_.pipeline)(body, external_zlib_.createInflateRaw(), reject);
					}

					response = new Response(fromAsyncIterable(body), responseOptions);
					resolve(response);
				});
				return;
			}

			// For br
			if (codings === 'br') {
				body = (0,external_stream_.pipeline)(body, external_zlib_.createBrotliDecompress(), reject);
				response = new Response(fromAsyncIterable(body), responseOptions);
				resolve(response);
				return;
			}

			// Otherwise, use response as-is
			response = new Response(fromAsyncIterable(body), responseOptions);
			resolve(response);
		});

		body_writeToStream(request_, request);
	});
}

/**
 *
 * @param {import('http').ClientRequest} request
 * @param {(error:Error) => void} errorCallback
 */
function fixResponseChunkedTransferBadEnding(request, errorCallback) {
	const LAST_CHUNK = external_buffer_.Buffer.from('0\r\n\r\n');

	let isChunkedTransfer = false;
	let properLastChunkReceived = false;
	/** @type {Buffer | undefined} */
	let previousChunk;

	request.on('response', response => {
		const {headers} = response;
		isChunkedTransfer = headers['transfer-encoding'] === 'chunked' && !headers['content-length'];
	});

	request.on('socket', socket => {
		const onSocketClose = () => {
			if (isChunkedTransfer && !properLastChunkReceived) {
				const error = Object.assign(new Error('Premature close'), {
					code: 'ERR_STREAM_PREMATURE_CLOSE'
				});
				errorCallback(error);
			}
		};

		/** @param {Buffer} buf */
		const onData = buf => {
			properLastChunkReceived = external_buffer_.Buffer.compare(buf.slice(-5), LAST_CHUNK) === 0;

			// Sometimes final 0-length chunk and end of message code are in separate packets
			if (!properLastChunkReceived && previousChunk) {
				properLastChunkReceived = (
					external_buffer_.Buffer.compare(previousChunk.slice(-3), LAST_CHUNK.slice(0, 3)) === 0 &&
					external_buffer_.Buffer.compare(buf.slice(-2), LAST_CHUNK.slice(3)) === 0
				);
			}

			previousChunk = buf;
		};

		socket.prependListener('close', onSocketClose);
		socket.on('data', onData);

		const removeSocketListeners = () => {
			socket.removeListener('close', onSocketClose);
			socket.removeListener('data', onData);
		}

		request.on('close', removeSocketListeners);
		request.on('abort', removeSocketListeners);
	});
}

/* harmony default export */ const src_fetch = ((/* unused pure expression or super */ null && (fetch)));


;// CONCATENATED MODULE: ./node_modules/@web-std/fetch/src/lib.node.js



// Electron-renderer should get the browser implementation instead of node
// Browser configuration is not enough

// Marking export as a DOM File object instead of custom class.
const lib_node_fetch = /** @type {typeof globalThis.fetch} */
  (typeof globalThis.fetch === "function" ? globalThis.fetch.bind(globalThis) : fetch)

const lib_node_Headers = globalThis.Headers || Headers
const lib_node_Request = globalThis.Request || Request
const lib_node_Response = globalThis.Response || Response

/* harmony default export */ const lib_node = (lib_node_fetch);

// EXTERNAL MODULE: external "os"
var external_os_ = __webpack_require__(22037);
;// CONCATENATED MODULE: ./node_modules/ipfs-car/dist/esm/blockstore/fs.js




class FsBlockStore extends base_BaseBlockstore {
    constructor() {
        super();
        this.path = `${external_os_.tmpdir()}/${(parseInt(String(Math.random() * 1e9), 10)).toString() + Date.now()}`;
        this._opened = false;
    }
    async _open() {
        if (this._opening) {
            await this._opening;
        }
        else {
            this._opening = external_fs_.promises.mkdir(this.path);
            await this._opening;
            this._opened = true;
        }
    }
    async put(cid, bytes) {
        if (!this._opened) {
            await this._open();
        }
        const cidStr = cid.toString();
        const location = `${this.path}/${cidStr}`;
        await external_fs_.promises.writeFile(location, bytes);
    }
    async get(cid) {
        if (!this._opened) {
            await this._open();
        }
        const cidStr = cid.toString();
        const location = `${this.path}/${cidStr}`;
        const bytes = await external_fs_.promises.readFile(location);
        return bytes;
    }
    async has(cid) {
        if (!this._opened) {
            await this._open();
        }
        const cidStr = cid.toString();
        const location = `${this.path}/${cidStr}`;
        try {
            await external_fs_.promises.access(location);
            return true;
        }
        catch (err) {
            return false;
        }
    }
    async *blocks() {
        if (!this._opened) {
            await this._open();
        }
        const cids = await external_fs_.promises.readdir(this.path);
        for (const cidStr of cids) {
            const location = `${this.path}/${cidStr}`;
            const bytes = await external_fs_.promises.readFile(location);
            yield { cid: cid_CID.parse(cidStr), bytes };
        }
    }
    async close() {
        if (this._opened) {
            await external_fs_.promises.rm(this.path, { recursive: true });
        }
        this._opened = false;
    }
}

;// CONCATENATED MODULE: ./node_modules/nft.storage/src/platform.js








;// CONCATENATED MODULE: ./node_modules/nft.storage/src/gateway.js
const GATEWAY = new URL('https://nftstorage.link/')

/**
 * @typedef {string|URL} GatewayURL Base URL of an IPFS Gateway e.g. https://dweb.link/ or https://ipfs.io/
 * @typedef {{ gateway?: GatewayURL }} GatewayURLOptions
 */

/**
 * Convert an IPFS URL (starting ipfs://) to a gateway URL (starting https://)
 * that can be used in a webpage. If the passed URL is not an IPFS URL it is
 * returned as a new URL object with no further changes.
 *
 * @param {string|URL} url An IPFS URL e.g. ipfs://bafy.../path
 * @param {GatewayURLOptions} [options] Options that allow customization of the gateway used.
 * @returns {URL} An IPFS gateway URL e.g. https://nftstorage.link/ipfs/bafy.../path
 */
const toGatewayURL = (url, options = {}) => {
  const gateway = options.gateway || GATEWAY
  url = new URL(String(url))
  return url.protocol === 'ipfs:'
    ? new URL(`/ipfs/${url.href.slice('ipfs://'.length)}`, gateway)
    : url
}

;// CONCATENATED MODULE: ./node_modules/nft.storage/src/bs-car-reader.js
/**
 * An implementation of the CAR reader interface that is backed by a blockstore.
 *
 * @typedef {import('multiformats').CID} CID
 * @typedef {import('@ipld/car/api').CarReader} CarReader
 * @implements {CarReader}
 */
class BlockstoreCarReader {
  /**
   * @param {number} version
   * @param {CID[]} roots
   * @param {import('ipfs-car/blockstore').Blockstore} blockstore
   */
  constructor(version, roots, blockstore) {
    /**
     * @private
     */
    this._version = version
    /**
     * @private
     */
    this._roots = roots
    /**
     * @private
     */
    this._blockstore = blockstore
  }

  get version() {
    return this._version
  }

  get blockstore() {
    return this._blockstore
  }

  async getRoots() {
    return this._roots
  }

  /**
   * @param {CID} cid
   */
  has(cid) {
    return this._blockstore.has(cid)
  }

  /**
   * @param {CID} cid
   */
  async get(cid) {
    const bytes = await this._blockstore.get(cid)
    return { cid, bytes }
  }

  blocks() {
    return this._blockstore.blocks()
  }

  async *cids() {
    for await (const b of this.blocks()) {
      yield b.cid
    }
  }
}

;// CONCATENATED MODULE: ./node_modules/nft.storage/src/token.js









/**
 * @typedef {import('./gateway.js').GatewayURLOptions} EmbedOptions
 * @typedef {import('./lib/interface.js').TokenInput} TokenInput
 * @typedef {import('ipfs-car/blockstore').Blockstore} Blockstore
 */

/**
 * @template T
 * @typedef {import('./lib/interface.js').Encoded<T, [[Blob, URL]]>} EncodedBlobUrl
 */

/**
 * @template G
 * @typedef {import('./lib/interface.js').Encoded<G, [[Blob, Blob]]>} EncodedBlobBlob
 */

/**
 * @template {import('./lib/interface.js').TokenInput} T
 * @typedef {import('./lib/interface.js').Token<T>} TokenType
 */

/**
 * @template {TokenInput} T
 * @implements {TokenType<T>}
 */
class token_Token {
  /**
   * @param {import('./lib/interface.js').CIDString} ipnft
   * @param {import('./lib/interface.js').EncodedURL} url
   * @param {import('./lib/interface.js').Encoded<T, [[Blob, URL]]>} data
   */
  constructor(ipnft, url, data) {
    /** @readonly */
    this.ipnft = ipnft
    /** @readonly */
    this.url = url
    /** @readonly */
    this.data = data

    Object.defineProperties(this, {
      ipnft: { enumerable: true, writable: false },
      url: { enumerable: true, writable: false },
      data: { enumerable: false, writable: false },
    })
  }
  /**
   * @returns {import('./lib/interface.js').Encoded<T, [[Blob, URL]]>}
   */
  embed() {
    return token_Token.embed(this)
  }

  /**
   * @template {TokenInput} T
   * @param {{data: import('./lib/interface.js').Encoded<T, [[Blob, URL]]>}} token
   * @returns {import('./lib/interface.js').Encoded<T, [[Blob, URL]]>}
   */
  static embed({ data }) {
    return token_embed(data, { gateway: GATEWAY })
  }

  /**
   * Takes token input, encodes it as a DAG, wraps it in a CAR and creates a new
   * Token instance from it. Where values are discovered `Blob` (or `File`)
   * objects in the given input, they are replaced with IPFS URLs (an `ipfs://`
   * prefixed CID with an optional path).
   *
   * @example
   * ```js
   * const cat = new File(['...'], 'cat.png')
   * const kitty = new File(['...'], 'kitty.png')
   * const { token, car } = await Token.encode({
   *   name: 'hello'
   *   image: cat
   *   properties: {
   *     extra: {
   *       image: kitty
   *     }
   *   }
   * })
   * ```
   *
   * @template {TokenInput} T
   * @param {T} input
   * @returns {Promise<{ cid: CID, token: TokenType<T>, car: import('./lib/interface.js').CarReader }>}
   */
  static async encode(input) {
    const blockstore = new FsBlockStore()
    const [blobs, meta] = mapTokenInputBlobs(input)
    /** @type {EncodedBlobUrl<T>} */
    const data = JSON.parse(JSON.stringify(meta))
    /** @type {import('./lib/interface.js').Encoded<T, [[Blob, CID]]>} */
    const dag = JSON.parse(JSON.stringify(meta))

    for (const [dotPath, blob] of blobs.entries()) {
      /** @type {string|undefined} */
      // @ts-ignore blob may be a File!
      const name = blob.name || 'blob'
      /** @type {import('./platform.js').ReadableStream} */
      let content
      // FIXME: should not be necessary to await arrayBuffer()!
      // Node.js 20 hangs reading the stream (it never ends) but in
      // older node versions and the browser it is fine to use blob.stream().
      /* c8 ignore next 5 */
      if (parseInt(globalThis.process?.versions?.node) > 18) {
        content = new Uint8Array(await blob.arrayBuffer())
      } else {
        content = blob.stream()
      }
      const { root: cid } = await pack({
        input: [{ path: name, content }],
        blockstore,
        wrapWithDirectory: true,
      })

      const href = new URL(`ipfs://${cid}/${name}`)
      const path = dotPath.split('.')
      setIn(data, path, href)
      setIn(dag, path, cid)
    }

    const { root: metadataJsonCid } = await pack({
      input: [{ path: 'metadata.json', content: JSON.stringify(data) }],
      blockstore,
      wrapWithDirectory: false,
    })

    const block = await block_encode({
      value: {
        ...dag,
        'metadata.json': metadataJsonCid,
        type: 'nft',
      },
      codec: dag_cbor_esm_namespaceObject,
      hasher: sha256,
    })
    await blockstore.put(block.cid, block.bytes)

    return {
      cid: block.cid,
      token: new token_Token(
        block.cid.toString(),
        `ipfs://${block.cid}/metadata.json`,
        data
      ),
      car: new BlockstoreCarReader(1, [block.cid], blockstore),
    }
  }
}

/**
 * @template T
 * @param {EncodedBlobUrl<T>} input
 * @param {EmbedOptions} options
 * @returns {EncodedBlobUrl<T>}
 */
const token_embed = (input, options) =>
  mapWith(input, isURL, embedURL, options)

/**
 * @template {TokenInput} T
 * @param {import('./lib/interface.js').EncodedToken<T>} value
 * @param {Set<string>} paths - Paths were to expect EncodedURLs
 * @returns {Token<T>}
 */
const token_decode = ({ ipnft, url, data }, paths) =>
  new token_Token(ipnft, url, mapWith(data, isEncodedURL, decodeURL, paths))

/**
 * @param {any} value
 * @returns {value is URL}
 */
const isURL = (value) => value instanceof URL

/**
 * @template State
 * @param {State} state
 * @param {import('./lib/interface.js').EncodedURL} url
 * @returns {[State, URL]}
 */
const decodeURL = (state, url) => [state, new URL(url)]

/**
 * @param {EmbedOptions} context
 * @param {URL} url
 * @returns {[EmbedOptions, URL]}
 */
const embedURL = (context, url) => [context, toGatewayURL(url, context)]

/**
 * @param {any} value
 * @returns {value is object}
 */
const isObject = (value) => typeof value === 'object' && value != null

/**
 * @param {any} value
 * @param {Set<string>} assetPaths
 * @param {PropertyKey[]} path
 * @returns {value is import('./lib/interface.js').EncodedURL}
 */
const isEncodedURL = (value, assetPaths, path) =>
  typeof value === 'string' && assetPaths.has(path.join('.'))

/**
 * Takes token input and encodes it into
 * [FormData](https://developer.mozilla.org/en-US/docs/Web/API/FormData)
 * object where form field values are discovered `Blob` (or `File`) objects in
 * the given token and field keys are `.` joined paths where they were discoverd
 * in the token. Additionally encoded `FormData` will also have a field
 * named `meta` containing JSON serialized token with blobs and file values
 * `null` set to null (this allows backend to injest all of the files from
 * `multipart/form-data` request and update provided "meta" data with
 * corresponding file ipfs:// URLs)
 *
 * @example
 * ```js
 * const cat = new File([], 'cat.png')
 * const kitty = new File([], 'kitty.png')
 * const form = encode({
 *   name: 'hello'
 *   image: cat
 *   properties: {
 *     extra: {
 *       image: kitty
 *     }
 *   }
 * })
 * [...form.entries()] //>
 * // [
 * //   ['image', cat],
 * //   ['properties.extra.image', kitty],
 * //   ['meta', '{"name":"hello",image:null,"properties":{"extra":{"kitty": null}}}']
 * // ]
 * ```
 *
 * @template {TokenInput} T
 * @param {EncodedBlobBlob<T>} input
 * @returns {FormData}
 */
const token_encode = (input) => {
  const [map, meta] = mapValueWith(input, token_isBlob, encodeBlob, new Map(), [])
  const form = new FormData()
  for (const [k, v] of map.entries()) {
    form.set(k, v)
  }
  form.set('meta', JSON.stringify(meta))
  return form
}

/**
 * @param {Map<string, Blob>} data
 * @param {Blob} blob
 * @param {PropertyKey[]} path
 * @returns {[Map<string, Blob>, void]}
 */
const encodeBlob = (data, blob, path) => {
  data.set(path.join('.'), blob)
  return [data, undefined]
}

/**
 * @param {any} value
 * @returns {value is Blob}
 */
const token_isBlob = (value) => value instanceof lib_node_Blob

/**
 * @template {TokenInput} T
 * @param {EncodedBlobBlob<T>} input
 */
const mapTokenInputBlobs = (input) => {
  return mapValueWith(input, token_isBlob, encodeBlob, new Map(), [])
}

/**
 * Substitues values in the given `input` that match `p(value) == true` with
 * `f(value, context, path)` where `context` is whatever you pass (usually
 * a mutable state) and `path` is a array of keys / indexes where the value
 * was encountered.
 *
 * @template T, I, X, O, State
 * @param {import('./lib/interface.js').Encoded<T, [[I, X]]>} input - Arbitrary input.
 * @param {(input:any, state:State, path:PropertyKey[]) => input is X} p - Predicate function to determine
 * which values to swap.
 * @param {(state:State, input:X, path:PropertyKey[]) => [State, O]} f - Function
 * that swaps matching values.
 * @param {State} state - Some additional context you need in the process.
 * likey you'll start with `[]`.
 * @returns {import('./lib/interface.js').Encoded<T, [[I, O]]>}
 */
const mapWith = (input, p, f, state) => {
  const [, output] = mapValueWith(input, p, f, state, [])
  return output
}

/**
 * @template T, I, X, O, State
 * @param {import('./lib/interface.js').Encoded<T, [[I, X]]>} input - Arbitrary input.
 * @param {(input:any, state:State, path:PropertyKey[]) => input is X} p - Predicate function to determine
 * which values to swap.
 * @param {(state:State, input:X, path:PropertyKey[]) => [State, O]} f - Function
 * that swaps matching values.
 * @param {State} state - Some additional context you need in the process.
 * @param {PropertyKey[]} path - Path where the value was encountered. Most
 * likey you'll start with `[]`.
 * @returns {[State, import('./lib/interface.js').Encoded<T, [[I, O]]>]}
 */
const mapValueWith = (input, p, f, state, path) =>
  p(input, state, path)
    ? f(state, input, path)
    : Array.isArray(input)
    ? mapArrayWith(input, p, f, state, path)
    : isObject(input)
    ? mapObjectWith(input, p, f, state, path)
    : [state, /** @type {any} */ (input)]

/**
 * Just like `mapWith` except
 *
 * @template State, T, I, X, O
 * @param {import('./lib/interface.js').Encoded<T, [[I, X]]>} input
 * @param {(input:any, state:State, path:PropertyKey[]) => input is X} p
 * @param {(state: State, input:X, path:PropertyKey[]) => [State, O]} f
 * @param {State} init
 * @param {PropertyKey[]} path
 * @returns {[State, import('./lib/interface.js').Encoded<T, [[I, O]]>]}
 */
const mapObjectWith = (input, p, f, init, path) => {
  let state = init
  const output =
    /** @type {import('./lib/interface.js').Encoded<T, [[I, O]]>} */ ({})
  for (const [key, value] of Object.entries(input)) {
    const [next, out] = mapValueWith(value, p, f, state, [...path, key])
    // @ts-ignore
    output[key] = out
    state = next
  }
  return [state, output]
}

/**
 * Just like `mapWith` except for Arrays.
 *
 * @template I, X, O, State
 * @template {any[]} T
 * @param {T} input
 * @param {(input:any, state:State, path:PropertyKey[]) => input is X} p
 * @param {(state: State, input:X, path:PropertyKey[]) => [State, O]} f
 * @param {State} init
 * @param {PropertyKey[]} path
 * @returns {[State, import('./lib/interface.js').Encoded<T, [[I, O]]>]}
 */
const mapArrayWith = (input, p, f, init, path) => {
  const output = /** @type {unknown[]} */ ([])

  let state = init
  for (const [index, element] of input.entries()) {
    const [next, out] = mapValueWith(element, p, f, state, [...path, index])
    output[index] = out
    state = next
  }

  return [
    state,
    /** @type {import('./lib/interface.js').Encoded<T, [[I, O]]>} */ (output),
  ]
}

/**
 * Sets a given `value` at the given `path` on a passed `object`.
 *
 * @example
 * ```js
 * const obj = { a: { b: { c: 1 }}}
 * setIn(obj, ['a', 'b', 'c'], 5)
 * obj.a.b.c //> 5
 * ```
 *
 * @template V
 * @param {any} object
 * @param {string[]} path
 * @param {V} value
 */
const setIn = (object, path, value) => {
  const n = path.length - 1
  let target = object
  for (let [index, key] of path.entries()) {
    if (index === n) {
      target[key] = value
    } else {
      target = target[key]
    }
  }
}

;// CONCATENATED MODULE: ./node_modules/nft.storage/src/lib.js
/**
 * A client library for the https://nft.storage/ service. It provides a convenient
 * interface for working with the [Raw HTTP API](https://nft.storage/#api-docs)
 * from a web browser or [Node.js](https://nodejs.org/) and comes bundled with
 * TS for out-of-the box type inference and better IntelliSense.
 *
 * @example
 * ```js
 * import { NFTStorage, File, Blob } from "nft.storage"
 * const client = new NFTStorage({ token: API_TOKEN })
 *
 * const cid = await client.storeBlob(new Blob(['hello world']))
 * ```
 * @module
 */













const MAX_STORE_RETRIES = 5
const MAX_CONCURRENT_UPLOADS = 3
const MAX_CHUNK_SIZE = 1024 * 1024 * 50 // chunk to ~50MB CARs
const RATE_LIMIT_REQUESTS = 30
const RATE_LIMIT_PERIOD = 10 * 1000

/**
 * @typedef {import('./lib/interface.js').Service} Service
 * @typedef {import('./lib/interface.js').CIDString} CIDString
 * @typedef {import('./lib/interface.js').Deal} Deal
 * @typedef {import('./lib/interface.js').FileObject} FileObject
 * @typedef {import('./lib/interface.js').FilesSource} FilesSource
 * @typedef {import('./lib/interface.js').Pin} Pin
 * @typedef {import('./lib/interface.js').CarReader} CarReader
 * @typedef {import('ipfs-car/blockstore').Blockstore} BlockstoreI
 * @typedef {import('./lib/interface.js').RateLimiter} RateLimiter
 * @typedef {import('./lib/interface.js').RequestOptions} RequestOptions
 */

/**
 * @returns {RateLimiter}
 */
function createRateLimiter() {
  const throttle = throttledQueue(RATE_LIMIT_REQUESTS, RATE_LIMIT_PERIOD)
  return () => throttle(() => {})
}

/**
 * Rate limiter used by static API if no rate limiter is passed. Note that each
 * instance of the NFTStorage class gets it's own limiter if none is passed.
 * This is because rate limits are enforced per API token.
 */
const globalRateLimiter = createRateLimiter()

/**
 * @template {import('./lib/interface.js').TokenInput} T
 * @typedef {import('./lib/interface.js').Token<T>} TokenType
 */

/**
 * @implements {Service}
 */
class NFTStorage {
  /**
   * Constructs a client bound to the given `options.token` and
   * `options.endpoint`.
   *
   * @example
   * ```js
   * import { NFTStorage, File, Blob } from "nft.storage"
   * const client = new NFTStorage({ token: API_TOKEN })
   *
   * const cid = await client.storeBlob(new Blob(['hello world']))
   * ```
   * Optionally you could pass an alternative API endpoint (e.g. for testing)
   * @example
   * ```js
   * import { NFTStorage } from "nft.storage"
   * const client = new NFTStorage({
   *   token: API_TOKEN
   *   endpoint: new URL('http://localhost:8080/')
   * })
   * ```
   *
   * @param {{token: string, endpoint?: URL, rateLimiter?: RateLimiter, did?: string}} options
   */
  constructor({
    token,
    did,
    endpoint = new URL('https://api.nft.storage'),
    rateLimiter,
  }) {
    /**
     * Authorization token.
     *
     * @readonly
     */
    this.token = token
    /**
     * Service API endpoint `URL`.
     * @readonly
     */
    this.endpoint = endpoint
    /**
     * @readonly
     */
    this.rateLimiter = rateLimiter || createRateLimiter()

    /**
     * @readonly
     */
    this.did = did
  }

  /**
   * @hidden
   * @param {object} options
   * @param {string} options.token
   * @param {string} [options.did]
   */
  static auth({ token, did }) {
    if (!token) throw new Error('missing token')
    return {
      Authorization: `Bearer ${token}`,
      'X-Client': 'nft.storage/js',
      ...(did ? { 'x-agent-did': did } : {}),
    }
  }

  /**
   * Stores a single file and returns its CID.
   *
   * @param {Service} service
   * @param {Blob} blob
   * @param {RequestOptions} [options]
   * @returns {Promise<CIDString>}
   */
  static async storeBlob(service, blob, options) {
    const blockstore = new FsBlockStore()
    let cidString

    try {
      const { cid, car } = await NFTStorage.encodeBlob(blob, { blockstore })
      await NFTStorage.storeCar(service, car, options)
      cidString = cid.toString()
    } finally {
      await blockstore.close()
    }

    return cidString
  }

  /**
   * Stores a CAR file and returns its root CID.
   *
   * @param {Service} service
   * @param {Blob|CarReader} car
   * @param {import('./lib/interface.js').CarStorerOptions} [options]
   * @returns {Promise<CIDString>}
   */
  static async storeCar(
    { endpoint, rateLimiter = globalRateLimiter, ...token },
    car,
    { onStoredChunk, maxRetries, maxChunkSize, decoders, signal } = {}
  ) {
    const url = new URL('upload/', endpoint)
    const headers = {
      ...NFTStorage.auth(token),
      'Content-Type': 'application/car',
    }
    const targetSize = maxChunkSize || MAX_CHUNK_SIZE
    const splitter =
      car instanceof lib_node_Blob
        ? await TreewalkCarSplitter.fromBlob(car, targetSize, { decoders })
        : new TreewalkCarSplitter(car, targetSize, { decoders })

    const upload = transform(
      MAX_CONCURRENT_UPLOADS,
      async function (/** @type {AsyncIterable<Uint8Array>} */ car) {
        const carParts = []
        for await (const part of car) {
          carParts.push(part)
        }
        const carFile = new lib_node_Blob(carParts, { type: 'application/car' })
        /** @type {Blob|ArrayBuffer} */
        let body = carFile
        // FIXME: should not be necessary to await arrayBuffer()!
        // Node.js 20 hangs reading the stream (it never ends) but in
        // older node versions and the browser it is fine to pass a blob.
        /* c8 ignore next 3 */
        if (parseInt(globalThis.process?.versions?.node) > 18) {
          body = await body.arrayBuffer()
        }
        const cid = await p_retry(
          async () => {
            await rateLimiter()
            /** @type {Response} */
            let response
            try {
              response = await lib_node(url.toString(), {
                method: 'POST',
                headers,
                body,
                signal,
              })
            } catch (/** @type {any} */ err) {
              // TODO: remove me and test when client accepts custom fetch impl
              /* c8 ignore next 1 */
              throw signal && signal.aborted ? new p_retry.AbortError(err) : err
            }
            /* c8 ignore next 3 */
            if (response.status === 429) {
              throw new Error('rate limited')
            }
            const result = await response.json()
            if (!result.ok) {
              // do not retry if unauthorized - will not succeed
              if (response.status === 401) {
                throw new p_retry.AbortError(result.error.message)
              }
              throw new Error(result.error.message)
            }
            return result.value.cid
          },
          {
            retries: maxRetries == null ? MAX_STORE_RETRIES : maxRetries,
          }
        )
        onStoredChunk && onStoredChunk(carFile.size)
        return cid
      }
    )

    let root
    for await (const cid of upload(splitter.cars())) {
      root = cid
    }

    return /** @type {CIDString} */ (root)
  }

  /**
   * Stores a directory of files and returns a CID. Provided files **MUST**
   * be within the same directory, otherwise error is raised e.g. `foo/bar.png`,
   * `foo/bla/baz.json` is ok but `foo/bar.png`, `bla/baz.json` is not.
   *
   * @param {Service} service
   * @param {FilesSource} filesSource
   * @param {RequestOptions} [options]
   * @returns {Promise<CIDString>}
   */
  static async storeDirectory(service, filesSource, options) {
    const blockstore = new FsBlockStore()
    let cidString
    try {
      const { cid, car } = await NFTStorage.encodeDirectory(filesSource, {
        blockstore,
      })
      await NFTStorage.storeCar(service, car, options)
      cidString = cid.toString()
    } finally {
      await blockstore.close()
    }

    return cidString
  }

  /**
   * Stores the given token and all resources it references (in the form of a
   * File or a Blob) along with a metadata JSON as specificed in ERC-1155. The
   * `token.image` must be either a `File` or a `Blob` instance, which will be
   * stored and the corresponding content address URL will be saved in the
   * metadata JSON file under `image` field.
   *
   * If `token.properties` contains properties with `File` or `Blob` values,
   * those also get stored and their URLs will be saved in the metadata JSON
   * file in their place.
   *
   * Note: URLs for `File` objects will retain file names e.g. in case of
   * `new File([bytes], 'cat.png', { type: 'image/png' })` will be transformed
   * into a URL that looks like `ipfs://bafy...hash/image/cat.png`. For `Blob`
   * objects, the URL will not have a file name name or mime type, instead it
   * will be transformed into a URL that looks like
   * `ipfs://bafy...hash/image/blob`.
   *
   * @template {import('./lib/interface.js').TokenInput} T
   * @param {Service} service
   * @param {T} metadata
   * @param {RequestOptions} [options]
   * @returns {Promise<TokenType<T>>}
   */
  static async store(service, metadata, options) {
    const { token, car } = await NFTStorage.encodeNFT(metadata)
    await NFTStorage.storeCar(service, car, options)
    return token
  }

  /**
   * Returns current status of the stored NFT by its CID. Note the NFT must
   * have previously been stored by this account.
   *
   * @param {Service} service
   * @param {string} cid
   * @param {RequestOptions} [options]
   * @returns {Promise<import('./lib/interface.js').StatusResult>}
   */
  static async status(
    { endpoint, rateLimiter = globalRateLimiter, ...token },
    cid,
    options
  ) {
    const url = new URL(`${cid}/`, endpoint)
    await rateLimiter()
    const response = await lib_node(url.toString(), {
      method: 'GET',
      headers: NFTStorage.auth(token),
      signal: options && options.signal,
    })
    /* c8 ignore next 3 */
    if (response.status === 429) {
      throw new Error('rate limited')
    }
    const result = await response.json()

    if (result.ok) {
      return {
        cid: result.value.cid,
        deals: decodeDeals(result.value.deals),
        size: result.value.size,
        pin: decodePin(result.value.pin),
        created: new Date(result.value.created),
      }
    } else {
      throw new Error(result.error.message)
    }
  }

  /**
   * Check if a CID of an NFT is being stored by NFT.Storage.
   *
   * @param {import('./lib/interface.js').PublicService} service
   * @param {string} cid
   * @param {RequestOptions} [options]
   * @returns {Promise<import('./lib/interface.js').CheckResult>}
   */
  static async check(
    { endpoint, rateLimiter = globalRateLimiter },
    cid,
    options
  ) {
    const url = new URL(`check/${cid}/`, endpoint)
    await rateLimiter()
    const response = await lib_node(url.toString(), {
      signal: options && options.signal,
    })
    /* c8 ignore next 3 */
    if (response.status === 429) {
      throw new Error('rate limited')
    }
    const result = await response.json()

    if (result.ok) {
      return {
        cid: result.value.cid,
        deals: decodeDeals(result.value.deals),
        pin: result.value.pin,
      }
    } else {
      throw new Error(result.error.message)
    }
  }

  /**
   * Removes stored content by its CID from this account. Please note that
   * even if content is removed from the service other nodes that have
   * replicated it might still continue providing it.
   *
   * @param {Service} service
   * @param {string} cid
   * @param {RequestOptions} [options]
   * @returns {Promise<void>}
   */
  static async delete(
    { endpoint, rateLimiter = globalRateLimiter, ...token },
    cid,
    options
  ) {
    const url = new URL(`${cid}/`, endpoint)
    await rateLimiter()
    const response = await lib_node(url.toString(), {
      method: 'DELETE',
      headers: NFTStorage.auth(token),
      signal: options && options.signal,
    })
    /* c8 ignore next 3 */
    if (response.status === 429) {
      throw new Error('rate limited')
    }
    const result = await response.json()
    if (!result.ok) {
      throw new Error(result.error.message)
    }
  }

  /**
   * Encodes the given token and all resources it references (in the form of a
   * File or a Blob) along with a metadata JSON as specificed in ERC-1155 to a
   * CAR file. The `token.image` must be either a `File` or a `Blob` instance,
   * which will be stored and the corresponding content address URL will be
   * saved in the metadata JSON file under `image` field.
   *
   * If `token.properties` contains properties with `File` or `Blob` values,
   * those also get stored and their URLs will be saved in the metadata JSON
   * file in their place.
   *
   * Note: URLs for `File` objects will retain file names e.g. in case of
   * `new File([bytes], 'cat.png', { type: 'image/png' })` will be transformed
   * into a URL that looks like `ipfs://bafy...hash/image/cat.png`. For `Blob`
   * objects, the URL will not have a file name name or mime type, instead it
   * will be transformed into a URL that looks like
   * `ipfs://bafy...hash/image/blob`.
   *
   * @example
   * ```js
   * const { token, car } = await NFTStorage.encodeNFT({
   *   name: 'nft.storage store test',
   *   description: 'Test ERC-1155 compatible metadata.',
   *   image: new File(['<DATA>'], 'pinpie.jpg', { type: 'image/jpg' }),
   *   properties: {
   *     custom: 'Custom data can appear here, files are auto uploaded.',
   *     file: new File(['<DATA>'], 'README.md', { type: 'text/plain' }),
   *   }
   * })
   *
   * console.log('IPFS URL for the metadata:', token.url)
   * console.log('metadata.json contents:\n', token.data)
   * console.log('metadata.json with IPFS gateway URLs:\n', token.embed())
   *
   * // Now store the CAR file on NFT.Storage
   * await client.storeCar(car)
   * ```
   *
   * @template {import('./lib/interface.js').TokenInput} T
   * @param {T} input
   * @returns {Promise<{ cid: CID, token: TokenType<T>, car: CarReader }>}
   */
  static async encodeNFT(input) {
    validateERC1155(input)
    return token_Token.encode(input)
  }

  /**
   * Encodes a single file to a CAR file and also returns its root CID.
   *
   * @example
   * ```js
   * const content = new Blob(['hello world'])
   * const { cid, car } = await NFTStorage.encodeBlob(content)
   *
   * // Root CID of the file
   * console.log(cid.toString())
   *
   * // Now store the CAR file on NFT.Storage
   * await client.storeCar(car)
   * ```
   *
   * @param {Blob} blob
   * @param {object} [options]
   * @param {BlockstoreI} [options.blockstore]
   * @returns {Promise<{ cid: CID, car: CarReader }>}
   */
  static async encodeBlob(blob, { blockstore } = {}) {
    if (blob.size === 0) {
      throw new Error('Content size is 0, make sure to provide some content')
    }
    return packCar([toImportCandidate('blob', blob)], {
      blockstore,
      wrapWithDirectory: false,
    })
  }

  /**
   * Encodes a directory of files to a CAR file and also returns the root CID.
   * Provided files **MUST** be within the same directory, otherwise error is
   * raised e.g. `foo/bar.png`, `foo/bla/baz.json` is ok but `foo/bar.png`,
   * `bla/baz.json` is not.
   *
   * @example
   * ```js
   * const { cid, car } = await NFTStorage.encodeDirectory([
   *   new File(['hello world'], 'hello.txt'),
   *   new File([JSON.stringify({'from': 'incognito'}, null, 2)], 'metadata.json')
   * ])
   *
   * // Root CID of the directory
   * console.log(cid.toString())
   *
   * // Now store the CAR file on NFT.Storage
   * await client.storeCar(car)
   * ```
   *
   * @param {FilesSource} files
   * @param {object} [options]
   * @param {BlockstoreI} [options.blockstore]
   * @returns {Promise<{ cid: CID, car: CarReader }>}
   */
  static async encodeDirectory(files, { blockstore } = {}) {
    let size = 0
    const input = it_pipe(files, async function* (files) {
      for await (const file of files) {
        yield toImportCandidate(file.name, file)
        size += file.size
      }
    })
    const packed = await packCar(input, {
      blockstore,
      wrapWithDirectory: true,
    })
    if (size === 0) {
      throw new Error(
        'Total size of files should exceed 0, make sure to provide some content'
      )
    }
    return packed
  }

  // Just a sugar so you don't have to pass around endpoint and token around.

  /**
   * Stores a single file and returns the corresponding Content Identifier (CID).
   * Takes a [Blob](https://developer.mozilla.org/en-US/docs/Web/API/Blob/Blob)
   * or a [File](https://developer.mozilla.org/en-US/docs/Web/API/File). Note
   * that no file name or file metadata is retained.
   *
   * @example
   * ```js
   * const content = new Blob(['hello world'])
   * const cid = await client.storeBlob(content)
   * cid //> 'zdj7Wn9FQAURCP6MbwcWuzi7u65kAsXCdjNTkhbJcoaXBusq9'
   * ```
   *
   * @param {Blob} blob
   * @param {RequestOptions} [options]
   */
  storeBlob(blob, options) {
    return NFTStorage.storeBlob(this, blob, options)
  }

  /**
   * Stores files encoded as a single [Content Addressed Archive
   * (CAR)](https://github.com/ipld/specs/blob/master/block-layer/content-addressable-archives.md).
   *
   * Takes a [Blob](https://developer.mozilla.org/en-US/docs/Web/API/Blob/Blob)
   * or a [File](https://developer.mozilla.org/en-US/docs/Web/API/File).
   *
   * Returns the corresponding Content Identifier (CID).
   *
   * See the [`ipfs-car` docs](https://www.npmjs.com/package/ipfs-car) for more
   * details on packing a CAR file.
   *
   * @example
   * ```js
   * import { pack } from 'ipfs-car/pack'
   * import { CarReader } from '@ipld/car'
   * const { out, root } = await pack({
   *  input: fs.createReadStream('pinpie.pdf')
   * })
   * const expectedCid = root.toString()
   * const carReader = await CarReader.fromIterable(out)
   * const cid = await storage.storeCar(carReader)
   * console.assert(cid === expectedCid)
   * ```
   *
   * @example
   * ```
   * import { packToBlob } from 'ipfs-car/pack/blob'
   * const data = 'Hello world'
   * const { root, car } = await packToBlob({ input: [new TextEncoder().encode(data)] })
   * const expectedCid = root.toString()
   * const cid = await client.storeCar(car)
   * console.assert(cid === expectedCid)
   * ```
   * @param {Blob|CarReader} car
   * @param {import('./lib/interface.js').CarStorerOptions} [options]
   */
  storeCar(car, options) {
    return NFTStorage.storeCar(this, car, options)
  }

  /**
   * Stores a directory of files and returns a CID for the directory.
   *
   * @example
   * ```js
   * const cid = await client.storeDirectory([
   *   new File(['hello world'], 'hello.txt'),
   *   new File([JSON.stringify({'from': 'incognito'}, null, 2)], 'metadata.json')
   * ])
   * cid //>
   * ```
   *
   * Argument can be a [FileList](https://developer.mozilla.org/en-US/docs/Web/API/FileList)
   * instance as well, in which case directory structure will be retained.
   *
   * @param {FilesSource} files
   * @param {RequestOptions} [options]
   */
  storeDirectory(files, options) {
    return NFTStorage.storeDirectory(this, files, options)
  }

  /**
   * Returns current status of the stored NFT by its CID. Note the NFT must
   * have previously been stored by this account.
   *
   * @example
   * ```js
   * const status = await client.status('zdj7Wn9FQAURCP6MbwcWuzi7u65kAsXCdjNTkhbJcoaXBusq9')
   * ```
   *
   * @param {string} cid
   * @param {RequestOptions} [options]
   */
  status(cid, options) {
    return NFTStorage.status(this, cid, options)
  }

  /**
   * Removes stored content by its CID from the service.
   *
   * > Please note that even if content is removed from the service other nodes
   * that have replicated it might still continue providing it.
   *
   * @example
   * ```js
   * await client.delete('zdj7Wn9FQAURCP6MbwcWuzi7u65kAsXCdjNTkhbJcoaXBusq9')
   * ```
   *
   * @param {string} cid
   * @param {RequestOptions} [options]
   */
  delete(cid, options) {
    return NFTStorage.delete(this, cid, options)
  }

  /**
   * Check if a CID of an NFT is being stored by nft.storage. Throws if the NFT
   * was not found.
   *
   * @example
   * ```js
   * const status = await client.check('zdj7Wn9FQAURCP6MbwcWuzi7u65kAsXCdjNTkhbJcoaXBusq9')
   * ```
   *
   * @param {string} cid
   * @param {RequestOptions} [options]
   */
  check(cid, options) {
    return NFTStorage.check(this, cid, options)
  }

  /**
   * Stores the given token and all resources it references (in the form of a
   * File or a Blob) along with a metadata JSON as specificed in
   * [ERC-1155](https://eips.ethereum.org/EIPS/eip-1155#metadata). The
   * `token.image` must be either a `File` or a `Blob` instance, which will be
   * stored and the corresponding content address URL will be saved in the
   * metadata JSON file under `image` field.
   *
   * If `token.properties` contains properties with `File` or `Blob` values,
   * those also get stored and their URLs will be saved in the metadata JSON
   * file in their place.
   *
   * Note: URLs for `File` objects will retain file names e.g. in case of
   * `new File([bytes], 'cat.png', { type: 'image/png' })` will be transformed
   * into a URL that looks like `ipfs://bafy...hash/image/cat.png`. For `Blob`
   * objects, the URL will not have a file name name or mime type, instead it
   * will be transformed into a URL that looks like
   * `ipfs://bafy...hash/image/blob`.
   *
   * @example
   * ```js
   * const metadata = await client.store({
   *   name: 'nft.storage store test',
   *   description: 'Test ERC-1155 compatible metadata.',
   *   image: new File(['<DATA>'], 'pinpie.jpg', { type: 'image/jpg' }),
   *   properties: {
   *     custom: 'Custom data can appear here, files are auto uploaded.',
   *     file: new File(['<DATA>'], 'README.md', { type: 'text/plain' }),
   *   }
   * })
   *
   * console.log('IPFS URL for the metadata:', metadata.url)
   * console.log('metadata.json contents:\n', metadata.data)
   * console.log('metadata.json with IPFS gateway URLs:\n', metadata.embed())
   * ```
   *
   * @template {import('./lib/interface.js').TokenInput} T
   * @param {T} token
   * @param {RequestOptions} [options]
   */
  store(token, options) {
    return NFTStorage.store(this, token, options)
  }
}

/**
 * Cast an iterable to an asyncIterable
 * @template T
 * @param {Iterable<T>} iterable
 * @returns {AsyncIterable<T>}
 */
function lib_toAsyncIterable(iterable) {
  return (async function* () {
    for (const item of iterable) {
      yield item
    }
  })()
}

/**
 * @template {import('./lib/interface.js').TokenInput} T
 * @param {T} metadata
 */
const validateERC1155 = ({ name, description, image, decimals }) => {
  // Just validate that expected fields are present
  if (typeof name !== 'string') {
    throw new TypeError(
      'string property `name` identifying the asset is required'
    )
  }
  if (typeof description !== 'string') {
    throw new TypeError(
      'string property `description` describing asset is required'
    )
  }
  if (!(image instanceof lib_node_Blob)) {
    throw new TypeError('property `image` must be a Blob or File object')
  } else if (!image.type.startsWith('image/')) {
    console.warn(`According to ERC721 Metadata JSON Schema 'image' must have 'image/*' mime type.

For better interoperability we would highly recommend storing content with different mime type under 'properties' namespace e.g. \`properties: { video: file }\` and using 'image' field for storing a preview image for it instead.

For more context please see ERC-721 specification https://eips.ethereum.org/EIPS/eip-721`)
  }

  if (typeof decimals !== 'undefined' && typeof decimals !== 'number') {
    throw new TypeError('property `decimals` must be an integer value')
  }
}

/**
 * @param {import('ipfs-car/pack').ImportCandidateStream|Array<{ path: string, content: import('./platform.js').ReadableStream }>} input
 * @param {object} [options]
 * @param {BlockstoreI} [options.blockstore]
 * @param {boolean} [options.wrapWithDirectory]
 */
const packCar = async (input, { blockstore, wrapWithDirectory } = {}) => {
  /* c8 ignore next 1 */
  blockstore = blockstore || new FsBlockStore()
  const { root: cid } = await pack({ input, blockstore, wrapWithDirectory })
  const car = new BlockstoreCarReader(1, [cid], blockstore)
  return { cid, car }
}

/**
 * @param {Deal[]} deals
 * @returns {Deal[]}
 */
const decodeDeals = (deals) =>
  deals.map((deal) => {
    const { dealActivation, dealExpiration, lastChanged } = {
      dealExpiration: null,
      dealActivation: null,
      ...deal,
    }

    return {
      ...deal,
      lastChanged: new Date(lastChanged),
      ...(dealActivation && { dealActivation: new Date(dealActivation) }),
      ...(dealExpiration && { dealExpiration: new Date(dealExpiration) }),
    }
  })

/**
 * @param {Pin} pin
 * @returns {Pin}
 */
const decodePin = (pin) => ({ ...pin, created: new Date(pin.created) })

/**
 * Convert the passed blob to an "import candidate" - an object suitable for
 * passing to the ipfs-unixfs-importer. Note: content is an accessor so that
 * the stream is created only when needed.
 *
 * @param {string} path
 * @param {Pick<Blob, 'stream'>|{ stream: () => AsyncIterable<Uint8Array> }} blob
 * @returns {import('ipfs-core-types/src/utils.js').ImportCandidate}
 */
function toImportCandidate(path, blob) {
  /** @type {AsyncIterable<Uint8Array>} */
  let stream
  return {
    path,
    get content() {
      stream = stream || blob.stream()
      return stream
    },
  }
}




/***/ })

};
;
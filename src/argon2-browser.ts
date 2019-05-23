export namespace Argon2 {
    interface ArgonModule {
        ALLOC_NORMAL: number;
        _argon2_verify: CallableFunction;
        _argon2_hash: CallableFunction;
        _free (descriptor: number): void;
        _argon2_error_message (res: number): number;
        allocate (value: any, typeSize: 'i8', allocator: number): number
        intArrayFromString (str: string): number
        Pointer_stringify (res: number): string;
        HEAP8: Int8Array;
    }

    declare const Module: ArgonModule;
    declare const importScripts: CallableFunction | undefined;

    const defaultDistPath = '/node_modules/argon2-browser/assets';

    /**
     * @enum
     */
    export enum ArgonType {
        Argon2d = 0,
        Argon2i = 1,
        Argon2id = 2
    }

    var scriptLoadedPromise;

    function loadScript (src) {
        return new Promise(function (resolve, reject) {
            if (typeof importScripts === 'function') {
                importScripts(src);
                resolve();
            } else {
                var el = document.createElement('script');
                el.src = src;
                el.onload = function () { resolve(); };
                el.onerror = function () { reject('Error loading script'); };
                document.body.appendChild(el);
            }
        });
    }

    function allocateArray (strOrArr) {
        var arr = strOrArr instanceof Uint8Array || strOrArr instanceof Array ? strOrArr
            : Module.intArrayFromString(strOrArr);
        return Module.allocate(arr, 'i8', Module.ALLOC_NORMAL);
    }

    /**
     * Argon2 hash
     * @example
     *  argon2.hash({ pass: 'password', salt: 'somesalt', result: [hash' , 'hashHex' , 'encoded'] })
     *      .then(h => console.log(h.hash, h.hashHex, h.encoded))
     *      .catch(e => console.error(e.message, e.code))
     */
    export function hash (params: {
        pass: Uint8Array | string // password
        salt: Uint8Array | string // salt
        memKb: number // used memory, in KiB
        iterations?: number // the number of iterations
        hashLen?: number // desired hash length
        type?: ArgonType; // Argon2d default
        distPath?: string; // asm.js script location, without trailing slash
        parallelism?: 1 // desired parallelism. Disabled to wasm complaint
        result?: Array<'hash' | 'hashHex' | 'encoded'> // field you get in result
    }): Promise<{
        hash?: Uint8Array;
        hashHex?: string;
        encoded?: string;
    }> {
        if (!scriptLoadedPromise) {
            var distPath = params.distPath || defaultDistPath;
            scriptLoadedPromise = loadScript(distPath + '/argon2-asm.min.js');
        }
        return scriptLoadedPromise.then(function () {
            var tCost = params.iterations || 1;
            var mCost = params.memKb || 1024;
            var parallelism = params.parallelism || 1;
            var pwd = allocateArray(params.pass);
            var pwdlen = params.pass.length;
            var salt = allocateArray(params.salt);
            var saltlen = params.salt.length;
            var hash = Module.allocate(new Array(params.hashLen || 24), 'i8', Module.ALLOC_NORMAL);
            var hashlen = params.hashLen || 24;
            var encoded = Module.allocate(new Array(512), 'i8', Module.ALLOC_NORMAL);
            var encodedlen = 512;
            var argon2Type = params.type || ArgonType.Argon2d;
            var version = 0x13;
            var err;
            var hashNeeded = params.result ? params.result.includes('hash') : true;
            var hexNeeded = params.result ? params.result.includes('hashHex') : false;
            var encodedNeeded = params.result ? params.result.includes('encoded') : false;
            try {
                var res = Module._argon2_hash(tCost, mCost, parallelism, pwd, pwdlen, salt, saltlen,
                    hash, hashlen, encoded, encodedlen, argon2Type, version
                );
            } catch (e) {
                err = e;
            }
            var result;
            if (res === 0 && !err) {
                var hashStr = '';
                var hashArr = new Uint8Array(hashlen);
                for (var i = 0; i < hashlen; i++) {
                    var byte = Module.HEAP8[hash + i];
                    hashArr[i] = byte;
                    if (hexNeeded) {
                        hashStr += ('0' + (0xFF & byte).toString(16)).slice(-2);
                    }
                }

                result = {hash: hashArr};
                if (hashNeeded) {
                    result.hash = hashArr;
                }
                if (hexNeeded) {
                    result.hashHex = hashStr;
                }
                if (encodedNeeded) {
                    result.encoded = Module.Pointer_stringify(encoded);
                }
            } else {
                try {
                    if (!err) {
                        err = Module.Pointer_stringify(Module._argon2_error_message(res));
                    }
                } catch (e) {
                }
                result = {message: err, code: res};
            }
            try {
                Module._free(pwd);
                Module._free(salt);
                Module._free(hash);
                Module._free(encoded);
            } catch (e) { }
            if (err) {
                throw result;
            } else {
                return result;
            }
        });
    }

    /**
     * Argon2 verify function
     * @example
     *  argon2.verify({ pass: 'password', encoded: 'encoded-hash' })
     *      .then(() => console.log('OK'))
     *      .catch(e => console.error(e.message, e.code))
     */
    export function verify (params: {
        pass: Uint8Array | string // password
        encoded: string
        type?: ArgonType; // may be omitted & get from encoded string Argon2d default
        distPath?: string; // asm.js script location, without trailing slash
    }): Promise<void> {
        if (!scriptLoadedPromise) {
            var distPath = params.distPath || defaultDistPath;
            scriptLoadedPromise = loadScript(distPath + '/argon2-asm.min.js');
        }
        return scriptLoadedPromise.then(function () {
            var pwd = allocateArray(params.pass);
            var pwdlen = params.pass.length;
            var enc = allocateArray(params.encoded);
            var argon2Type = params.type;
            if (argon2Type === undefined) {
                var typeStr = params.encoded.split('$')[1];
                if (typeStr) {
                    typeStr = typeStr.replace('a', 'A');
                    argon2Type = ArgonType[typeStr] || ArgonType.Argon2d;
                }
            }
            var err;
            try {
                var res = Module._argon2_verify(enc, pwd, pwdlen, argon2Type);
            } catch (e) {
                err = e;
            }
            var result;
            if (res || err) {
                try {
                    if (!err) {
                        err = Module.Pointer_stringify(Module._argon2_error_message(res));
                    }
                } catch (e) {
                }
                result = {message: err, code: res};
            }
            try {
                Module._free(pwd);
                Module._free(enc);
            } catch (e) { }
            if (err) {
                throw result;
            } else {
                return result;
            }
        });
    }
}

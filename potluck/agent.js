/*
Agent to inject into a target process.

In addition to providing a simple api to enumerate
information from the process, this agent implements
function hooks in such a way that enables command
and control from its python handler prior to
resuming execution.
*/

const Ansi = true;

const Task = Object.freeze({
    "NOP"   : 0,
    "RESUME": 1,
    "CALL"  : 2,
});

rpc.exports = {

    getImage() {    // path
        return Process
            .enumerateModules()
            .sort(function (a, b) {
                return a["base"] - b["base"]
            })[0]["path"];
    },

    getPid() {      // pid
        return Process.id;
    },

    getTid() {      // tid
        return Process.getCurrentThreadId();
    },

    getArch() {     // arch (ia32, x64, arm, arm64)
        return Process.arch;
    },

    getPlatform() {     // platform (windows, darwin, linux, qnx)
        return Process.platform;
    },

    getPageSize() {     // pageSize
        return Process.pageSize;
    },

    getPointerSize() {      // pointerSize
        return Process.pointerSize;
    },

    getSymbolByName(name) {      // address, name, moduleName, fileName, lineNumber
        var symbol = DebugSymbol.fromName(name);
        if (!symbol.address.isNull())
            return symbol;
    },

    getSymbolByAddress(address) {    // address, name, moduleName, fileName, lineNumber
        var symbol = DebugSymbol.fromAddress(ptr(address));
        if (symbol.name)
            return symbol;
    },

    getFunctionsNamed(name, module = null) {        // list [ address, name, moduleName, fileName, lineNumber ]
        return DebugSymbol
            .findFunctionsNamed(name)
            .map(DebugSymbol.fromAddress)
            .filter(function(symbol) {
                return (!module || symbol.moduleName === module);
            });
    },

    getFunctionsMatching(glob, module = null) {    // list [ address, name, moduleName, fileName, lineNumber ]
        return DebugSymbol
            .findFunctionsMatching(glob)
            .map(DebugSymbol.fromAddress)
            .filter(function(symbol) {
                return (!module || symbol.moduleName === module);
            });
    },

    getThreads() {      // list [ id, state, context ]
        return Process.enumerateThreads();
    },

    getRanges(protection = "---") {     // list [ base, size, protection, file ]
        return Process.enumerateRanges(protection);
    },

    getMallocRanges(protection = "---") {
        return Process.enumerateMallocRanges(protection);
    },

    getModules() {      // list [ name, base, size, path ]
        return Process.enumerateModules();
    },

    getModuleByName(name) {         // name, base, size, path
        var module = Process.findModuleByName(name);
        if (module)
            return module;
    },

    getModuleByAddress(address) {   // name, base, size, path
        var module = Process.findModuleByAddress(ptr(address));
        if (module)
            return module;
    },

    getExportsByModuleAddress(address) {    // list [ address, name, type, moduleName ]
        var module = Process.findModuleByAddress(ptr(address));
        if (module)
            return module.enumerateExports().filter(function (e) {
                e.moduleName = module.name;
                return e;
            });
    },

    getExportsByModuleName(name) {          // list [ address, name, type, moduleName ]
        var module = Process.findModuleByName(name);
        if (module)
            return module.enumerateExports().filter(function (e) {
                e.moduleName = module.name;
                return e;
            });
    },

    getImportsByModuleAddress(address) {    //list [ address, name, type, moduleName ]
        var module = Process.findModuleByAddress(ptr(address));
        if (module)
            return module.enumerateImports().filter(function (i) {
                i.moduleName = module.name;
                return i;
            });
    },

    getImportsByModuleName(name) {          // list [ address, name, type, moduleName ]
        var module = Process.findModuleByName(name);
        if (module)
            return module.enumerateImports().filter(function (i) {
                i.moduleName = module.name;
                return i;
            });
    },

    read(address, size) {   // bytes
        return ptr(address).readByteArray(size);
        // throws frida.core.RPCException
    },
    
    dump(address, size, limit = 0, ansi = Ansi) {
        var next, buf;
        try {
            address = ptr(address);

            // Fetch memory at specified address
            buf = hexdump(address, {"length": size, "ansi": ansi});

            // Recursively check if memory is pointer
            for (var i = 0; i < limit; i++) {
                next = address.readPointer();

                // Fetch memory at next address
                buf = hexdump(next, {"length": size, "ansi": ansi});

                // If successful, dump memory at previous address
                console.log("\n" + hexdump(ptr(address), {
                    "length": Process.pointerSize, "ansi": ansi}) + "\n");

                // Iterate with next address
                address = next;
            }
            throw "Recursion limit reached: " + limit;
            
        // Dump memory at ultimate address
        } catch (error) {
            if (buf)
                console.log("\n" + buf + "\n");
            else
                console.error(error);
        }
    },

    search(pattern, address, size) {    // list [ address, size ]
        return Memory.scanSync(ptr(address), size, pattern);
        // throws frida.core.RPCException
    },
    
    searchAndDump(pattern, address, size, limit = 0, ansi = Ansi) {
        var next, matches;
        try {
            matches = [];
            address = ptr(address);
            console.log(`Searching for ${pattern} between ${address} and ${address.add(size)}`);

            // Search memory at specified address
            Memory
                .scanSync(address, size, pattern)
                .forEach(function (match) {
                    console.log("\n" + hexdump(ptr(match.address), {
                        "length": match.size, "ansi": ansi}) + "\n");
                });

            // Recursively check if memory is pointer
            for (var i = 0; i < limit; i++) {
                next = address.readPointer();

                // Search memory at next address
                Memory
                    .scanSync(next, size, pattern)
                    .forEach(function (match) {
                        console.log("\n" + hexdump(ptr(match.address), {
                            "length": match.size, "ansi": ansi}) + "\n");
                    });

                // If successful, iterate with next address
                address = next;
            }
            
        } catch (error) {
            console.error(error);
        }
    },

    searchAndDumpAll(pattern, ansi = Ansi) {
        Process.enumerateRanges("r--").forEach(function (range) {
            rpc.exports.searchAndDump(pattern, range.base, range.size, 0, ansi);
        });
    },
    
    test(args) {
        //console.log("Performing test with args: " + JSON.stringify(task.args));
        //for (var j = 0; j < 10000; j++)
        //    console.log(`${j}`);
    },

    hook(address, numArgs = 3) {
        var symbol = DebugSymbol.fromAddress(ptr(address))
        console.log(`Hooking: ${symbol}`);
        // TODO: Debug symbol is sometimes inaccurate..
        // Hooking: 0x7ff8de1fadc0 notepad.exe!LoadLibraryExW
        
        Interceptor.attach(ptr(address), {

            // Grab arguments upon entering
            onEnter: function (args) {
                this.args = [];
                for (var i = 0; i < numArgs; i++)
                    this.args.push(args[i]);

                // Guestimate backtrace with symbols and module mapping
                this.backtrace = Thread
                    .backtrace(this.context, Backtracer.FUZZY)
                    .map(function (address) {
                        var symbol = DebugSymbol.fromAddress(address);
                        var label = symbol.toString();
                        if (!symbol.moduleName) {
                            var module = Process.findModuleByAddress(address);
                            if (module) {
                                var name = "0x" + (address - module.base).toString();
                                label = symbol.address + " " + module.name + "!" + name;
                            }
                        }
                        return label;
                    });

                // TODO: pause thread and wait for tasking onEnter
            },

            // Grab and report result upon leaving
            onLeave: function (ret) {
                send(JSON.stringify({
                    thread: this.threadId,
                    addr: this.context.pc,
                    func: DebugSymbol.fromAddress(this.context.pc),
                    args: this.args,
                    ret: ret,
                    retaddr: this.returnAddress,
                    backtrace: this.backtrace,
                    context: this.context,
                }));

                // Pause thread and wait for tasking
                var resume = false;
                while (!resume) {
                    var op = recv(this.threadId, function (message) {
                        for (var i in message.payload) {
                            try {
                                var task = message.payload[i];
                                switch (task.type) {
                                    case Task.NOP:
                                        rpc.exports.test(task.args);
                                        break;
                                    
                                    case Task.RESUME:
                                        resume = true;
                                        break
                                    
                                    case Task.CALL:
                                        var func = rpc.exports[task.name];
                                        if (!func)
                                            throw "Export does not exist: " + task.name;

                                        func.apply(null, task.args);
                                        break;

                                    default:
                                        console.warn("Unknown task: " + task);
                                }
                            } catch (error) {
                                console.error(error);
                            }
                        }
                    });
                    op.wait();
                }
            },
        });
    },

    unhook() {
        Interceptor.detachAll();
    },

};

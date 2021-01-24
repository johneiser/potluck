/*
Agent to inject into a target process.

In addition to providing a simple api to enumerate
information from the process, this agent implements
function hooks in such a way that enables command
and control from its python handler prior to
resuming execution.
*/

const Task = Object.freeze({
    "NOP"   : 0,
    "RESUME": 1,
    "CALL"  : 2,
});

rpc.exports = {

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

    getExportsByModuleAddress(address) {    // list [ address, name, type ]
        var module = Process.findModuleByAddress(ptr(address));
        if (module)
            return module.enumerateExports();
    },

    getExportsByModuleName(name) {          // list [ address, name, type ]
        var module = Process.findModuleByName(name);
        if (module)
            return module.enumerateExports();
    },

    getImportsByModuleAddress(address) {    //list [ address, name, type ]
        var module = Process.findModuleByAddress(ptr(address));
        if (module)
            return module.enumerateImports();
    },

    getImportsByModuleName(name) {          // list [ address, name, type ]
        var module = Process.findModuleByName(name);
        if (module)
            return module.enumerateImports();
    },

    read(address, size) {   // bytes
        try {
            return ptr(address).readByteArray(size);
        } catch (error) {
            console.error(error);
        }
    },

    dump(address, size, ansi = true) {
        try {
            console.log("\n" + hexdump(ptr(address), {
                "length": size, "ansi": ansi}) + "\n");
        } catch (error) {
            console.error(error);
        }
    },

    search(address, size, pattern) {    // list [ address, size ]
        try {
            return Memory.scanSync(ptr(address), size, pattern);
        } catch (error) {
            console.error(error);
        }
    },

    searchAndDump(address, size, pattern, ansi = true) {
        try {
            console.log(`Searching for ${pattern}`);
            Memory
                .scanSync(ptr(address), size, pattern)
                .forEach(function (match) {
                    console.log("\n" + hexdump(ptr(match.address), {
                        "length": match.size, "ansi": ansi}) + "\n");
                });
        } catch (error) {
            console.error(error);
        }
    },

    test(args) {
        //console.log("Performing test with args: " + JSON.stringify(task.args));
        //for (var j = 0; j < 10000; j++)
        //    console.log(`${j}`);
    },

    hook(address, numArgs = 3) {
        var symbol = DebugSymbol.fromAddress(ptr(address))
        console.log(`Hooking: ${symbol}`);
        
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

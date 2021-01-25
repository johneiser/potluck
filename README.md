
# Potluck

Potluck is a custom debugger combining dynamic instrumentation with symbolic execution.

## XX WORK IN PROGRESS XX

TODO:
- [x] generate memory maps
- [x] create angr concrete target
- [x] pull state from frida using concrete target and symbion
- [ ] automatically get file backing process for simulation
- [ ] add symbolic execution functionality using pulled state

## Requirements

- python >= 3.5
- python3-pip

## Install

To install the basic frida debugger:

```
$ pip3 install git+https://github.com/johneiser/potluck.git
```

To add support for angr symbolic execution:

```
$ pip3 install potluck[angr]
```

To add support for pretty output:

```
$ pip3 install potluck[pretty]
```

# Usage


```
usage: potluck [-h] [-c CREATE] [-p PROCESS] [-f FUNCTION] [-m MODULE]
               [-n NUMBER] [-s SCRIPT] [-v] [-l LOG]

optional arguments:
  -h, --help            show this help message and exit
  -c CREATE, --create CREATE
                        spawn a process
  -p PROCESS, --process PROCESS
                        attach to process
  -f FUNCTION, --function FUNCTION
                        hook function(s) by name
  -m MODULE, --module MODULE
                        restrict hooks to module(s)
  -n NUMBER, --number NUMBER
                        number of function arguments
  -s SCRIPT, --script SCRIPT
                        file with commands to run for each hook
  -v, --verbose         print debug info
  -l LOG, --log LOG     log to file
```


# Quick start

To spawn `echo` and hook after it has written "Hello, world!".
```
$ potluck -c "$(which echo) Hello world\!" -f write
Hooking: 0x7f113af7b1d0 libc.so.6!__write
Hooking: 0x7f113ae4a280 libpthread.so.0!write
Hello world!
0x7f113af7b1d0 libc.so.6!__write (0x1, 0x56127d2b2cf0, 0xd) = 0xd
[Session(pid=37661) => 37661]> dumpret 1

               0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
56127d2b2cf0  48 65 6c 6c 6f 20 77 6f 72 6c 64 21 0a           Hello world!.

[Session(pid=37661) => 37661]> 
```


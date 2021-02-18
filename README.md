[![Documentation Status](https://readthedocs.org/projects/frida-potluck/badge/?version=latest)](https://frida-potluck.readthedocs.io/en/latest/?badge=latest)

# Potluck

Potluck is a custom debugger combining dynamic instrumentation with symbolic execution.

## XX WORK IN PROGRESS XX

TODO:
- [x] generate memory maps
- [x] create angr concrete target
- [x] pull state from frida using concrete target and symbion
- [x] automatically get file backing process for simulation
- [ ] pull state from frida manually ([angr/angr/issues/2384](https://github.com/angr/angr/issues/2384))
- [ ] do something with symbolic execution

## Requirements

- python >= 3.5
- python3-pip

## Install

To install the basic frida debugger:

```
$ sudo pip3 install git+https://github.com/johneiser/potluck.git
```

<!--
To add support for angr symbolic execution:
```
$ sudo pip3 install frida-potluck[angr]
```
-->


# Usage


```
usage: potluck [-h] [-c CREATE] [-p PROCESS] [-f FUNCTION] [-m MODULE]
               [-n NUMBER] [-s SCRIPT] [-r REMOTE] [-v]

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
  -r REMOTE, --remote REMOTE
                        address of remote frida-server
  -v, --verbose         print debug info
```


# Quick start

Spawn `echo` and hook after it has written "Hello, world!".
```
$ potluck -c "$(which echo) Hello world\!" -f write -n 3 -s <(echo -e "dump 1 0xd\n exit")
Hooking: 0x7fc6a0696280 libpthread.so.0!write
Hooking: 0x7fc6a07c71d0 libc.so.6!__write
 @ 0x7fc6a07c71d0 libc.so.6!__write (0x1, 0x55ce55689cf0, 0xd) = 0xd

               0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
55ce55689cf0  48 65 6c 6c 6f 20 77 6f 72 6c 64 21 0a           Hello world!.
```

Connect to a remote [frida-server](https://github.com/frida/frida/releases), spawn notepad, and hook after each time LoadLibrary is called.
```
$ potluck -r 192.168.1.2 -c "C:\\\\Windows\\\\System32\\\\notepad.exe" -f "LoadLibrary*" -n 1 -s <(echo -e "dump 0 64\ncontinue")
Hooking: 0x7ff8de1fadc0 notepad.exe!LoadLibraryExW
Hooking: 0x7ff8de1ffbc0 notepad.exe!LoadLibraryExA
Hooking: 0x7ff8de1ffee0 notepad.exe!LoadLibraryW
Hooking: 0x7ff8de2004f0 notepad.exe!LoadLibraryA
Hooking: 0x7ff8dd9235a0 notepad.exe!LoadLibraryExW
Hooking: 0x7ff8dd92bbb0 notepad.exe!LoadLibraryExA
Hooking: 0x7ff8dd977ea0 notepad.exe!LoadLibraryA
Hooking: 0x7ff8dd979400 notepad.exe!LoadLibraryW
 @ 0x7ff8dd9235a0 notepad.exe!LoadLibraryExW (0x2f2b1f2c0) = 0x7ff8db370000

            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
2f2b1f2c0  43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00  C.:.\.W.i.n.d.o.
2f2b1f2d0  77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00  w.s.\.s.y.s.t.e.
2f2b1f2e0  6d 00 33 00 32 00 5c 00 75 00 78 00 74 00 68 00  m.3.2.\.u.x.t.h.
2f2b1f2f0  65 00 6d 00 65 00 2e 00 64 00 6c 00 6c 00 00 00  e.m.e...d.l.l...

...
```

For further details, refer to the [docs](https://frida-potluck.readthedocs.io/en/latest/).

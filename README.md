
# Potluck

Potluck is a custom debugger combining dynamic instrumentation with symbolic execution.

## XX WORK IN PROGRESS XX

TODO:
- generate memory maps
- create angr concrete target
- pull state from frida using concrete target and symbion

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
$ pip3 install git+https://github.com/johneiser/potluck.git[angr]
```

To add support for pretty output:

```
$ pip3 install git+https://github.com/johneiser/potluck.git[pretty]
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
$ potluck -c "$(which echo) Hello world\!" -f write -s <(echo -e "dumpret 1")
Hooking: 0x7f0879bb71d0 libc.so.6!__write
Hooking: 0x7f0879a86280 libpthread.so.0!write
Hello world!
0x7f0879bb71d0 libc.so.6!__write (0x1, 0x557415ed9cf0, 0xd) = 0xd
[Session(pid=37661) => 37661]> 
```

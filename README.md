
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

```
$ pip3 install git+https://github.com/johneiser/potluck.git
```

# Usage


```
usage: potluck [-h] [-s SPAWN] [-p PROCESS] [-f FUNCTIONS] [-a ADDRESSES]
               [-m MODULES] [-n NUMBER] [-v] [-l LOG]

optional arguments:
  -h, --help            show this help message and exit
  -s SPAWN, --spawn SPAWN
                        spawn a process
  -p PROCESS, --process PROCESS
                        attach to process
  -f FUNCTIONS, --function FUNCTIONS
                        hook function(s) by name
  -a ADDRESSES, --address ADDRESSES
                        hook function(s) by address
  -m MODULES, --module MODULES
                        restrict hooks to module(s)
  -n NUMBER, --number NUMBER
                        number of function arguments
  -v, --verbose         print debug info
  -l LOG, --log LOG     log to file
```

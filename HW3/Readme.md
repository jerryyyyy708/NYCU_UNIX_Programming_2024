# UNIX HW3
Simple Debugger.
## Build
```
//install library
make setup

//sdb
make

//sdb, sdb2, sdb3
make all
```

## Description
* sdb: restore next in cont and syscall if next is bp (stable)
* sdb2: reset all bp before command and restore all if hit bp to ensure disassemble shows correct (might be more correct in hidden case)
* sdb3: same as sdb but use single step instead for cases with same bp duplicate (just for backup)

## Note
1. For demo, run sdb first, and if there is an error, use sdb2 instead.
2. can change onestep in syscall to si() instead of logic
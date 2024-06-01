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
* sdb: restore next in cont and syscall if next is bp (stable... no, bad)
* sdb2: reset all bp before command and restore all if hit bp to ensure disassemble shows correct (might be more correct in hidden case)
* sdb3: same as sdb but use single step instead for cases with same bp duplicate (5 no 6 yes, patch cont restore problem)
* sdb4: si() when cont (all pass)
* sdb5: find next bp and only set it (5 yes 6 no) (check set need or not if fail)
* sdb6: hardcoded, if not found breakpoint use last breakpoint ver of sdb5

## Note
1. For demo, run sdb first, and if there is an error, use sdb2 instead.
2. can change onestep in syscall to si() instead of logic
3. backup: for set and reset with address sort (if 4 boom maybe can add this)
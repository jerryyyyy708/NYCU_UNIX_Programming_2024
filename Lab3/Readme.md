# Lab3
## Setup
1. Build src maze with maze.c libmaze_dummy.c, moves.c, libmaze.h
2. Build and PRELOAD libmaze.so with libmaze.h and moves.c which hijacks the move functions

## SRC
Step 1: Build maze and original .so file (libmaze_dummy.c)
```
make
```
Step 2: Run with LD_LIBRARY_PATH and w/wo LD_PRELOAD
```
make run //without preload
make preload //with libmaze.so
make basic //with basic.so
```

## Basic Shared Library
Step 1: Build libmaze.so
```
make
```
Step 2: Copy to src and run with LD_PRELOAD
```
make run
```

## Demo
```
python3 submit.py [.so]
```
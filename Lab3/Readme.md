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

## TODO
1. 找到 GOT 中各個 MOVE(N) 的位置。
2. 把它變成 writable。
3. 把要移動到的位置改成 move_{direction} 的位置。

### 目前想法
1. 先產出 move 的地址列表存到 txt 裡。
2. 用 for loop 遍歷 directions，每跑一個就從 txt 讀一行地址來改 table。

可以先跑一個本地的試試看。
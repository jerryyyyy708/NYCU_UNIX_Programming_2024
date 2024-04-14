#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <dlfcn.h>

#include "libmaze.h"

static void (*o_move_up)(maze_t *mz) = NULL;
static void (*o_move_down)(maze_t *mz) = NULL;
static void (*o_move_left)(maze_t *mz) = NULL;
static void (*o_move_right)(maze_t *mz) = NULL;

static int (*original_maze_init)() = NULL;
static maze_t *(*original_maze_load)(const char *fn) = NULL;

//searching result
static int visited[101][101] = {0};
int maze_cpy[101][101];
int cx_cpy;
int cy_cpy;
int ex_cpy;
int ey_cpy;
int found;
static int directions[202];
static int step_count  = 0;

static int _dirx[] = { 0, 0, -1, 1 };
static int _diry[] = { -1, 1, 0, 0 };

void injection_init(void) __attribute__((constructor));

void injection_init(void) {
    original_maze_init = dlsym(RTLD_NEXT, "maze_init");
    original_maze_load = dlsym(RTLD_NEXT, "maze_load");
    o_move_up = dlsym(RTLD_NEXT, "move_up");
    o_move_down = dlsym(RTLD_NEXT, "move_down");
    o_move_left = dlsym(RTLD_NEXT, "move_left");
    o_move_right = dlsym(RTLD_NEXT, "move_right");
    if (!original_maze_init || !original_maze_load || !o_move_up){
        fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }
}

int maze_init() {
	printf("UP112_GOT_MAZE_CHALLENGE\n");
	return original_maze_init();
}

void print_directions() {
    printf("(0:up, 1:down, 2:left, 3:right):\n");
    for (int i = 0; i < step_count; i++) {
        printf("%d ", directions[i]);
    }
    printf("\n");
}

void dfs(int x, int y, int from_dir) {
    if (x < 0 || x >= 101 || y < 0 || y >= 101 || visited[y][x] || maze_cpy[y][x] != 0) {
        return;
    }

    visited[y][x] = 1;
    if (from_dir != -1) {
        directions[step_count] = from_dir;
        step_count++;
    }

    if (x == ex_cpy && y == ey_cpy) {
        found = 1;
        //print_directions();
        return;
    }

    for (int i = 0; i < 4; i++) {
        int nx = x + _dirx[i];
        int ny = y + _diry[i];
        if (!found) {
            dfs(nx, ny, i);
        }
    }

    if (!found && from_dir != -1) {
        step_count--;
        visited[y][x] = 0;
    }
}

maze_t * maze_load(const char *fn){
    maze_t *mz = original_maze_load(fn);
    for(int i = 0; i < mz->h; i++) {
		for(int j = 0; j < mz->w; j++) {
			maze_cpy[i][j] = mz->blk[i][j];
		}
	}
    cx_cpy = mz->sx;
	cy_cpy = mz->sy;
	ex_cpy = mz->ex;
	ey_cpy = mz->ey;
    dfs(cx_cpy, cy_cpy, -1);
    return mz;
}

void move_1(maze_t *mz){
    print_directions();
    for(int i=0; i<step_count;i++){
        switch (directions[i]){
            case 0:
                o_move_up(mz);
                break;
            case 1:
                o_move_down(mz);
                break;
            case 2:
                o_move_left(mz);
                break;
            case 3:
                o_move_right(mz);
                break;
        }    
    }
}
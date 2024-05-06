#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include "libmaze.h"

static void * __stored_ptr = NULL;
static void * main_base = NULL;

static void (*o_move_up)(maze_t *mz) = NULL;
static void (*o_move_down)(maze_t *mz) = NULL;
static void (*o_move_left)(maze_t *mz) = NULL;
static void (*o_move_right)(maze_t *mz) = NULL;
static void *(*o_get_ptr)() = NULL;

static int (*original_maze_init)() = NULL;
static maze_t *(*original_maze_load)(const char *fn) = NULL;
char * got = "got.txt";
static void *got_function_addresses[1200];

//searching result
static int visited[101][101] = {0};
int maze_cpy[101][101];
int cx_cpy;
int cy_cpy;
int ex_cpy;
int ey_cpy;
int found;
static int directions[101*101];
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
    o_get_ptr = dlsym(RTLD_NEXT, "maze_get_ptr");
    if (!original_maze_init || !original_maze_load || !o_move_up || !o_get_ptr){
        fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }
}

void set_main(){
    unsigned int offset = 0x1b7a9; //get from .py
    main_base = __stored_ptr - offset;
}


void initialize_got_address(){
    FILE *file = fopen(got, "r");
    if (!file) {
        fprintf(stderr, "Failed to open file: %s\n", got);
        exit(EXIT_FAILURE);
    }

    char buffer[1024];
    int index = 0;
    while (fgets(buffer, sizeof(buffer), file) && index < 1200) {
        unsigned long offset;
        if (sscanf(buffer, "%lx", &offset) == 1) {
            got_function_addresses[index++] = main_base + offset;
        }
    }

    fclose(file);

    printf("Successfully set table!\n");
}

int maze_init() {
	printf("UP112_GOT_MAZE_CHALLENGE\n");
    __stored_ptr = o_get_ptr();
    set_main();
    printf("Main function stored in: %p\n", main_base);
    initialize_got_address();
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
    }
}



void inject_table(){
    long pagesize = sysconf(_SC_PAGESIZE);
    print_directions();
    for(int i=0; i<step_count;i++){
        uintptr_t page_start = (uintptr_t)got_function_addresses[i] & ~(pagesize - 1);

        // Temporarily change the protection to read-write-execute
        if (mprotect((void*)page_start, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
            perror("mprotect failed");
            exit(EXIT_FAILURE);
        }

        switch (directions[i]){
            case 0:
                //set the address that got_funtion_address[i] goes to into o_move_up
                *((void**)got_function_addresses[i]) = o_move_up;
                break;
            case 1:
                //set the address that got_funtion_address[i] goes to into o_move_down
                *((void**)got_function_addresses[i]) = o_move_down;
                break;
            case 2:
                //set the address that got_funtion_address[i] goes to into o_move_left
                *((void**)got_function_addresses[i]) = o_move_left;
                break;
            case 3:
                //set the address that got_funtion_address[i] goes to into o_move_right
                *((void**)got_function_addresses[i]) = o_move_right;
                break;
        }    
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
    inject_table();
    return mz;
}
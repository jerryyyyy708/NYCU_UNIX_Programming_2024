#include <linux/module.h>	// included for all kernel modules
#include <linux/kernel.h>	// included for KERN_INFO
#include <linux/init.h>		// included for __init and __exit macros
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/sched.h>	// task_struct requried for current_uid()
#include <linux/cred.h>		// for current_uid();
#include <linux/slab.h>		// for kmalloc/kfree
#include <linux/uaccess.h>	// copy_to_user
#include <linux/string.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/random.h>
#include "maze.h"


DEFINE_MUTEX(maze_mutex);
static dev_t devnum;
static struct cdev c_dev;
static struct class * clazz;
static int user_cnt = 0;
static int pids[3] = {-1,-1,-1};
maze_t mazes[3];
coord_t players[3];
bool debug = false;

static void random_build_maze(int idx, int x, int y) {
    unsigned int rand_val;
    mazes[idx].w = x;
    mazes[idx].h = y;

    get_random_bytes( & rand_val, sizeof(rand_val));
    unsigned int sx = 1 + (rand_val % (x - 3));
    get_random_bytes( & rand_val, sizeof(rand_val));
    unsigned int sy = 1 + (rand_val % (y - 3));

    unsigned int ex, ey;
    do {
        get_random_bytes( & rand_val, sizeof(rand_val));
        ex = 1 + (rand_val % (x - 3));
        get_random_bytes( & rand_val, sizeof(rand_val));
        ey = 1 + (rand_val % (y - 3));
    } while (sx == ex && sy == ey);

    mazes[idx].sx = sx;
    mazes[idx].sy = sy;
    mazes[idx].ex = ex;
    mazes[idx].ey = ey;

    int x_move = ex - sx;
    int y_move = ey - sy;

    mazes[idx].blk[sy][sx] = 'A';
    int current_x = sx, current_y = sy;

    while (current_x != ex || current_y != ey) {
        bool move_horizontally = false;
        if (x_move != 0 && y_move != 0) {
            get_random_bytes( & rand_val, sizeof(rand_val));
            move_horizontally = (rand_val & 1);
        } else if (x_move != 0) {
            move_horizontally = true;
        }

        if (move_horizontally) {
            current_x += (x_move > 0) ? 1 : -1;
            x_move -= (x_move > 0) ? 1 : -1;
        } else {
            current_y += (y_move > 0) ? 1 : -1;
            y_move -= (y_move > 0) ? 1 : -1;
        }
        mazes[idx].blk[current_y][current_x] = 'A';
    }

    for (int i = 0; i < y; ++i) {
        for (int j = 0; j < x; ++j) {
            if (mazes[idx].blk[i][j] == 'A')
                mazes[idx].blk[i][j] = '.';
            else if (i == 0 || i == y - 1 || j == 0 || j == x - 1)
                mazes[idx].blk[i][j] = '#';
            else {
                get_random_bytes( & rand_val, sizeof(rand_val));
                mazes[idx].blk[i][j] = (rand_val % 2 == 0) ? '#' : '.';
            }
        }
    }

    for (int i = 1; i < y - 1; ++i) {
        for (int j = 1; j < x - 1; ++j) {
            if (mazes[idx].blk[i][j] == '#') {
                bool has_wall_around =
                    mazes[idx].blk[i - 1][j] == '#' ||
                    mazes[idx].blk[i + 1][j] == '#' ||
                    mazes[idx].blk[i][j - 1] == '#' ||
                    mazes[idx].blk[i][j + 1] == '#';

                if (!has_wall_around) {
                    mazes[idx].blk[i][j] = '.';
                }
            }
        }
    }

    mazes[idx].blk[sy][sx] = 'S';
    mazes[idx].blk[ey][ex] = 'E';
    players[idx].x = sx;
    players[idx].y = sy;
}

static void build_maze(int idx, int x, int y) {
    mazes[idx].w = x;
    mazes[idx].h = y;
    mazes[idx].sx = 1;
    mazes[idx].sy = 1;
    mazes[idx].ex = x - 2;
    mazes[idx].ey = y - 2;
    for (int i = 0; i < y; ++i) {
        for (int j = 0; j < x; ++j) {
            mazes[idx].blk[i][j] = (i == 0 || i == y - 1 || j == 0 || j == x - 1) ? '#' : '.';
        }
    }
    mazes[idx].blk[1][1] = 'S';
    mazes[idx].blk[y - 2][x - 2] = 'E';
    players[idx].x = 1;
    players[idx].y = 1;
    return;
}

static bool is_created(void) {
    for (int i = 0; i < 3; i++) {
        if (pids[i] == current -> pid)
            return true;
    }
    return false;
}

static int get_maze_id(void) {
    for (int i = 0; i < 3; i++) {
        if (pids[i] == current -> pid)
            return i;
    }
    return -1;
}

static int maze_dev_open(struct inode * i, struct file * f) {
    printk(KERN_INFO "maze: device opened.\n");
    return 0;
}

static int maze_dev_close(struct inode * i, struct file * f) {
    int idx = get_maze_id();
    if (idx != -1) {
        pids[idx] = -1;
        user_cnt--;
    }
    return 0;
}

static ssize_t maze_dev_read(struct file * f, char __user * buf, size_t len, loff_t * off) {
    int idx = get_maze_id();
    if (idx == -1)
        return -ENOENT;

    int maze_len = mazes[idx].w * mazes[idx].h;
    char * maze_layout = kmalloc(maze_len, GFP_KERNEL); // Use kmalloc to allocate memory
    if (!maze_layout)
        return -ENOMEM; // Return if allocation failed

    int count = 0;
    for (int i = 0; i < mazes[idx].h; ++i) {
        for (int j = 0; j < mazes[idx].w; ++j) {
            maze_layout[count] = (mazes[idx].blk[i][j] == '#') ? 1 : 0;
            count++;
        }
    }

    // Make sure we don't copy more data than available or requested
    size_t bytes_to_copy = min(maze_len - (size_t)( * off), len);
    if (copy_to_user(buf, maze_layout + * off, bytes_to_copy)) {
        kfree(maze_layout); // Free allocated memory
        return -EFAULT;
    }

    * off += bytes_to_copy;
    kfree(maze_layout); // Free allocated memory after use
    return bytes_to_copy;
}

static ssize_t maze_dev_write(struct file * f,
    const char __user * buf, size_t len, loff_t * off) {

    if (len % sizeof(coord_t) != 0) {
        return -EINVAL;
    }

    int idx = get_maze_id();
    if (idx == -1) {
        return -EBADFD;
    }

    size_t num_moves = len / sizeof(coord_t);
    coord_t * moves = kmalloc(len, GFP_KERNEL);
    if (!moves) {
        return -ENOMEM;
    }

    if (copy_from_user(moves, buf, len)) {
        kfree(moves);
        return -EBUSY;
    }

    for (size_t i = 0; i < num_moves; i++) {
        coord_t move = moves[i];
        if (!((move.x == -1 && move.y == 0) || (move.x == 1 && move.y == 0) ||
                (move.x == 0 && move.y == -1) || (move.x == 0 && move.y == 1))) {
            continue;
        }

        int new_x = players[idx].x + move.x;
        int new_y = players[idx].y + move.y;
        if (new_x >= 0 && new_x < mazes[idx].w && new_y >= 0 && new_y < mazes[idx].h) {
            if (mazes[idx].blk[new_y][new_x] != '#') {
                players[idx].x = new_x;
                players[idx].y = new_y;
            }
        }
    }

    kfree(moves);
    return len;
}

static long maze_dev_ioctl(struct file * fp, unsigned int cmd, unsigned long arg) {
    coord_t coord;
    int idx;
    long ret = 0;
    if (cmd != MAZE_CREATE) {
        if (!is_created())
            return -ENOENT;
    }
    switch (cmd) {
    case MAZE_CREATE:
        mutex_lock( & maze_mutex);
        pid_t cur = current -> pid;
        // check if a maze is already created
        if (is_created()) {
            mutex_unlock( & maze_mutex);
            return -EEXIST;
        }
        // check is there a spare maze
        if (user_cnt == _MAZE_MAXUSER) {
            printk(KERN_INFO "Too many users.\n");
            mutex_unlock( & maze_mutex);
            return ENOMEM;
        }

        if (copy_from_user( & coord, (coord_t __user * ) arg, sizeof(coord))) {
            mutex_unlock( & maze_mutex);
            return -EBUSY;
        }
        if (coord.x < 0 || coord.y < 0 || coord.x > _MAZE_MAXX || coord.y > _MAZE_MAXY) {
            mutex_unlock( & maze_mutex);
            return -EINVAL;
        }
        //assign a maze
        for (int i = 0; i < 3; i++) {
            if (pids[i] == -1) {
                pids[i] = cur;
                user_cnt++;
                if (debug)
                    build_maze(i, coord.x, coord.y);
                else
                    random_build_maze(i, coord.x, coord.y);
                break;
            }
        }
        mutex_unlock( & maze_mutex);
        break;

    case MAZE_RESET:
        idx = get_maze_id();
        if (idx == -1) {
            return -ENOENT;
        }
        players[idx].x = mazes[idx].sx;
        players[idx].y = mazes[idx].sy;
        break;

    case MAZE_DESTROY:
        idx = get_maze_id();
        pids[idx] = -1;
        user_cnt--;
        break;

    case MAZE_GETSIZE:
        idx = get_maze_id();
        if (idx == -1) { // don't need this
            return -ENOENT;
        }
        coord.x = mazes[idx].w;
        coord.y = mazes[idx].h;
        if (copy_to_user((coord_t __user * ) arg, & coord, sizeof(coord))) {
            return -EFAULT;
        }
        break;

    case MAZE_MOVE:
        idx = get_maze_id();
        if (idx == -1) {
            return -ENOENT;
        }
        if (copy_from_user( & coord, (coord_t __user * ) arg, sizeof(coord))) {
            return -EFAULT;
        }
        if (!((coord.x == -1 && coord.y == 0) ||
                (coord.x == 1 && coord.y == 0) ||
                (coord.x == 0 && coord.y == -1) ||
                (coord.x == 0 && coord.y == 1))) {
            return ret;
        }
        int tempx = players[idx].x + coord.x;
        int tempy = players[idx].y + coord.y;
        if (!(tempx < 1 || tempx >= mazes[idx].w ||
                tempy < 1 || tempy >= mazes[idx].h)) {
            if (mazes[idx].blk[tempy][tempx] != '#') {
                players[idx].x = tempx;
                players[idx].y = tempy;
            }
        }
        break;

    case MAZE_GETPOS:
        idx = get_maze_id();
        if (idx == -1) {
            return -ENOENT;
        }
        coord.x = players[idx].x;
        coord.y = players[idx].y;
        if (copy_to_user((coord_t __user * ) arg, & coord, sizeof(coord))) {
            return -EFAULT;
        }
        break;

    case MAZE_GETSTART:
        idx = get_maze_id();
        if (idx == -1) {
            return -ENOENT;
        }
        coord.x = mazes[idx].sx;
        coord.y = mazes[idx].sy;
        if (copy_to_user((coord_t __user * ) arg, & coord, sizeof(coord))) {
            return -EFAULT;
        }
        break;
    case MAZE_GETEND:
        idx = get_maze_id();
        if (idx == -1) {
            return -ENOENT;
        }
        coord.x = mazes[idx].ex;
        coord.y = mazes[idx].ey;
        if (copy_to_user((coord_t __user * ) arg, & coord, sizeof(coord))) {
            return -EFAULT;
        }
        break;

    default:
        ret = -EINVAL;
    }
    return ret;
}

static
const struct file_operations maze_dev_fops = {
    .owner = THIS_MODULE,
    .open = maze_dev_open,
    .read = maze_dev_read,
    .write = maze_dev_write,
    .unlocked_ioctl = maze_dev_ioctl,
    .release = maze_dev_close
};

static int maze_proc_read(struct seq_file * m, void * v) {
    for (int i = 0; i < 3; i++) {
        if (pids[i] == -1) {
            seq_printf(m, "#0%d: vacancy\n\n", i);
        } else {
            seq_printf(m, "#0%d:\n pid %d - [%d x %d]: (%d, %d) -> (%d, %d) @ (%d %d)\n", i, pids[i], mazes[i].w, mazes[i].h, mazes[i].sx, mazes[i].sy, mazes[i].ex, mazes[i].ey, players[i].x, players[i].y);

            for (int y = 0; y < mazes[i].h; y++) {
                seq_printf(m, "- %03d: ", y);
                for (int x = 0; x < mazes[i].w; x++) {
                    if (x == players[i].x && y == players[i].y) {
                        seq_printf(m, "*");
                    } else
                        seq_printf(m, "%c", mazes[i].blk[y][x]);
                }
                seq_printf(m, "\n");
            }
            seq_printf(m, "\n");
        }
    }
    return 0;
}

static int maze_proc_open(struct inode * inode, struct file * file) {
    return single_open(file, maze_proc_read, NULL);
}

static
const struct proc_ops maze_proc_fops = {
    .proc_open = maze_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static char * maze_devnode(const struct device * dev, umode_t * mode) {
    if (mode == NULL) return NULL;
    * mode = 0666;
    return NULL;
}

static int __init maze_init(void) {
    // create char dev
    if (alloc_chrdev_region( & devnum, 0, 1, "updev") < 0)
        return -1;
    if ((clazz = class_create("upclass")) == NULL)
        goto release_region;
    clazz -> devnode = maze_devnode;
    if (device_create(clazz, NULL, devnum, NULL, "maze") == NULL)
        goto release_class;
    cdev_init( & c_dev, & maze_dev_fops);
    if (cdev_add( & c_dev, devnum, 1) == -1)
        goto release_device;

    // create proc
    proc_create("maze", 0, NULL, & maze_proc_fops);

    printk(KERN_INFO "maze: initialized.\n");
    return 0; // Non-zero return means that the module couldn't be loaded.

    release_device:
        device_destroy(clazz, devnum);
    release_class:
        class_destroy(clazz);
    release_region:
        unregister_chrdev_region(devnum, 1);
    return -1;
}

static void __exit maze_cleanup(void) {
    remove_proc_entry("maze", NULL);

    cdev_del( & c_dev);
    device_destroy(clazz, devnum);
    class_destroy(clazz);
    unregister_chrdev_region(devnum, 1);

    printk(KERN_INFO "maze: cleaned up.\n");
}

module_init(maze_init);
module_exit(maze_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("jerryyyyy708");
MODULE_DESCRIPTION("Lab2");
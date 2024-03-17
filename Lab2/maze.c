/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
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
#include "maze.h"


static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;
char *maze0 = "#00: vacancy";
char *maze1 = "#01: vacancy";
char *maze2 = "#02: vacancy";
char *maze_content = "#00: vacancy\n\n#01: vacancy\n\n#02: vacancy\n\n";
static int user_cnt = 0;
static int pids[3] = {-1, -1, -1};
struct maze_t mazes[3];
struct coord_t players[3];
bool debug = true;

static void random_build_maze(int idx, int x, int y){
	return;
}

static void build_maze(int idx, int x, int y){
	mazes[idx].w = x;
    mazes[idx].h = y;
    mazes[idx].sx = 1;
    mazes[idx].sy = 1;
    mazes[idx].ex = x - 2;
    mazes[idx].ey = y - 2;
	for(int i = 0; i < y; ++i) {
        for(int j = 0; j < x; ++j) {
            mazes[idx].blk[i][j] = (i == 0 || i == y-1 || j == 0 || j == x-1) ? '#' : '.';
        }
    }
	mazes[idx].blk[sx][sy] = '*';
	mazes[idx].blk[ex][ey] = 'E';
	players[idx].x = 1;
	players[idx].y = 1;
	return
}

static bool is_created(){
	for(int i=0; i<3; i++){
		if(pids[i] == current -> pid)
			return true;
	}
	return false;
}

static int maze_dev_open(struct inode *i, struct file *f) {
	printk(KERN_INFO "maze: device opened.\n");
	return 0;
}

static int maze_dev_close(struct inode *i, struct file *f) {
	printk(KERN_INFO "maze: device closed.\n");
	return 0;
}

static ssize_t maze_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
	printk(KERN_INFO "maze: read %zu bytes @ %llu.\n", len, *off);
	return len;
}

static ssize_t maze_dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
	printk(KERN_INFO "maze: write %zu bytes @ %llu.\n", len, *off);
	return len;
}

static long maze_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
	coord_t coord;
	long ret = 0;
	if(cmd != MAZE_CREATE){
		if(!is_created())
			return -EBUSY;
	}
    switch (cmd) {
        case MAZE_CREATE:
			pid_t cur = current -> pid;
			// check if a maze is already created
			if (is_created())
				return -EEXIST;
			// check is there a spare maze
			if (user_cnt == _MAZE_MAXUSER)
				return ENOMEM;
            if (copy_from_user(&coord, (coord_t __user *)arg, sizeof(coord))) {
                return -EBUSY;
            }
			if(coord.x < 0 || coord.y < 0 || coord.x > _MAZE_MAXX || coord.y > _MAZE_MAXY)
				return -EINVAL;
			//assign a maze
			for(int i=0; i<3; i++){
				if(pid[i] == -1){
					pid[i] = cur;
					user_cnt ++;
					if(debug)
						build_maze(i, coord.x, coord.y);
					else
						random_build_maze(i, coord.x, coord.y);

					break;
				}
			}

            printk(KERN_INFO "create maze done.");
			created = true;
            break;

        case MAZE_RESET:
            printk(KERN_INFO "Resetting the maze.\n");
            break;

        case MAZE_DESTROY:
            printk(KERN_INFO "Destroying the maze.\n");
            break;

        case MAZE_GETSIZE:
            if (copy_to_user((coord_t __user *)arg, &coord, sizeof(coord))) {
                return -EFAULT;
            }
            printk(KERN_INFO "Getting maze size.\n");
            break;

        case MAZE_MOVE:
            if (copy_from_user(&coord, (coord_t __user *)arg, sizeof(coord))) {
                return -EFAULT;
            }
            printk(KERN_INFO "Moving to position (%d, %d).\n", coord.x, coord.y);
            break;

        case MAZE_GETPOS:
        case MAZE_GETSTART:
        case MAZE_GETEND:
            if (copy_to_user((coord_t __user *)arg, &coord, sizeof(coord))) {
                return -EFAULT;
            }
            printk(KERN_INFO "Getting maze position/start/end.\n");
            break;

        default:
            ret = -EINVAL;
    }
	return ret;
}

static const struct file_operations maze_dev_fops = {
	.owner = THIS_MODULE,
	.open = maze_dev_open,
	.read = maze_dev_read,
	.write = maze_dev_write,
	.unlocked_ioctl = maze_dev_ioctl,
	.release = maze_dev_close
};

static int maze_proc_read(struct seq_file *m, void *v) {
	char *content="";
	for(int i=0; i<3; i++){
		if(pids[i] == -1){
			seq_printf(m, "#0%d: vacancy\n\n", i);
		}
		else{
			seq_printf(m, "#0%d:\n pid %d - [%d x %d]: (%d, %d) -> (%d, %d) @ (%d %d)", i, pids[i], mazes[i].w, mazes[i].h, mazes[i].sx, mazes[i].sy, mazes[i].ex, mazes[i].ey, players[i].x, players[i].y);

            for(int y = 0; y < mazes[i].h; y++) {
				seq_printf(m, "- %03d: ", y);
                for(int x = 0; x < mazes[i].w; x++) {
                    seq_printf(m, "%c", mazes[i].blk[y][x]);
                }
                seq_printf(m, "\n");
            }
            seq_printf(m, "\n");
		}
	}
    seq_printf(m, "%s", maze_content);
    return 0;
}

static int maze_proc_open(struct inode *inode, struct file *file) {
	return single_open(file, maze_proc_read, NULL);
}

static const struct proc_ops maze_proc_fops = {
	.proc_open = maze_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static char *maze_devnode(const struct device *dev, umode_t *mode) {
	if(mode == NULL) return NULL;
	*mode = 0666;
	return NULL;
}

static int __init maze_init(void)
{
	// create char dev
	if(alloc_chrdev_region(&devnum, 0, 1, "updev") < 0)
		return -1;
	if((clazz = class_create("upclass")) == NULL)
		goto release_region;
	clazz->devnode = maze_devnode;
	if(device_create(clazz, NULL, devnum, NULL, "maze") == NULL)
		goto release_class;
	cdev_init(&c_dev, &maze_dev_fops);
	if(cdev_add(&c_dev, devnum, 1) == -1)
		goto release_device;

	// create proc
	proc_create("maze", 0, NULL, &maze_proc_fops);

	printk(KERN_INFO "maze: initialized.\n");
	return 0;    // Non-zero return means that the module couldn't be loaded.

release_device:
	device_destroy(clazz, devnum);
release_class:
	class_destroy(clazz);
release_region:
	unregister_chrdev_region(devnum, 1);
	return -1;
}

static void __exit maze_cleanup(void)
{
	remove_proc_entry("maze", NULL);

	cdev_del(&c_dev);
	device_destroy(clazz, devnum);
	class_destroy(clazz);
	unregister_chrdev_region(devnum, 1);

	printk(KERN_INFO "maze: cleaned up.\n");
}

module_init(maze_init);
module_exit(maze_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chun-Ying Huang");
MODULE_DESCRIPTION("The unix programming course demo kernel module.");

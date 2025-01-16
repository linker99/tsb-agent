#include <linux/module.h>
#include <linux/fs.h>
#include <net/sock.h>

#define FS_TYPE_COMMON 	"sysfs"
#define FS_TYPE_NARI 	"debugfs"

static char* fs_type = FS_TYPE_COMMON;
static char* file_system_fs_type = FS_TYPE_COMMON;
static char* super_block_fs_type = FS_TYPE_NARI;

/*init filesystem value*/
static unsigned long filesystems = 0xffffffff;
static unsigned long filesystemslock = 0xffffffff;
static unsigned long superblocks = 0xffffffff;
static unsigned long sblock = 0xffffffff;
module_param(filesystems, ulong, 0644);
module_param(filesystemslock, ulong, 0644);
module_param(superblocks, ulong, 0644);
module_param(sblock, ulong, 0644);
MODULE_PARM_DESC(filesystems, "ulong file_systems address");
MODULE_PARM_DESC(filesystemslock, "ulong file_systems_lock address");
MODULE_PARM_DESC(superblocks, "ulong super_blocks address");
MODULE_PARM_DESC(sblock, "ulong sb_lock address");
/*end*/

static struct file_system_type *file_systems;
static rwlock_t *file_systems_lock;
static struct list_head *p_super_blocks;
static spinlock_t *p_sb_lock;

const struct super_operations *super_op = NULL;
struct super_block *item = NULL;

static void (*origin_kill_sb)(struct super_block *sb);
static void new_kill_sb(struct super_block *sb)
{
        printk("enter:[%s]\n", __func__);
        origin_kill_sb(sb);
}

static struct super_operations new_super_operations;
static struct inode *(*origin_alloc_inode)(struct super_block *sb);

static int kernel_args_addr_init(void)
{
        struct file_system_type **tmp;

        if (filesystems == 0xffffffff || filesystems == 0 ||
            filesystemslock == 0xffffffff || filesystemslock == 0 ||
            superblocks == 0xffffffff || superblocks == 0 ||
            sblock == 0xffffffff || sblock == 0) { 
                printk("Insmod [FILESYSTEM] Argument Error!\n");
                return -EINVAL;
        } else {
                printk("filesystems:[%0lx]!\n", filesystems);
                printk("filesystemslock:[%0lx]!\n", filesystemslock);
                printk("superblocks:[%0lx]!\n", superblocks);
                printk("sblock:[%0lx]!\n", sblock);
        }

        tmp = (struct file_system_type **)filesystems;
        file_systems = *tmp;
        file_systems_lock = (rwlock_t *)filesystemslock;
        p_super_blocks = (struct list_head *)superblocks;
        p_sb_lock = (spinlock_t *)sblock;

        return 0;
}

void check_special_kernel_version(void)
{
	// ÄÏÈð3310 || Ææ°²ÐÅ
	if ((strcmp(CONFIG_DEFAULT_HOSTNAME, "NARI")==0) || strcmp(CONFIG_DEFAULT_HOSTNAME, "NSG")==0) {
		fs_type = FS_TYPE_NARI;
	}

	printk("attack filesystem type:%s\n", fs_type);
}

static int dmeasure_test_modify_file_system(void)
{
        int ret = 0;
        struct file_system_type *fs = NULL;

        printk("start replace!\n");
        /* replace */
        write_lock(file_systems_lock);
        fs = file_systems;
        while (fs) {
                if (!strncmp(fs->name, file_system_fs_type, strlen(file_system_fs_type))) {
                        origin_kill_sb = fs->kill_sb;
                        fs->kill_sb = new_kill_sb;
                        printk("replace [%s] kill_sb\n", file_system_fs_type);
                        break;
                }
                fs = fs->next;
        }
        write_unlock(file_systems_lock);

        //printk("start recovery!\n");
        /* recovery */
        //msleep(10*1000);
        //write_lock(file_systems_lock);
        //fs = file_systems;
        //while (fs) {
        //        if (!strncmp(fs->name, FS_TYPE, strlen(FS_TYPE))) {
        //                fs->kill_sb = origin_kill_sb;
        //                printk("recovery [%s] kill_sb back\n", FS_TYPE);
        //                break;
        //        }
        //        fs = fs->next;
        //}
        //write_unlock(file_systems_lock);

        return ret;
}

static int dmeasure_test_modify_super_block(void)
{
        int ret = 0;
        struct super_block *sb = NULL;
        //struct super_block *item = NULL;
        //const struct super_operations *super_op = NULL;

        /* replace */
	spin_lock(p_sb_lock);
        list_for_each_entry(sb, p_super_blocks, s_list) {
                if (!strncmp(sb->s_type->name, super_block_fs_type, strlen(super_block_fs_type))) {
                        super_op = sb->s_op;
                        memcpy(&new_super_operations, sb->s_op, sizeof(struct super_operations));
                        origin_alloc_inode = sb->s_op->alloc_inode;
                        //new_super_operations.alloc_inode = new_alloc_inode;
                        sb->s_op = &new_super_operations;
                        item = sb;
                        printk("replace [%s] sb_op\n", super_block_fs_type);
                        break;
                }
        }
	spin_unlock(p_sb_lock);

        /* recovery */
        //msleep(20*1000);
        //spin_lock(p_sb_lock);
        //list_for_each_entry(sb, p_super_blocks, s_list) {
        //        if (!strncmp(sb->s_type->name, FS_TYPE, strlen(FS_TYPE)) && item == sb) {
        //                item->s_op = super_op;
        //                printk("recovery [%s] sb_op\n", FS_TYPE);
        //                break;
        //        }
        //}
        //spin_unlock(p_sb_lock);

        return ret;
}


static int test_filesystem_init(void)
{
        int ret = 0;

        ret = kernel_args_addr_init();
        if (ret)
                goto out;

	check_special_kernel_version();
        ret = dmeasure_test_modify_file_system();
        if (ret)
                printk("dmeasure file system error!\n");

        ret = dmeasure_test_modify_super_block();
        if (ret)
                printk("dmeasure super block error!\n");
out:
        return ret;
}

static void test_filesystem_exit(void)
{

	struct file_system_type *fs = NULL;

	struct super_block *sb = NULL;
	//struct super_block *item = NULL;


	printk("start recovery!\n");
	/* recovery */
	write_lock(file_systems_lock);
	fs = file_systems;
	while (fs) {
		if (!strncmp(fs->name, file_system_fs_type, strlen(file_system_fs_type))) {
			fs->kill_sb = origin_kill_sb;
			printk("recovery [%s] kill_sb back\n", file_system_fs_type);
			break;
		}
		fs = fs->next;
	}
	write_unlock(file_systems_lock);

	/* recovery */
	spin_lock(p_sb_lock);
	list_for_each_entry(sb, p_super_blocks, s_list) {
		if (!strncmp(sb->s_type->name, super_block_fs_type, strlen(super_block_fs_type)) && item == sb) {
			item->s_op = super_op;
			printk("recovery [%s] sb_op\n", super_block_fs_type);
			break;
		}
	}
	spin_unlock(p_sb_lock);

    return;
}

module_init(test_filesystem_init);
module_exit(test_filesystem_exit);

MODULE_AUTHOR("HTTC");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("HTTCSEC FILESYSTEM TEST");


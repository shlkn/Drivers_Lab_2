// SPDX-License-Identifier: GPL-2.0

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>


static int major;
static char buffer[200];

static ssize_t lab2_read(struct file *file, char __user *buf,
			 size_t count, loff_t *pos)
{
	ssize_t cnt_byte = 0;
	int i = 0;
	printk("in read function");
	while(buffer[i] != '\0')
	{
		printk("%c", buffer[i]);
		i++;
	}
	printk("%ld\n", count);
	if(copy_to_user(buf, buffer, count))
	{
		printk("copy_to_user error");
		return -EFAULT;
	}
	return cnt_byte;
}

static ssize_t lab2_write(struct file *file, const char __user *buf,
			 size_t count, loff_t *pos)
{
	printk("in write function");
	if (count > sizeof(buffer)-1)
		return -EINVAL;
	if (copy_from_user(buffer, buf, count))
	{
		printk("copy_from_user error");
		return -EFAULT;
	}
	printk("%s", buffer);
	buffer[count] = '\0';
	return count;
}

int lab2_open(struct inode *in, struct file *fl)
{
	printk("file opened\n");
	return 0;
}

int lab2_release(struct inode *in, struct file *fl)
{
	printk("file closed\n");
	return 0;
}

static struct file_operations fops = {
	.read	= lab2_read,
	.write	= lab2_write,
	.open = lab2_open,
	.release = lab2_release,
};


static int __init modinit(void)
{
	/* 0 is ? */
	major = register_chrdev(0, "Lab2", &fops);
	if (major < 0) {
		printk("failed to register_chrdev failed with %d\n", major);
		/* should follow 0/-E convention ... */
		return major;
	}
	printk("/dev/register_chrdev assigned major %d\n", major);
	printk("create node with mknod /dev/register_chrdev c %d 0\n", major);
	return 0;
}

static void __exit modexit(void)
{
	unregister_chrdev(major, "register_chrdev");
	printk("bye");
}



module_init(modinit);
module_exit(modexit);
MODULE_AUTHOR("iliyash");
MODULE_DESCRIPTION("Drivers design lab2");
MODULE_LICENSE("GPL");

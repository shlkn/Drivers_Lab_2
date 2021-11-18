// SPDX-License-Identifier: GPL-2.0

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/wait.h>
#define BUFFER_SIZE 10

DECLARE_WAIT_QUEUE_HEAD(module_queue);

struct cycle_buffer {
	char buffer[BUFFER_SIZE];
	int buf_size;
	int read_ptr;
	int write_ptr;
	int bytes_avalible;
};

void  write_in_cycle_buffer(struct cycle_buffer *buf, int count, char *data);
char *read_from_cycle_buffer(struct cycle_buffer *buf, int count);
int readble_count_of_bytes_in_cycle_buffer(struct cycle_buffer buf);

struct cycle_buffer test_buffer;
static int major;


static ssize_t lab2_read(struct file *file, char __user *buf,
			 size_t count, loff_t *pos)
{
	ssize_t cnt = 0;
	int read_bytes_avail = 0;
	char *read_data;
	read_data = kzalloc(count, GFP_KERNEL);
	printk("in read function");
	read_bytes_avail = readble_count_of_bytes_in_cycle_buffer(test_buffer);
	if (read_bytes_avail == 0)
		return 0;
	if(read_bytes_avail >= count)
		read_data = read_from_cycle_buffer(&test_buffer, count);
	else {
		int already_readen_count = -1;
		while(already_readen_count != count) {
			char *data;
			int i;
			if (already_readen_count - count < readble_count_of_bytes_in_cycle_buffer(test_buffer)) {
				data = read_from_cycle_buffer(&test_buffer, already_readen_count - count);
			}
			data = read_from_cycle_buffer(&test_buffer, read_bytes_avail);
			for(i = 0;i < already_readen_count + read_bytes_avail; i++) {
				read_data[already_readen_count++] = data[i];
			}
			already_readen_count += read_bytes_avail;
			count -= read_bytes_avail;
			read_bytes_avail = readble_count_of_bytes_in_cycle_buffer(test_buffer);
			kfree(data);
			wake_up(&module_queue);
			wait_event_interruptible_exclusive(module_queue, readble_count_of_bytes_in_cycle_buffer(test_buffer) > 0);
		}
	}

	if (copy_to_user(buf, read_data, count)) {
		printk("copy_to_user error");
		return -EFAULT;
	}
	kfree(read_data);
	return cnt;
}

static ssize_t lab2_write(struct file *file, const char __user *buf,
			 size_t count, loff_t *pos)
{
	char *data;
	int i;

	printk("in write function");
	data = kzalloc(count, GFP_KERNEL);
	if (copy_from_user(data, buf, count)) {
		printk("copy_from_user error");
		return -EFAULT;
	}


	if(test_buffer.bytes_avalible > count)
		write_in_cycle_buffer(&test_buffer, count, data);
	else {
		int already_writen_count = 0;
		while(count != already_writen_count) {
			if (count - already_writen_count < test_buffer.bytes_avalible){
				write_in_cycle_buffer(&test_buffer, count - already_writen_count, data + already_writen_count);
			}
			write_in_cycle_buffer(&test_buffer, test_buffer.bytes_avalible, data + already_writen_count);
			already_writen_count += test_buffer.bytes_avalible;
			wake_up(&module_queue);
			wait_event_interruptible_exclusive(module_queue, test_buffer.bytes_avalible > 0);
		}
	}


	for(i = 0; i < test_buffer.buf_size; i++)
		printk("%X", test_buffer.buffer[i]);
	//buffer[count] = '\0';
	kfree(data);
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
	test_buffer.buf_size = BUFFER_SIZE;
	test_buffer.bytes_avalible = test_buffer.buf_size;
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

int readble_count_of_bytes_in_cycle_buffer(struct cycle_buffer buf)
{
	int bytes_count;

	if(buf.bytes_avalible == buf.buf_size)
		return 0;
	bytes_count = buf.buf_size - buf.bytes_avalible; 
	return bytes_count;
}

char *read_from_cycle_buffer(struct cycle_buffer *buf, int count)
{
	int read_cnt;
	char *data;

	data = kzalloc(count, GFP_KERNEL);
	if (data == NULL)
		return NULL;
	for (read_cnt = 0; read_cnt < count; read_cnt++) {
		if (buf->read_ptr == buf->buf_size)
			buf->read_ptr = 0;
		data[read_cnt] = buf->buffer[buf->read_ptr];
		buf->read_ptr++;
		buf->bytes_avalible++;
	}
	return data;
}

void  write_in_cycle_buffer(struct cycle_buffer *buf, int count, char *data)
{
	int write_cnt;

	for (write_cnt = 0; write_cnt < count; write_cnt++) {
		if (buf->write_ptr == buf->buf_size)
			buf->write_ptr = 0;
		buf->buffer[buf->write_ptr] = data[write_cnt];
		buf->write_ptr++;
		buf->bytes_avalible--;
	}
}



module_init(modinit);
module_exit(modexit);
MODULE_AUTHOR("iliyash");
MODULE_DESCRIPTION("Drivers design lab2");
MODULE_LICENSE("GPL");

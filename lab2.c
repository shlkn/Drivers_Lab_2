// SPDX-License-Identifier: GPL-2.0

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/wait.h>
#define BUFFER_SIZE 5

DECLARE_WAIT_QUEUE_HEAD(module_queue);

struct cycle_buffer {
	char buffer[BUFFER_SIZE];
	int buf_size;
	int read_ptr;
	int write_ptr;
	ssize_t bytes_avalible;
}; 

int write_in_cycle_buffer(struct cycle_buffer *buf, int count, char *data);
void read_from_cycle_buffer(struct cycle_buffer *buf, int count, char *read_data, ssize_t offset);
int readble_count_of_bytes_in_cycle_buffer(struct cycle_buffer buf);

struct cycle_buffer test_buffer;
static int major;


static ssize_t lab2_read(struct file *file, char __user *buf,
			 size_t count, loff_t *pos)
{
	ssize_t cnt = 0;
	int read_bytes_avail = 0;
	char *read_data;
	read_data = kzalloc(count + 1, GFP_KERNEL);
	printk("in read function");
	read_bytes_avail = readble_count_of_bytes_in_cycle_buffer(test_buffer);
	if (read_bytes_avail == 0)
		return 0;
	if(read_bytes_avail >= count)//
		read_from_cycle_buffer(&test_buffer, count, read_data, 0);
	else {
		int already_read_count = 0;
		while(true) {
			char *data;
			int i, data_ptr;
			read_bytes_avail = readble_count_of_bytes_in_cycle_buffer(test_buffer);
			if (count - already_read_count <= read_bytes_avail) {
				read_from_cycle_buffer(&test_buffer, count - already_read_count, read_data, already_read_count);
				wake_up(&module_queue);
				data_ptr = -1;
				cnt = i;
				break;
			}
			else {
				read_from_cycle_buffer(&test_buffer, read_bytes_avail, read_data, already_read_count);
				already_read_count += read_bytes_avail;
			}
			kfree(data);
			wake_up(&module_queue);
			if(wait_event_interruptible_exclusive(module_queue, (readble_count_of_bytes_in_cycle_buffer(test_buffer) > 0)) == -ERESTARTSYS)
				break;
		}
	}

	if (copy_to_user(buf, read_data, count)) {
		printk("copy_to_user error");
		return -EFAULT;
	}
	kfree(read_data);
	return count;
}

static ssize_t lab2_write(struct file *file, const char __user *buf,
			 size_t count, loff_t *pos)
{
	char *data;

	data = kzalloc(count, GFP_KERNEL);
	if (copy_from_user(data, buf, count)) {
		printk("copy_from_user error");
		return -EFAULT;
	}
	if(test_buffer.bytes_avalible >= count)
		write_in_cycle_buffer(&test_buffer, count, data);
	else {
		int already_written_count = 0;
		while(true) {
			if (count - already_written_count <= test_buffer.bytes_avalible){
				write_in_cycle_buffer(&test_buffer, count - already_written_count, (data + already_written_count));
				wake_up(&module_queue);
				break;
			}
			else {
				printk("already_written_count before - %d", already_written_count);
				already_written_count += write_in_cycle_buffer(&test_buffer, test_buffer.bytes_avalible, (data + already_written_count));
				printk("already_written_count after - %d", already_written_count);
			}
			wake_up(&module_queue);
			if(wait_event_interruptible_exclusive(module_queue, (test_buffer.bytes_avalible > 0)) == -ERESTARTSYS)
			{
				break;
			}
		}
	}
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
	//init
	test_buffer.buf_size = BUFFER_SIZE;
	test_buffer.bytes_avalible = test_buffer.buf_size;
	test_buffer.write_ptr = 0;
	test_buffer.read_ptr = 0;

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

void read_from_cycle_buffer(struct cycle_buffer *buf, int count, char *read_data, ssize_t offset)
{
	int read_cnt;

	for (read_cnt = 0; read_cnt < count; read_cnt++) {
		if (buf->read_ptr == buf->buf_size - 1)
		{
			read_data[offset] = buf->buffer[buf->read_ptr];
			buf->read_ptr = 0;
			offset++;
		}
		else{
			read_data[offset] = buf->buffer[buf->read_ptr];
			buf->read_ptr++;
			offset++;
		}
		buf->bytes_avalible++;
	}
}

int write_in_cycle_buffer(struct cycle_buffer *buf, int count, char *data)
{
	int write_cnt;
	for (write_cnt = 0; write_cnt < count; write_cnt++) {
		if (buf->write_ptr == buf->buf_size - 1)
		{
			buf->buffer[buf->write_ptr] = data[write_cnt];
			buf->write_ptr = 0;
		}
		else {
			buf->buffer[buf->write_ptr] = data[write_cnt];
			buf->write_ptr++;
		}
		buf->bytes_avalible--;
	}
	return write_cnt;
}



module_init(modinit);
module_exit(modexit);
MODULE_AUTHOR("iliyash");
MODULE_DESCRIPTION("Drivers design lab2");
MODULE_LICENSE("GPL");

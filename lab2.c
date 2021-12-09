// SPDX-License-Identifier: GPL-2.0

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <uapi/asm-generic/ioctl.h>
#include "lab2.h"

#define BUFFER_SIZE 5

static int major;

struct cycle_buffer **sessions;
int count_of_sessions;

struct cycle_buffer {
	kgid_t user_group;
	int writer_pid; // -1 - n/a
	int reader_pid; // -1 - n/a
	char *buffer;
	int buf_size;
	int read_ptr;
	int write_ptr;
	struct mutex gate;
	wait_queue_head_t queue;
	ssize_t bytes_avalible;
};

static int gid_cmp(const void *_a, const void *_b)
{
	kgid_t a = *(kgid_t *)_a;
	kgid_t b = *(kgid_t *)_b;

	return gid_gt(a, b) - gid_lt(a, b);
}

int find_sesion(kgid_t group, struct file *fl)
{
	int i;

	for (i = 0; i < count_of_sessions; i++) {
		int res;

		pr_alert("cyc");
		res = gid_cmp((void *) &sessions[i]->user_group, (void *) &group);
		pr_alert("cyc");
		if (fl->f_mode & FMODE_READ) {
			if (sessions[i]->reader_pid == -1 && res == 0) {
				sessions[i]->reader_pid = current->pid;
				return i;
			}
		} else if (fl->f_mode & FMODE_WRITE) {
			if (sessions[i]->writer_pid == -1 && res == 0) {
				sessions[i]->writer_pid = current->pid;
				return i;
			}
		} else {
			return -2;
		}
	}
	return -1;
}

void add_new_session(struct file *fl, int pid)
{
	struct cycle_buffer **temp;
	char *tempbuff;

	count_of_sessions++;
	temp = krealloc(sessions, count_of_sessions * sizeof(struct cycle_buffer *), GFP_KERNEL);
	if (temp == NULL)
		pr_alert("Can`t allocate memory");
	pr_alert("new ses 1");

	temp[count_of_sessions - 1] = krealloc((sessions + count_of_sessions - 1), sizeof(struct cycle_buffer), GFP_KERNEL);
	if (temp[count_of_sessions - 1] == NULL)
		pr_alert("Can`t allocate memory");
	temp[count_of_sessions - 1]->buffer = NULL;
	pr_alert("new ses 2");


	tempbuff = krealloc(temp[count_of_sessions - 1]->buffer, BUFFER_SIZE, GFP_KERNEL);
	if (tempbuff == NULL)
		pr_alert("Can`t allocate memory");
	temp[count_of_sessions - 1]->buffer = tempbuff;
	sessions = temp;
	pr_alert("new ses 3");



	//init mem
	sessions[count_of_sessions - 1]->user_group = fl->f_cred->group_info->gid[0];
	if (fl->f_mode & FMODE_WRITE) {
		sessions[count_of_sessions - 1]->writer_pid = pid;
		sessions[count_of_sessions - 1]->reader_pid = -1;
	}
	if (fl->f_mode & FMODE_READ) {
		sessions[count_of_sessions - 1]->reader_pid = pid;
		sessions[count_of_sessions - 1]->writer_pid = -1;
	}
	sessions[count_of_sessions - 1]->buf_size = BUFFER_SIZE;
	sessions[count_of_sessions - 1]->read_ptr = 0;
	sessions[count_of_sessions - 1]->write_ptr = 0;
	sessions[count_of_sessions - 1]->bytes_avalible = sessions[count_of_sessions - 1]->buf_size;
	mutex_init(&sessions[count_of_sessions - 1]->gate);
	init_waitqueue_head(&sessions[count_of_sessions - 1]->queue);
}

int readble_count_of_bytes_in_cycle_buffer(struct cycle_buffer *buf)
{
	int bytes_count;

	if (buf->bytes_avalible == buf->buf_size)
		return 0;
	bytes_count = buf->buf_size - buf->bytes_avalible;
	return bytes_count;
}

void read_from_cycle_buffer(struct cycle_buffer *buf, int count, char *read_data, ssize_t offset)
{
	int read_cnt;

	for (read_cnt = 0; read_cnt < count; read_cnt++) {
		if (buf->read_ptr == buf->buf_size - 1) {
			read_data[offset] = buf->buffer[buf->read_ptr];
			buf->read_ptr = 0;
			offset++;
		} else {
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
		if (buf->write_ptr == buf->buf_size - 1) {
			buf->buffer[buf->write_ptr] = data[write_cnt];
			buf->write_ptr = 0;
		} else {
			buf->buffer[buf->write_ptr] = data[write_cnt];
			buf->write_ptr++;
		}
		buf->bytes_avalible--;
	}
	return write_cnt;
}

static ssize_t lab2_read(struct file *file, char __user *buf,
			 size_t count, loff_t *pos)
{
	pr_alert("in read func\n");
	int read_bytes_avail = 0, iter = 0, i, already_read_count = 0;
	struct cycle_buffer *crt_session = NULL;
	char *read_data;

	read_data = kzalloc(count + 1, GFP_KERNEL);
	pr_alert("memory alloc\n");
	for (iter = 0; iter < count_of_sessions; iter++) { //finds sesion
		pr_alert("iter - %d\n", iter);
		pr_alert("res - %d\n", (sessions[iter]->reader_pid == current->pid));
		if (sessions[iter]->reader_pid == current->pid) {
			crt_session = sessions[iter];
			break;
		}
	}
	pr_alert("iter finish - %d\n", iter);
	pr_alert("current->pid - %d\n", current->pid);
	if (mutex_lock_interruptible(&crt_session->gate)) {
		pr_alert("mutex interrupt");
		return -1;
	}

	for (i = 0; i < count_of_sessions; i++) {
		printk("i - %d\n", i);
		printk("sessions[i]->writer_pid - %d\n", crt_session->writer_pid);
		printk("sessions[i]->reader_pid - %d\n", crt_session->reader_pid);
		printk("sessions[i]->user_group - %d\n", crt_session->user_group);
		printk("sessions[i]->bytes_avalible - %d\n", crt_session->bytes_avalible);
		printk("sessions[i]->buf_size - %d\n", crt_session->buf_size);
		pr_alert("file opened\n");
	}


	while (true) {
		pr_alert("cycle");
		read_bytes_avail = readble_count_of_bytes_in_cycle_buffer(crt_session);
		if (count - already_read_count > read_bytes_avail) {
			read_from_cycle_buffer(crt_session, read_bytes_avail, read_data, already_read_count);
			already_read_count += read_bytes_avail;
		} else {
			read_from_cycle_buffer(crt_session, count - already_read_count, read_data, already_read_count);
			already_read_count += count - already_read_count;
			mutex_unlock(&crt_session->gate);
			wake_up(&crt_session->queue);
			break;
		}

		mutex_unlock(&crt_session->gate);
		wake_up(&crt_session->queue);
		if (wait_event_interruptible(crt_session->queue, (readble_count_of_bytes_in_cycle_buffer(crt_session) > 0)) == -ERESTARTSYS)
			break;
	}

	if (copy_to_user(buf, read_data, count)) {
		pr_alert("copy_to_user error");
		return -EFAULT;
	}
	kfree(read_data);
	return already_read_count;
}

static ssize_t lab2_write(struct file *file, const char __user *buf,
			 size_t count, loff_t *pos)
{
	int i;
	struct cycle_buffer *crt_session = NULL;

	pr_alert("in write func\n");
	char *data;
	int iter = 0, already_written_count = 0;

	data = kzalloc(count, GFP_KERNEL);
	if (copy_from_user(data, buf, count)) {
		pr_alert("copy_from_user error");
		return -EFAULT;
	}

	for (iter = 0; iter < count_of_sessions; iter++) { //finds sesion
		pr_alert("iter - %d\n", iter);
		pr_alert("res - %d\n", (sessions[iter]->writer_pid == current->pid));
		if (sessions[iter]->writer_pid == current->pid) {
			crt_session = sessions[iter];
			break;
		}
	}


	if (mutex_lock_interruptible(&crt_session->gate)) {
		pr_alert("mutex interrupt");
		return -1;
	}
	pr_alert("iter finish - %d\n", iter);
	pr_alert("current->pid - %d\n", current->pid);

	for (i = 0; i < count_of_sessions; i++) {
		printk("i - %d\n", i);
		printk("sessions[i]->writer_pid - %d\n", crt_session->writer_pid);
		printk("sessions[i]->reader_pid - %d\n", crt_session->reader_pid);
		printk("sessions[i]->user_group - %d\n", crt_session->user_group);
		printk("sessions[i]->bytes_avalible - %d\n", crt_session->bytes_avalible);
		printk("sessions[i]->buf_size - %d\n", crt_session->buf_size);
		pr_alert("file opened\n");
	}


	while (true) {
		if (count - already_written_count > crt_session->bytes_avalible)
			already_written_count += write_in_cycle_buffer(crt_session, crt_session->bytes_avalible, (data + already_written_count));
		else {
			already_written_count += write_in_cycle_buffer(crt_session, count - already_written_count, (data + already_written_count));
			mutex_unlock(&crt_session->gate);
			wake_up(&crt_session->queue);
			break;
		}

		mutex_unlock(&crt_session->gate);
		wake_up(&crt_session->queue);
		if (wait_event_interruptible(crt_session->queue, (crt_session->bytes_avalible > 0)) == -ERESTARTSYS)
			break;
	}

	kfree(data);
	return already_written_count;
}

int lab2_open(struct inode *in, struct file *fl)
{
	int sesionID, i, j;

	if (fl->f_cred->group_info->ngroups != 1)
		pr_alert("too many groups. first will be used\n");

	pr_alert("count of sessions in open %d - ", count_of_sessions);

	pr_alert("tyt");
	sesionID = find_sesion(fl->f_cred->group_info->gid[0], fl);
	pr_alert("sesionID - %d", sesionID);
	if (sesionID == -1)
		add_new_session(fl, current->pid);

	for (i = 0; i < count_of_sessions; i++) {
		printk("i - %d\n", i);
		printk("sessions[i]->writer_pid - %d\n", sessions[i]->writer_pid);
		printk("sessions[i]->reader_pid - %d\n", sessions[i]->reader_pid);
		printk("sessions[i]->user_group - %d\n", sessions[i]->user_group);
		printk("sessions[i]->bytes_avalible - %d\n", sessions[i]->bytes_avalible);
		printk("sessions[i]->buf_size - %d\n", sessions[i]->buf_size);
		for(j = 0; j < sessions[i]->buf_size; j++)
			printk("sessions[i]->buf_size - %c\n", sessions[i]->buffer[j]);
		pr_alert("file opened\n");
	}
	return 0;
}

int lab2_release(struct inode *in, struct file *fl)
{
	int i;
	struct cycle_buffer **temp;

	for (i = 0; i < count_of_sessions; i++) {

		if (sessions[i]->writer_pid == current->pid) {
			sessions[i]->writer_pid = -1; // return to n/a
			pr_alert("process %d closed file", current->pid);
		}
		if (sessions[i]->reader_pid == current->pid) {
			sessions[i]->reader_pid = -1; // return to n/a
			pr_alert("process %d closed file", current->pid);
		}
		if (sessions[i]->writer_pid == -1 && sessions[i]->reader_pid == -1) { //delete mem
			int iter, new_iter = 0;

			if (count_of_sessions == 1) {
				kfree(sessions[i]->buffer);
				kfree(sessions[i]);
				kfree(sessions);
				sessions = NULL;
				count_of_sessions--;
				return 0;
			}
			pr_alert(" count_of_sessions - %d", count_of_sessions);
			temp = kmalloc((count_of_sessions - 1) * sizeof(struct cycle_buffer *), GFP_KERNEL);
			if (temp == NULL) {
				pr_alert("Bad mem alloc\n");
				return 0;
			}
			for (iter = 0; iter < count_of_sessions; iter++) {
				pr_alert(" iter - %d", iter);
				pr_alert(" i - %d", i);
				if (i == iter) { // delete sesion
					pr_alert("delete session\n");
					kfree(sessions[iter]->buffer);
					kfree(sessions[iter]);
				}
				else {
					pr_alert("%d = %d\n", new_iter, iter);
					temp[new_iter] = sessions[iter]; // copy to new array;
					new_iter++;
				}
			}
			count_of_sessions--;
			kfree(sessions);
			sessions = temp;
			pr_alert("count of sessions reduced. New sessions count - %d\n", count_of_sessions);
		}
	}
	pr_alert("sessions count - %d\n", count_of_sessions);
	for (i = 0; i < count_of_sessions; i++) {
		printk("i - %d\n", i);
		printk("sessions[i]->writer_pid - %d\n", sessions[i]->writer_pid);
		printk("sessions[i]->reader_pid - %d\n", sessions[i]->reader_pid);
		printk("sessions[i]->user_group - %d\n", sessions[i]->user_group);
		printk("sessions[i]->bytes_avalible - %d\n", sessions[i]->bytes_avalible);
		printk("sessions[i]->buf_size - %d\n", sessions[i]->buf_size);
	}
	return 0;
}

static long lab2_ioctl_handler(struct file *fl, unsigned int cmd, unsigned long arg)
{
	char *temp;

	if (arg < 1) {
		pr_alert("Received wrong argument! No futher actions");
		return -EINVAL;
	}

	switch (cmd) {
		case CH_BUF_SIZE: {
			int i = 0;

			for (i = 0; i < count_of_sessions; i++) {
				if (sessions[i]->writer_pid == current->pid || sessions[i]->reader_pid == current->pid) {
					if (mutex_lock_interruptible(&sessions[i]->gate)) {
						pr_alert("mutex interrupt");
						return -1;
					}
					if (sessions[i]->bytes_avalible != sessions[i]->buf_size) {
						pr_alert("Buffer contains data. No futher actions");
						mutex_unlock(&sessions[i]->gate);
						return -EINVAL;
					}
					temp = krealloc(sessions[i]->buffer, arg, GFP_KERNEL);
					if (temp == NULL) {
						pr_alert("Error in memory allocate.");
						mutex_unlock(&sessions[i]->gate);
						return -EINVAL;
					}
					sessions[i]->buffer = temp;
					sessions[i]->buf_size = arg;
					sessions[i]->bytes_avalible = arg;
					mutex_unlock(&sessions[i]->gate);
				}
			}
			break;
		}
		default: {
			pr_alert("Received wrong cmd! No futher actions");
			return -EINVAL;
		}
	}
	return 0;
}

static const struct file_operations fops = {
	.read	= lab2_read,
	.write	= lab2_write,
	.open = lab2_open,
	.release = lab2_release,
	.unlocked_ioctl = lab2_ioctl_handler,
};

static int __init modinit(void)
{
	count_of_sessions = 0;
	sessions = NULL;

	major = register_chrdev(0, "Lab2", &fops);
	if (major < 0) {
		pr_alert("failed to register_chrdev failed with %d\n", major);
		/* should follow 0/-E convention ... */
		return major;
	}
	pr_alert("/dev/register_chrdev assigned major %d\n", major);
	pr_alert("create node with mknod /dev/register_chrdev c %d 0\n", major);
	return 0;
}

static void __exit modexit(void)
{
	int i;

	for (i = 0; i < count_of_sessions; i++) {
		mutex_unlock(&sessions[i]->gate);
		wake_up(&sessions[i]->queue);
		kfree(sessions[i]->buffer);
		kfree(sessions[i]);
	}
	kfree(sessions);
	unregister_chrdev(major, "register_chrdev");
	pr_alert("bye");
}

module_init(modinit);
module_exit(modexit);
MODULE_AUTHOR("iliyash");
MODULE_DESCRIPTION("Drivers design lab2");
MODULE_LICENSE("GPL");

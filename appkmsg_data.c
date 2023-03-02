/* appkmsg_data.c -- This file is part of the appkmsg project.
 *
 * Copyright (c) 2023, Liao Jian <leaoxc@gmail.com> All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of leaoxc nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <linux/fs.h>
#include <linux/aio.h>
#include <linux/uio.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/rculist.h>
#include <linux/radix-tree.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/zsmalloc.h>
#include <linux/poll.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/tty.h>
#include <linux/delay.h>
#include <linux/dcache.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/semaphore.h>
#include <linux/kobject.h>
#include "appkmsg_config.h"
#include "appkmsg_crypto.h"
#include "appkmsg_cdev.h"
#include "appkmsg_data.h"
#include "appkmsg_params.h"
#include "appkmsg_lib.h"

enum data_flags {
	DATA_INITIALIZED = FLAG_SHIFT,
	DATA_UNINITIALIZE,
};

enum segment_flags {	  
	SEGMENT_COMPRESSED = FLAG_SHIFT,
	SEGMENT_PROCESSED,
};

enum record_flags {	  
	REC_FLUSHED,
	REC_SYNCED,
	REC_INVALID,
};

enum record_io_type {
	REC_RW_ITER,
	REC_RW_USER,
	REC_RW_KBUF,
};

enum record_link_type {
	REC_ADD_LINK,
	REC_CHG_LINK,
};

struct record_ops {
	ssize_t (*read)(struct record *r, void *buf, size_t count, loff_t pos,
			ssize_t (*read_func)(void *, const void *, size_t, loff_t));
	ssize_t (*write)(struct record *r, const void *buf, size_t count,
			ssize_t (*write_func)(void *, const void *, size_t, loff_t));
	int (*insert)(struct record *r, unsigned long index, void **ret);
	void *(*fetch)(struct record *r, unsigned long index);
	int (*flush)(struct record *r, struct segment *smt);
	int (*sync)(struct record *r);
	void (*free)(struct appkmsg_data *ad, struct record *r);
};

struct metadata {
	const char *name;
	const char *exepath;
	struct pid *pid;
	struct proc_dir_entry *pde;
	void *cache;
	size_t cache_used;
	size_t size;
	size_t compressed_size;
	unsigned long flags;
	time64_t timestamp;
};

struct segment {
	unsigned long handle;
	unsigned long flags;
};

struct record {
	struct rcu_head rcu;
	struct metadata meta;
	union {
		struct segment *table;
		struct radix_tree_root *root;
	};
	spinlock_t lock;
	struct kref kref;
	struct list_head entry;
	struct record_ops *ops;
};

struct data_ops {
	int (*init)(struct appkmsg_data **ad);
	struct record *(*create)(struct appkmsg_data *ad);
	struct record *(*search)(struct appkmsg_data *ad, pid_t pid);
	int (*remove)(struct appkmsg_data *ad, pid_t pid);
	int (*link)(struct appkmsg_data *ad, struct record *r, int action);
	void (*free)(struct appkmsg_data *ad);
	void (*exit)(struct appkmsg_data **ad);
};

struct appkmsg_data {
	unsigned long flags;
	spinlock_t lock;
	long srcu_index;
	struct srcu_struct srcu;
	struct list_head list;
	struct radix_tree_root root;
	struct zs_pool *pool;
	struct proc_dir_entry *proc_root;
	struct proc_dir_entry *link;
	const struct data_ops *ops;
};

static struct appkmsg_data *data;

static inline void *seq_get_private(struct seq_file *seq)
{
#ifdef HAVE_SEQ_FILE_FILE
	return PDE_DATA(file_inode(seq->file));
#else
	return seq->private;
#endif /* HAVE_SEQ_FILE_FILE */
}

static void *data_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct appkmsg_data *data = seq_get_private(seq);
	
	data->srcu_index = srcu_read_lock(&data->srcu);
	return *pos ? seq_list_start(&data->list, *pos) : SEQ_START_TOKEN;
}

static void data_seq_stop(struct seq_file *seq, void *v)
{
	struct appkmsg_data *data = seq_get_private(seq);
	
	srcu_read_unlock(&data->srcu, data->srcu_index);
}

static void *data_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct appkmsg_data *data = seq_get_private(seq);

	if (v == SEQ_START_TOKEN) {
		++*pos;
		if (!list_empty(&data->list))
			return data->list.next;
		return NULL;
	}
	
	return seq_list_next(v, &data->list, pos);
}

static char *record_bytes2xb(size_t bytes, char *buf, size_t size)
{
#define KB_SHIFT 10
#define MB_SHIFT 20
#define GB_SHIFT 30
#define R 	9765625UL
#define POW 100000000UL

    unsigned long var1, var2;

    if (bytes < BIT(KB_SHIFT)) {
        var1 = bytes;
        scnprintf(buf, size, "%lu(B)", var1);
    } else if (bytes >= BIT(KB_SHIFT) && bytes < BIT(MB_SHIFT)) {
        var1 = bytes >> KB_SHIFT;
        var2 = (bytes & (BIT(KB_SHIFT) - 1)) * R / POW;
        scnprintf(buf, size, "%lu.%lu(KB)", var1, var2);
    } else if (bytes >= BIT(MB_SHIFT) && bytes < BIT(GB_SHIFT)) {
        var1 = bytes >> MB_SHIFT;
        var2 = ((bytes >> KB_SHIFT) & (BIT(KB_SHIFT) - 1)) * R / POW;
        scnprintf(buf, size, "%lu.%lu(MB)", var1, var2);
    } else {
		var1 = bytes >> GB_SHIFT;
        var2 = ((bytes >> MB_SHIFT) & (BIT(KB_SHIFT) - 1)) * R / POW;
		scnprintf(buf, size, "%lu.%lu(GB)", var1, var2);
	}
	
    return buf;
}

static int data_seq_show(struct seq_file *seq, void *v)
{
	struct tm tm;
	char buf[64];

	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "%-6s ", "[Pid]");
		seq_printf(seq, "%-22s ", "[Exec path]");
		seq_printf(seq, "%-30s ", "[Compressed size/Raw size]");
		seq_printf(seq, "%s\n", "[Timestamp]");
	} else {
		struct record __rcu *r = list_entry_rcu(v, struct record, entry);
		appkmsg_time_to_tm(r->meta.timestamp, 60 * 60 * 8, &tm);

		seq_printf(seq, "%-6ld ", (long)pid_nr(r->meta.pid));
		seq_printf(seq, "%-24s ", r->meta.exepath);
		seq_printf(seq, "%10s/",
				record_bytes2xb(r->meta.compressed_size, buf, sizeof(buf)));
		seq_printf(seq, "%-15s ",
				record_bytes2xb(r->meta.size, buf, sizeof(buf)));
		seq_printf(seq, "%02d:%02d:%02d ",
				tm.tm_hour, tm.tm_min, tm.tm_sec);
		seq_printf(seq, "%02d/%02d/%ld\n",
				1 + tm.tm_mon, tm.tm_mday, tm.tm_year - 100);
	}
	
	return 0;
}

static const struct seq_operations proc_seq_ops = {
	.start  = data_seq_start,
	.stop   = data_seq_stop,
	.next   = data_seq_next,
	.show   = data_seq_show,
};

static int proc_seq_open(struct inode *inode, struct file *filp)
{
    int ret;
    struct seq_file *seq;

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;
	
    ret = seq_open(filp, &proc_seq_ops);
    if (ret < 0) {
		module_put(THIS_MODULE);
        return ret;
    }
	
	seq = filp->private_data;
	seq->private = PDE_DATA(inode);
	return 0;
}

static int proc_seq_close(struct inode *inode, struct file *filp)
{
	int ret = seq_release(inode, filp);
	module_put(THIS_MODULE);
	return ret;
}

#ifdef HAVE_PROC_OPS
static const struct proc_ops proc_seq_fops = {
	.proc_open      = proc_seq_open,
	.proc_read      = seq_read,
	.proc_lseek     = seq_lseek,
	.proc_release   = proc_seq_close,
};
#else 
static const struct file_operations proc_seq_fops = {
	.owner          = THIS_MODULE,
	.open           = proc_seq_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = proc_seq_close,
};
#endif /* HAVE_PROC_SEQ */

static int proc_record_open(struct inode *inode, struct file *filp)
{
	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	return 0;
}

static ssize_t proc_record_read_iter(struct kiocb *kiocb, 
				struct iov_iter *iter)
{
	void *page;
	ssize_t ret;
	size_t nread = 0, ndone = 0, count = iov_iter_count(iter);
	struct record __rcu *r = PDE_DATA(file_inode(kiocb->ki_filp));

	page = (void *)__get_free_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	count = min_t(size_t, r->meta.size - kiocb->ki_pos, count);
	do {
		nread = min_t(size_t, count, PAGE_SIZE);		
		
		ret = record_read_to_kbuf(r, page, nread, kiocb->ki_pos);
		pr_debug("%s %d ret=%ld, nread=%ld, count=%ld, pos=%ld\n",
			__FUNCTION__, __LINE__, ret, nread, count, (long)kiocb->ki_pos);
		if (ret <= 0)
			goto out;
		
		ret = copy_to_iter(page, nread, iter);
		pr_debug("%s %d copy_to_iter ret=%ld, nread=%ld, count=%ld, pos=%ld\n",
			__FUNCTION__, __LINE__, ret, nread, count, (long)kiocb->ki_pos);
		if (ret != nread) {
			ret = -EFAULT;
			goto out;
		}

		count -= nread;
		ndone += nread;
		kiocb->ki_pos += nread;
	} while (count);
	ret = ndone;
out:
	free_page((unsigned long)page);
	return ret;
}

static ssize_t proc_record_read(struct file *filp, 
				char __user *buf, size_t count, loff_t *ppos)
{
	struct iovec iov = { .iov_base = buf, .iov_len = count };
	struct kiocb kiocb;
	struct iov_iter iter;
	ssize_t ret;

	init_sync_kiocb(&kiocb, filp);
	iov_iter_init(&iter, READ, &iov, 1, count);

	kiocb.ki_pos = *ppos;
	ret = proc_record_read_iter(&kiocb, &iter);
	if (ret < 0)
		goto out;
	
	*ppos = kiocb.ki_pos;
out:
	return ret;
}

static loff_t proc_record_lseek(struct file *filp, loff_t offset, int whence)
{
	struct record *r = PDE_DATA(file_inode(filp));

	switch (whence) {
	case SEEK_SET:
		break;
	case SEEK_CUR:
		offset += filp->f_pos;
		break;
	default:
		return -EINVAL;
	}

	if (offset < 0)
		offset = 0;

	if (offset > r->meta.size)
		offset = r->meta.size;

	return (filp->f_pos = offset);
}

static int proc_record_close(struct inode *inode, struct file *filp)
{
	module_put(THIS_MODULE);
	return 0;
}

#ifdef HAVE_PROC_OPS
const struct proc_ops proc_record_ops = {
	.proc_open      = proc_record_open,
	.proc_read      = proc_record_read,
	.proc_read_iter = proc_record_read_iter,
	.proc_lseek     = proc_record_lseek,
	.proc_release   = proc_record_close,
};
#else
const struct file_operations proc_record_ops = {
	.owner      = THIS_MODULE,
	.open       = proc_record_open,
	.read       = proc_record_read,
	.read_iter  = proc_record_read_iter,
	.llseek     = proc_record_lseek,
	.release    = proc_record_close,
};
#endif /* HAVE_PROC_OPS */

static int segment_insert(struct record *r, unsigned long index, void **data)
{
	int ret = 0;
	struct segment *smt;

	smt = radix_tree_lookup(r->root, index);
	if (smt) {
		*data = smt;
		goto out;
	}

	smt = kzalloc(sizeof(*smt), GFP_KERNEL);
	if (!smt) {
		ret = -ENOMEM;
		goto out;
	}

	ret = radix_tree_preload(GFP_NOIO);
	if (ret < 0)
	   goto err_insert;

	ret = radix_tree_insert(r->root, index, smt);
	if (unlikely(ret)) {
		radix_tree_preload_end();
		goto err_insert;
	}
	
	radix_tree_preload_end();
	*data = smt;
	return 0;
	
err_insert:
	kfree(smt);
out:
	return ret;
}

static inline ssize_t record_read_func_iter(void *iter, const void *src,
		size_t count, loff_t pos)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)
	ssize_t ret = copy_to_iter((void *)src, count, iter);
#else
	ssize_t ret = copy_to_iter(src, count, iter);
#endif
	return (ret != count) ? -EFAULT : count;
}

static inline ssize_t record_read_func_user(void *dst, const void *src,
		size_t count, loff_t pos)
{
	return (copy_to_user(dst + pos, src, count) != 0) ? -EFAULT : count;
}

static inline ssize_t record_read_func_kbuf(void *dst, const void *src,
		size_t count, loff_t pos)
{
	memcpy(dst + pos, src, count);
	return count;
}

ssize_t record_read_to_iter(struct record *r, struct iov_iter *iter,
		size_t count, loff_t pos)
{
	return r->ops->read(r, iter, count, pos, record_read_func_iter);
}

ssize_t record_read_to_user(struct record *r, void __user *buf,
		size_t count, loff_t pos)
{
	return r->ops->read(r, buf, count, pos, record_read_func_user);
}

ssize_t record_read_to_kbuf(struct record *r, void *buf,
		size_t count, loff_t pos)
{
	return r->ops->read(r, buf, count, pos, record_read_func_kbuf);
}

static ssize_t record_read(struct record *rec,
		void *buf, size_t count, loff_t pos,
		ssize_t (*read_func)(void *, const void *, size_t, loff_t))
{
	int idx;
	ssize_t ret;
	size_t nbytes, smt_size, ndone = 0;
	unsigned int realbytes;
	void *src, *page;
	struct segment *smt;
	struct compressor *cpr;
	struct record __rcu *r;
	
	page = (void *)__get_free_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;
	
	idx = srcu_read_lock(&data->srcu);
	r = srcu_dereference(rec, &data->srcu);
	count = min_t(size_t, count, r->meta.size - pos);

	do {
		unsigned long index = pos >> PAGE_SHIFT;
		unsigned long offset = pos & (PAGE_SIZE - 1);

		if (pos >= r->meta.size) {
			ret = 0;	/* EOF */
			goto out;
		}
		
		smt = r->ops->fetch(r, index);
		if (unlikely(!smt)) {
			ret = -EINVAL;
			goto out;
		}
		
		smt_size = flags_get_size(&smt->flags);
		cpr = crypto_compressor_get();
		src = zs_map_object(data->pool, smt->handle, ZS_MM_RO);
		
		if (test_bit(SEGMENT_COMPRESSED, &smt->flags)) {
			ret = appkmsg_crypto_decompress(cpr, src, smt_size, &realbytes);
			if (unlikely(ret)) {
				pr_err("[%ld] decompress failed, ret = %ld!\n",
					index, (long)ret);
				zs_unmap_object(data->pool, smt->handle);
				crypto_compressor_put();
				goto out;
			}
			appkmsg_crypto_dump(cpr, page, realbytes);
		} else {
			memcpy(page, src, smt_size);
		}
		
		zs_unmap_object(data->pool, smt->handle);
		crypto_compressor_put();

		nbytes = min_t(size_t, PAGE_SIZE - offset, count);
		ret = read_func(buf, page + offset, nbytes, ndone);
		if (ret < 0)
			goto out;
		
		pos += nbytes;
		ndone += nbytes;
		count -= nbytes;
	} while (count);
	
out:
	srcu_read_unlock(&data->srcu, idx);
	free_page((unsigned long)page);
	return ret < 0 ? ret : ndone;
}

static inline ssize_t record_write_func_iter(void *dst, const void *iter,
		size_t count, loff_t pos)
{
	return (copy_from_iter(dst, count, (void *)iter) != count) ? -EFAULT : count;
}

static inline ssize_t record_write_func_user(void *dst, const void *src,
		size_t count, loff_t pos)
{
	return (copy_from_user(dst, src + pos, count) != 0) ? -EFAULT : count;
}

static inline ssize_t record_write_func_kbuf(void *dst, const void *src,
		size_t count, loff_t pos)
{	
	memcpy(dst, src + pos, count);
	return count;
}

ssize_t record_write_from_iter(struct record *r, struct iov_iter *iter,
		size_t count)
{
	return r->ops->write(r, iter, count, record_write_func_iter);
}

ssize_t record_write_from_user(struct record *r, const void __user *buf,
		size_t count)
{
	return r->ops->write(r, buf, count, record_write_func_user);
}

ssize_t record_write_from_kbuf(struct record *r, const void *buf,
		size_t count)
{
	return r->ops->write(r, buf, count, record_write_func_kbuf);
}

#ifdef CONFIG_STUPID_CODE
static inline int nothing_to_do(struct record *r, struct segment *smt)
{
	return 0;
}
#endif /* CONFIG_STUPID_CODE */

static ssize_t record_write(struct record *r, const void *buf, size_t count,
	ssize_t (*write_func)(void *, const void *, size_t, loff_t))
{
	ssize_t ret;
	size_t nbytes, ndone = 0;
	struct segment *smt;

#ifdef CONFIG_STUPID_CODE
	int (* const write_algo[2])(struct record *, struct segment *) = {
		[0] = nothing_to_do,
		[1] = r->ops->flush,
	};
#endif /* CONFIG_STUPID_CODE */

	do {
		unsigned long index  = r->meta.size >> PAGE_SHIFT;
		unsigned long offset = r->meta.cache_used & (PAGE_SIZE - 1);
		
		nbytes = min_t(size_t, PAGE_SIZE - offset, count);
		ret = write_func(r->meta.cache + offset, buf, nbytes, ndone);
		if (ret < 0)
			goto out;

		ret = r->ops->insert(r, index, (void **)&smt);
		if (ret < 0)
			goto out;

		r->meta.cache_used += nbytes;
		
#ifdef CONFIG_STUPID_CODE
		ret = write_algo[r->meta.cache_used >> PAGE_SHIFT](r, smt);
		if (ret < 0)
			goto out;
#else	
		if (r->meta.cache_used == PAGE_SIZE) {
			ret = r->ops->flush(r, smt);
			if (ret < 0)
				goto out;
		}
#endif /* CONFIG_STUPID_CODE */

		r->meta.size += nbytes;
		ndone += nbytes;
		count -= nbytes;
	} while (count);

out:
	return (ret < 0) ? ret : ndone;
}

static inline struct record *record_get(struct record *r)
{
	if (likely(r))
		kref_get(&r->kref);
	
	return r;
}

static inline void record_release(struct kref *kref)
{
	struct record *r = container_of(kref, struct record, kref);
	r->ops->free(data, r);
}

static inline void record_put(struct record *r)
{
	if (likely(r))
		kref_put(&r->kref, record_release);
}

static int record_flush(struct record *r, struct segment *smt)
{
	int ret = 0;
	bool is_overflow = false;
	unsigned int dst_len;
	gfp_t gfp_flags;
	void *dst;
	struct compressor *cpr;
	
	if (unlikely(!smt)) {
		if (test_bit(REC_INVALID, &r->meta.flags)) {
			ret = -EINVAL;
			goto out;
		}
		
		if (test_bit(REC_SYNCED, &r->meta.flags)) {
			ret = -EEXIST;
			goto out;
		}

		if (!r->meta.cache_used) {
			ret = -ENOENT;
			goto out;
		}
	
		smt = radix_tree_lookup(r->root, (r->meta.size - 1) >> PAGE_SHIFT);
		if (unlikely(!smt)) {
			ret = -ESRCH;
			goto out;
		}
	}

	if (unlikely(test_bit(SEGMENT_COMPRESSED , &smt->flags))) {
		ret = -EBUSY;
		goto out;
	}

	cpr = crypto_compressor_get();
	ret = appkmsg_crypto_compress(cpr, r->meta.cache, r->meta.cache_used, &dst_len);
	if (unlikely(ret)) {
		ret = -ENOMEM;
		goto cpr_put;
	}

	if (dst_len > PAGE_SIZE) {
		dst_len = PAGE_SIZE;
		is_overflow = true;
	}
	
	flags_set_size(&smt->flags, dst_len);
	gfp_flags = __GFP_KSWAPD_RECLAIM | __GFP_NOWARN | __GFP_HIGHMEM | __GFP_MOVABLE;
	smt->handle = ZS_MALLOC(data->pool, dst_len, gfp_flags);
	if (!smt->handle) {
		ret = -ENOMEM;
		goto cpr_put;
	}

	dst = zs_map_object(data->pool, smt->handle, ZS_MM_WO);
	if (!is_overflow) {
		appkmsg_crypto_dump(cpr, dst, dst_len);
		__set_bit(SEGMENT_COMPRESSED, &smt->flags);
	} else {
		memcpy(dst, r->meta.cache, r->meta.cache_used);
	}
	zs_unmap_object(data->pool, smt->handle);
	r->meta.compressed_size += dst_len;
	r->meta.cache_used = 0;
cpr_put:
	crypto_compressor_put();
out:
	return ret;
}

static inline void *record_fetch_from_radix(struct record *r,
		unsigned long index)
{
	return radix_tree_lookup(r->root, (unsigned long)index);
}

static inline void *record_fetch_from_table(struct record *r,
		unsigned long index)
{
	return &r->table[index];
}

static int record_sync(struct record *r)
{
	int ret = 0;
	unsigned long i, n;
	struct segment *table;

	if (test_bit(REC_INVALID, &r->meta.flags)) {
		ret = -EINVAL;
		goto out;
	}

	if (test_bit(REC_SYNCED, &r->meta.flags)) {
		ret = -EEXIST;
		goto out;
	}

	n = r->meta.size >> PAGE_SHIFT;
	n += !!(r->meta.size & (PAGE_SIZE - 1));

	if (!n) { 
		record_put(r);
		__set_bit(REC_INVALID, &r->meta.flags);
		ret = -ENOENT;
		goto out;
	}

	table = vzalloc(array_size(n, sizeof(*table)));
	if (!table) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < n; i++) {
		struct segment *smt = radix_tree_delete(r->root, i);
		if (unlikely(!smt))
			pr_err("%s %d [%ld]=%p, size=%ld, handle=%ld\n", __FUNCTION__,
				__LINE__, i, smt, flags_get_size(&smt->flags), smt->handle);
		memcpy(&table[i], smt, sizeof(*smt));
		kfree(smt);
	}
	
	kfree(r->root);
	r->table = table;
	r->ops->fetch = record_fetch_from_table;
	__set_bit(REC_SYNCED, &r->meta.flags);

	r->meta.pde = proc_create_data(r->meta.name, APPKMSG_RDONLY, 
					data->proc_root, &proc_record_ops, r);
	if (!r->meta.pde) {
		ret = -ENOMEM;
		goto out;
	}
	
	ret = data->ops->link(data, r, REC_ADD_LINK);
out:
	return ret;
}

static int record_link(struct appkmsg_data *ad, struct record *r, int action)
{
#define REC_LINK_NAME __stringify(latest)

	int idx, ret = 0;
	struct record __rcu *next = NULL;
	struct proc_dir_entry *link = NULL;

	idx = srcu_read_lock(&ad->srcu);
	switch (action) {
	case REC_ADD_LINK:
		next = r;
		break;
	case REC_CHG_LINK:
		if (!list_empty(&ad->list))
			next = list_entry_rcu(ad->list.prev, struct record, entry);
		break;
	default:
		ret = -EINVAL;
		goto out;
	}
	
	if (ad->link) 
		proc_remove(ad->link);

	if (next) {
		link = proc_symlink(REC_LINK_NAME, ad->proc_root, next->meta.name);
		if (!link) {
			ret = -ENOMEM;
			goto out;
		}
	}

	ad->link = link;
out:
	srcu_read_unlock(&ad->srcu, idx);
	return ret;
}

static inline struct segment *record_fetch(struct record *r, unsigned long index)
{
	return r->ops->fetch(r, index);
}

static inline void metadata_destroy(struct metadata *md)
{
	if (md->cache)
		free_page((unsigned long)md->cache);
	
	kfree(md->name);
	kfree(md->exepath);
	put_pid(md->pid);
	proc_remove(md->pde);
}

static void record_free_n(struct record **rp)
{
	unsigned long i, n;
	struct record *r = *rp;
	
	n = r->meta.size >> PAGE_SHIFT;
	n += !!(r->meta.size & (PAGE_SIZE - 1));
	
	if (likely(test_bit(REC_SYNCED, &r->meta.flags))) {
		for (i = 0; i < n; i++) {
			struct segment *smt = &r->table[i];
			zs_free(data->pool, smt->handle);
		}
		vfree(r->table);
	} else {
		for (i = 0; i < n; i++) {
			struct segment *smt = radix_tree_delete(r->root, i);
			zs_free(data->pool, smt->handle);
			kfree(smt);
		}
		kfree(r->root);
	}
	
	pr_debug("Freeing: r[%ld] %s\n",
		(unsigned long)pid_nr(r->meta.pid), r->meta.name);
	metadata_destroy(&r->meta);
	kfree(r);
}

static inline void record_free(struct appkmsg_data *ad, struct record *rec)
{
	struct record __rcu *r;
	
	spin_lock(&ad->lock);
	r = srcu_dereference_check(rec, &ad->srcu, lockdep_is_held(&ad->lock));
	list_del_rcu(&r->entry);
	radix_tree_delete(&ad->root, (unsigned long)pid_nr(r->meta.pid));
	spin_unlock(&ad->lock);
	synchronize_srcu(&data->srcu);
	record_free_n(&r);
	data->ops->link(data, NULL, REC_CHG_LINK);
}

static struct record_ops record_default_ops = {
	.read		= record_read,
	.write		= record_write,
	.insert		= segment_insert,
	.flush		= record_flush,
	.sync		= record_sync,
	.fetch		= record_fetch_from_radix,
	.free		= record_free,
};

static int metadata_init(struct metadata *md)
{
	int ret = -EINVAL;
	struct task_struct *task = current;
	char *exepathp;
	struct file *exe_file;
	struct mm_struct *mm;

	md->cache = (void *)__get_free_page(GFP_KERNEL);
	if (!md->cache) {
		ret = -ENOMEM;
		goto err_alloc_page;
	}

	mm = get_task_mm(task);
	rcu_read_lock();
	exe_file = rcu_dereference(mm->exe_file);
	if (exe_file && !get_file_rcu(exe_file)) {
		exe_file = NULL;
		ret = -EINVAL;
		mmput(mm);
		rcu_read_unlock();
		goto err_get_exe_file;
	}
	
	exepathp = file_path(exe_file, md->cache, PAGE_SIZE);
	if (IS_ERR(exepathp)) {
		task_lock(task);
		strncpy(exepathp, task->comm, PAGE_SIZE);
		task_unlock(task);
	}
	rcu_read_unlock();
	mmput(mm);			/* __might_sleep */

	md->exepath = kstrdup(exepathp, GFP_KERNEL);
	if (!md->exepath) {
		ret = -ENOMEM;
		goto err_alloc_exepath;
	}

	md->timestamp = appkmsg_get_real_seconds();
	md->pid = get_pid(task_pid(current));
	scnprintf(md->cache, PAGE_SIZE, "%s_%ld",
			kbasename(md->exepath), (long)pid_nr(md->pid));

	md->name = kstrdup(md->cache, GFP_KERNEL);
	if (!md->name) {
		ret = -ENOMEM;
		goto err_alloc_name;
	}

	return 0;
	
err_alloc_name:
	put_pid(md->pid);
	kfree(md->exepath);
err_alloc_exepath:
err_get_exe_file:
	free_page((unsigned long)md->cache);
err_alloc_page:
	return ret;
}

static struct record *record_create(struct appkmsg_data *ad)
{
	int idx, ret = -ENOMEM;
	struct record *r;

	idx = srcu_read_lock(&ad->srcu);
	r = ad->ops->search(ad, (unsigned long)pid_nr(task_pid(current)));
	srcu_read_unlock(&ad->srcu, idx);
	if (r)
		return r;

	r = kzalloc(sizeof(*r), GFP_KERNEL);
	if (!r)
		goto out;

	ret = metadata_init(&r->meta);
	if (ret)
		goto err_meta_init;

	r->root = kzalloc(sizeof(*r->root), GFP_KERNEL);
	if (!r->root)
		goto err_alloc_radix;

	INIT_RADIX_TREE(r->root, GFP_ATOMIC);
	INIT_LIST_HEAD_RCU(&r->entry);
	spin_lock_init(&r->lock);
	kref_init(&r->kref);
	r->ops = &record_default_ops;

	ret = radix_tree_preload(GFP_NOIO);
	if (ret < 0)
		goto err_radix_insert;
	
	spin_lock(&ad->lock);
	ret = radix_tree_insert(&ad->root, (unsigned long)pid_nr(r->meta.pid), r);
	if (unlikely(ret)) {
		spin_unlock(&ad->lock);
		radix_tree_preload_end();
		goto err_radix_insert;
	}
	
	list_add_tail_rcu(&r->entry, &ad->list);
	spin_unlock(&ad->lock);
	radix_tree_preload_end();
	return r;

err_radix_insert:
	kfree(r->root);
err_alloc_radix:
	metadata_destroy(&r->meta);
err_meta_init:
	kfree(r);
out:
	return ERR_PTR(ret);
}

static inline struct record *record_search(struct appkmsg_data *ad, pid_t pid)
{
	return radix_tree_lookup(&ad->root, (unsigned long)pid);
}

struct record *appkmsg_record_search(pid_t pid)
{
	return record_search(data, pid);
}

static inline int record_remove(struct appkmsg_data *ad, pid_t pid)
{
	struct record __rcu *r;
	int idx;

	idx = srcu_read_lock(&ad->srcu);
	r = ad->ops->search(data, pid);
	if (r) {
		srcu_read_unlock(&ad->srcu, idx);
		record_put(r);
		return APPKMSG_TRUE;
	}
	
	srcu_read_unlock(&ad->srcu, idx);
	return APPKMSG_FALSE;
}

static inline void record_free_all(struct appkmsg_data *ad)
{
	int idx;
	struct record *r, *tmp;

	idx = srcu_read_lock(&ad->srcu);
	list_for_each_entry_safe(r, tmp, &data->list, entry) {
		srcu_read_unlock(&ad->srcu, idx);
		record_put(r);
		idx = srcu_read_lock(&ad->srcu);
	}
	srcu_read_unlock(&ad->srcu, idx);
}

static inline void data_exit(struct appkmsg_data **pp)
{
	if (!*pp || test_bit(DATA_UNINITIALIZE, &(*pp)->flags))
		return;

	(*pp)->ops->free(*pp);
	cleanup_srcu_struct(&(*pp)->srcu);
	remove_proc_subtree(APPKMSG_NAME, NULL);
	zs_destroy_pool((*pp)->pool);
	kfree(*pp);
	*pp = NULL;
}

static const struct data_ops default_data_ops = {
	.create = record_create,
	.search = record_search,
	.remove = record_remove,
	.link 	= record_link,
	.free 	= record_free_all,
	.exit 	= data_exit,
};

void appkmsg_record_free_all(void)
{
	return data->ops->free(data);
}

struct record *appkmsg_record_create(void)
{
	return data->ops->create(data);
}

ssize_t appkmsg_record_read(struct record *r,void *buf, size_t count,
	loff_t pos, unsigned long io_type)
{
	ssize_t (*read_func)(void *, const void *, size_t, loff_t);
	
	switch (io_type) {
	case REC_RW_ITER:
		read_func = record_read_func_iter;
		break;
	case REC_RW_USER:
		read_func = record_read_func_user;
		break;
	case REC_RW_KBUF:
		read_func = record_read_func_kbuf;
		break;
	default:
		return -EINVAL;
	}
	
	return r->ops->read(r, buf, count, pos, read_func);
}

ssize_t appkmsg_record_write(struct record *r, const void *buf, size_t count,
	unsigned long io_type)
{
	ssize_t (*write_func)(void *, const void *, size_t, loff_t);

	switch (io_type) {
	case REC_RW_ITER:
		write_func = record_write_func_iter;
		break;
	case REC_RW_USER:
		write_func = record_write_func_user;
		break;
	case REC_RW_KBUF:
		write_func = record_write_func_kbuf;
		break;
	default:
		return -EINVAL;
	}
	
	return r->ops->write(r, buf, count, write_func);
}

int appkmsg_record_flush(struct record *r)
{
	return r->ops->flush(r, NULL);
}

int appkmsg_record_sync(struct record *r)
{
	return r->ops->sync(r);
}

static ssize_t record_sysfs_ctrl(struct param *p, void *val, size_t count)
{
	int value;
	ssize_t ret;
	struct appkmsg_data *d = param_get_data(p);

	if (!strcmp(param_get_name(p), "destroy")) {
		ret = kstrtoint(val, 10, &value);
		if (ret < 0)
			return ret;
		
		ret = d->ops->remove(d, (unsigned long)value);
		if (!ret)
			return -ENOENT;
	} else if (!strcmp(param_get_name(p), "destroy_all")) {
		d->ops->free(d);
	}

	return count;
}

static const struct param_ops record_sysfs_ops = {
	.set = record_sysfs_ctrl,
};

static int data_init(struct appkmsg_data **pp)
{
	int ret = -ENOMEM;
	struct appkmsg_data *ad;

	if (*pp && test_bit(DATA_INITIALIZED, &(*pp)->flags))
		return 0;

	ad = kzalloc(sizeof(*ad), GFP_KERNEL);
	if (!ad)
		goto out;

	ad->pool = ZS_CREATE_POOL(APPKMSG_NAME, GFP_KERNEL);
	if (!ad->pool)
		goto err_alloc_pool;

	ad->proc_root = proc_mkdir(APPKMSG_NAME, NULL);
	if (!ad->proc_root)
		goto err_proc_mkdir;

	if (!proc_create_data("all", APPKMSG_RDONLY, ad->proc_root, 
							&proc_seq_fops, ad))
		goto err_proc_seq;

	init_srcu_struct(&ad->srcu);
	spin_lock_init(&ad->lock);
	INIT_LIST_HEAD(&ad->list);
	INIT_RADIX_TREE(&ad->root, GFP_ATOMIC);
	__set_bit(DATA_INITIALIZED, &ad->flags);
	ad->ops = &default_data_ops;
	*pp = ad;
	return 0;

err_proc_seq:
	remove_proc_subtree(APPKMSG_NAME, NULL);
err_proc_mkdir:
	zs_destroy_pool(ad->pool);
err_alloc_pool:
	kfree(ad);
out:
	return ret;
}

static ssize_t record_read_tty(char *buf, size_t count)
{
	ssize_t ret = -EINVAL;
	
#ifdef CONFIG_TTY
	struct tty_struct *tty = get_current_tty();

	if (unlikely(!tty))
		return -EINVAL;

	if (likely(!list_empty(&tty->tty_files))) {
		loff_t pos = 0;
		struct tty_file_private *file_priv;

		file_priv = list_first_entry(&tty->tty_files,
						struct tty_file_private, list);

#ifdef HAVE_NEW_KERNEL_READ
		ret = kernel_read(file_priv->file, buf, count, &pos);
#else
		ret = kernel_read(file_priv->file, pos, buf, count);
#endif
	}

	tty_kref_put(tty);

	if (ret == -EAGAIN)
		msleep(1);
	
#endif /* CONFIG_TTY */
	return ret;
}

static void record_write_tty(const char *buf, size_t count)
{
#ifdef CONFIG_TTY
	struct tty_struct *tty;

	tty = get_current_tty();
	if (unlikely(!tty))
		return;
	
	if (likely(!list_empty(&tty->tty_files))) {
		loff_t pos = 0;
		struct tty_file_private *file_priv;

		file_priv = list_first_entry(&tty->tty_files,
						struct tty_file_private, list);
		
#ifdef HAVE_NEW_KERNEL_WRITE
		kernel_write(file_priv->file, buf, count, &pos);
#else
		kernel_write(file_priv->file, buf, count, pos);
#endif
	}

	tty_kref_put(tty);
#endif /* CONFIG_TTY */
}

static int record_chrdev_open(struct inode *inode, struct file *filp)
{
	struct record *r; 

	if (!try_module_get(filp->f_op->owner))
		return -ENODEV;

	r = appkmsg_record_create();
	if (!r)
		return -ENOMEM;

	filp->private_data = record_get(r);
	return 0;
}

static DEFINE_SEMAPHORE(sem);
static ssize_t record_chrdev_read(struct file *filp, char __user *buf,
		size_t count, loff_t *ppos)
{
	void *page;
	size_t nbytes;
	ssize_t ret, nread = 0;
	struct record *r = filp->private_data;

	page = (void *)__get_free_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	nbytes = min_t(size_t, count, PAGE_SIZE);
	ret = nread = record_read_tty(page, nbytes);
	if (ret < 0)
		goto out;

	ret = down_interruptible(&sem);
	if (ret == -EINTR)
		goto out;
	
	ret = record_write_from_kbuf(r, page, nread);
	up(&sem);
	if (ret < 0)
		goto out;

	ret = copy_to_user(buf, page, nread);
	if (ret)
		ret = -EFAULT;
out:
	free_page((unsigned long)page);
	return ret < 0 ? ret : nread;
}

static ssize_t record_chrdev_write(struct file *filp, const char __user *buf,
		size_t count, loff_t *ppos)
{
	ssize_t ret;
	void *page;
	size_t nbytes, nwritten = 0;
	struct record *r = filp->private_data;

	page = (void *)__get_free_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	ret = down_interruptible(&sem);
	if (ret == -EINTR)
		goto out;
	
	do {
		nbytes = min_t(size_t, count, PAGE_SIZE);
		ret = copy_from_user(page, buf + nwritten, nbytes);
		if (ret) {
			ret = -EFAULT;
			goto clean;
		}

		record_write_tty(page, nbytes);
		ret = record_write_from_kbuf(r, page, nbytes);
		if (ret < 0)
			goto clean;

		nwritten += nbytes;
		count -= nbytes;
	} while (count);
	
	*ppos += nwritten;
clean:
	up(&sem);
out:
	free_page((unsigned long)page);
	return ret < 0 ? ret : nwritten;
}

static int record_chrdev_close(struct inode *inode, struct file *filp)
{
	struct record __rcu *r = filp->private_data;
	
	if (likely(r)) {
		(void)appkmsg_record_flush(r);
		(void)appkmsg_record_sync(r);
		record_put(r);
		filp->private_data = NULL;
	} 

	module_put(THIS_MODULE);
	return 0;
}

static const struct file_operations record_chrdev_fops = {
	.owner		= THIS_MODULE,
	.open		= record_chrdev_open,
	.read		= record_chrdev_read,
	.write		= record_chrdev_write,
	.release	= record_chrdev_close,
};

int appkmsg_data_init(void)
{
	int ret = 0;
	struct chardev *cdev;

	ret = data_init(&data);
	if (ret < 0)
		return ret;
	
	ret = param_create_data("destroy", data, 0200, &record_sysfs_ops);
	ret += param_create_data("destroy_all", data, 0200, &record_sysfs_ops);
	if (ret < 0)
		return ret;
	
	cdev = appkmsg_chrdev_alloc_misc(APPKMSG_NAME, &record_chrdev_fops);
	if (IS_ERR(cdev))
		return PTR_ERR(cdev);

	return appkmsg_params_sync();
}

void appkmsg_data_exit(void)
{
	if (!data)
		return;
	
	data->ops->exit(&data);
}


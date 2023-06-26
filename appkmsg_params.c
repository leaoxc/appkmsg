/* appkmsg_params.c -- This file is part of the appkmsg project.
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

#include <linux/kobject.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/idr.h>
#include <linux/radix-tree.h>
#include <linux/vmalloc.h>
#include "appkmsg_config.h"
#include "appkmsg_params.h"
#include "appkmsg_lib.h"

enum param_type {
	PARAM_TYPE_ULONG,
	PARAM_TYPE_STRING,
	PARAM_TYPE_DATA,
};

enum param_flags {
	PARAM_SYNCED = FLAG_SHIFT,
};

struct param_string {
	size_t length;
	char str[0];
};

struct param {
	spinlock_t lock;
	struct attribute attr;
	union {
		unsigned long value;
		struct param_string *string;
		void *data;
	};
	const struct param_ops *ops;
};

struct params_ops {
	int (*create)(struct appkmsg_params *ap, const char *name, void *val,
		umode_t mode, unsigned long type, const struct param_ops *ops);
	struct param *(*fetch)(struct appkmsg_params *ap, unsigned long id);
	int (*sync)(struct appkmsg_params *ap);
	void (*free)(struct appkmsg_params *ap);
};

struct appkmsg_params {
	unsigned long flags;
	spinlock_t lock;
	union {
		struct idr *idr;
		struct param **table;
	};
	struct kobject kobj;
	struct params_ops *ops;
};

#define to_params_obj(x) container_of(x, struct appkmsg_params, kobj)
#define to_param_obj(x) container_of(x, struct param, attr)

static struct appkmsg_params *params;

static int param_init_ulong(struct param *p, void *val)
{
	p->value = (unsigned long)val;
	return 0;
}

static inline ssize_t param_set_ulong(struct param *p, void *buf, size_t count)
{
	unsigned long long value;
	
	if (kstrtoull(buf, 10, &value) < 0)
		return -EINVAL;

	p->value = (unsigned long)value;
	return count;
}

static inline ssize_t param_get_ulong(struct param *p, void *buf, size_t size)
{
	return scnprintf(buf, size, "%ld\n", p->value);
}

static const struct param_ops param_ulong_ops = {
	.init = param_init_ulong,
	.set  = param_set_ulong,
	.get  = param_get_ulong,
};

static inline int param_init_string(struct param *p, void *string)
{
	size_t length = strlen((const char *)string);
	
	p->string = kzalloc(sizeof(*p->string) + length + 1, GFP_KERNEL);
	if (!p->string)
		return -ENOMEM;

	p->string->length = length;
	strncpy(p->string->str, string, p->string->length);
	return 0;
}

static inline ssize_t param_set_string(struct param *p,
		void *string, size_t count)
{
	struct param_string *ps;
	char *tmp = string;
	size_t length = strlen(tmp);

	if (likely(tmp[count - 1] == '\n'))
		length -= 1;

	ps = kzalloc(sizeof(*p->string) + length + 1, GFP_KERNEL);
	if (!ps)
		return -ENOMEM;

	ps->length = length;
	strncpy(ps->str, string, ps->length);
	kfree(p->string);
	p->string = ps;
	return count;
}

static inline ssize_t param_get_string(struct param *p, void *buf, size_t size)
{
	return scnprintf(buf, size, "%s\n", p->string->str);
}

static inline void param_free_string(struct param *p)
{
	if (likely(p->string))
		kfree(p->string);
}

static const struct param_ops param_string_ops = {
	.init = param_init_string,
	.set  = param_set_string,
	.get  = param_get_string,
	.free = param_free_string,
};

static int param_create(struct appkmsg_params *ap, const char *name, void *val,
		umode_t mode, unsigned long type, const struct param_ops *ops)
{
	int id, ret = -ENOMEM;
	struct param *p;

	if (test_bit(PARAM_SYNCED, &ap->flags))
		return -EEXIST;

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		goto out;

	switch (type) {
	case PARAM_TYPE_ULONG:
		p->ops = &param_ulong_ops;
		break;
	case PARAM_TYPE_STRING:
		p->ops = &param_string_ops;
		break;
	case PARAM_TYPE_DATA:
		p->data = val;
		p->ops = ops;
		break;
	default:
		goto err_param_type;
	}

	if (p->ops->init) {
		ret = p->ops->init(p, val);
		if (ret < 0)
			goto err_param_init;
	}
	
	idr_preload(GFP_KERNEL);
	spin_lock(&ap->lock);
	ret = idr_alloc(ap->idr, p, 0, 0, GFP_ATOMIC);
	if (ret < 0) {
		spin_unlock(&ap->lock);
		goto err_idr_alloc;
	}
	spin_unlock(&ap->lock);
	idr_preload_end();
	
	id = ret;
	p->attr.name = name;
	p->attr.mode = mode;
	spin_lock_init(&p->lock);
	flags_set_size(&ap->flags, flags_get_size(&ap->flags) + 1);
	return id;

err_idr_alloc:
	if (p->ops->free)
		p->ops->free(p);
err_param_init:
err_param_type:
	kfree(p);
out:
	return ret;
}

int param_create_ulong(const char *name, unsigned long value, umode_t mode)
{
	return params->ops->create(params, name, (void *)value, mode,
				PARAM_TYPE_ULONG, NULL);
}

int param_create_string(const char *name, const char *str, umode_t mode)
{
	return params->ops->create(params, name, (void *)str, mode,
				PARAM_TYPE_STRING, NULL);
}

int param_create_data(const char *name, void *data, umode_t mode, 
		const struct param_ops *ops)
{
	if (!ops)
		return -EINVAL;
	
	return params->ops->create(params, name, data, mode, PARAM_TYPE_DATA, ops);
}

const char *param_get_name(struct param *p)
{
	return p->attr.name;
}

void *param_get_data(struct param *p)
{
	return p->data;
}

static inline struct param *param_fetch_from_idr(struct appkmsg_params *ap,
		unsigned long id)
{
	return idr_find(ap->idr, id);
}

static inline struct param *param_fetch_from_table(struct appkmsg_params *ap,
		unsigned long id)
{
	return ap->table[id];
}

static inline struct param *param_fetch(struct appkmsg_params *ap,
		unsigned long id)
{
	return ap->ops->fetch(ap, id);
}

static int param_sync(struct appkmsg_params *ap)
{
	int i, size, ret = 0;
	struct param *p, **table;
	
	if (test_bit(PARAM_SYNCED, &ap->flags)) {
		ret = -EEXIST;
		goto out;
	}

	size = flags_get_size(&ap->flags);
	table = vzalloc(array_size(size, sizeof(*table)));
	if (!table) {
		ret = -ENOMEM;
		goto out;
	}
	
	idr_for_each_entry(ap->idr, p, i) {
		table[i] = p;
		idr_remove(ap->idr, i);		
		ret = sysfs_create_file(&ap->kobj, &table[i]->attr);
		if (ret)
			goto err_create_file;
	}

	idr_destroy(ap->idr);
	kfree(ap->idr);
	__set_bit(PARAM_SYNCED, &ap->flags);
	ap->table = table;
	ap->ops->fetch = param_fetch_from_table;
	return 0;
	
err_create_file:
	vfree(table);
out:
	return ret;
}

static struct params_ops default_params_ops = {
	.create	= param_create,
	.fetch	= param_fetch_from_idr,
	.sync	= param_sync,
};

struct param *appkmsg_param_fetch(unsigned long id)
{
	if (id > flags_get_size(&params->flags))
		return NULL;
	
	return params->ops->fetch(params, id);
}

int appkmsg_params_sync(void)
{
	return params->ops->sync(params);
}

static inline ssize_t sysfs_param_show(struct appkmsg_params *ap,
		struct param *p, char *buf)
{
	return p->ops->get(p, buf, PAGE_SIZE);
}

static inline ssize_t sysfs_param_store(struct appkmsg_params *ap,
		struct param *p, const char *buf, size_t count)
{
	return p->ops->set(p, (void *)buf, count);
}

static ssize_t sysfs_kobj_show(struct kobject *kobj, struct attribute *attr,
		char *buf)
{
	struct appkmsg_params *ap = to_params_obj(kobj);
	struct param *p = to_param_obj(attr);

	if (!p->ops->get)
		return -EIO;
	
	return sysfs_param_show(ap, p, buf);
}

static ssize_t sysfs_kobj_store(struct kobject *kobj, struct attribute *attr,
		const char *buf, size_t count)
{
	struct appkmsg_params *ap = to_params_obj(kobj);
	struct param *p = to_param_obj(attr);

	if (!p->ops->set)
		return -EIO;
	
	return sysfs_param_store(ap, p, buf, count);
}

static const struct sysfs_ops param_sysfs_ops = {
	.show  = sysfs_kobj_show,
	.store = sysfs_kobj_store,
};

static void params_release(struct kobject *kobj)
{
	struct param *p;
	struct appkmsg_params *ap = to_params_obj(kobj);
	unsigned long id, size = flags_get_size(&ap->flags);
	
	for (id = 0; id < size; id++) {
		p = param_fetch(ap, id);
		if (p->ops->free)
			p->ops->free(p);
		kfree(p);
	}
	
	if (likely(test_bit(PARAM_SYNCED, &ap->flags))) {
		vfree(ap->table);
	} else {
		idr_destroy(ap->idr);
		kfree(ap->idr);
	}
	
	kfree(ap);
}

static struct kobj_type param_type = {
	.release	= params_release,
	.sysfs_ops	= &param_sysfs_ops,
};

int appkmsg_params_init(void)
{
	int ret = -EINVAL;
	struct appkmsg_params *ap;

	ap = kzalloc(sizeof(*ap), GFP_KERNEL);
	if (!ap)
		goto out;

	ap->idr = kzalloc(sizeof(*ap->idr), GFP_KERNEL);
	if (!ap->idr)
		goto err_idr;

	ret = kobject_init_and_add(&ap->kobj, &param_type, NULL, "%s",
			APPKMSG_NAME);
	if (ret)
		goto err_kobj_add;

	kobject_uevent(&ap->kobj, KOBJ_ADD);
	idr_init(ap->idr);
	spin_lock_init(&ap->lock);
	ap->ops = &default_params_ops;
	params = ap;

	ret = param_create_string("version", "appkmsg v0.1.0 beta", APPKMSG_RDONLY);
	return ret;

err_kobj_add:
	kfree(ap->idr);
err_idr:
	kfree(ap);
out:
	return ret;
}

void appkmsg_params_exit(void)
{
	if (!params)
		return;
	
	kobject_put(&params->kobj);
	params = NULL;
}


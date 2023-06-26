/* appkmsg_cdev.c -- This file is part of the appkmsg project.
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
#include <linux/cdev.h>
#include <linux/kdev_t.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/miscdevice.h>
#include "appkmsg_cdev.h"
#include "appkmsg_lib.h"

enum class_type {
	CLASS_ORIGIN = FLAG_SHIFT,
	CLASS_NEW,
};

enum chardev_type {
	CDEV_GENERIC,
	CDEV_MISC,
};

struct chrdev {
	const char *name;
	dev_t devno;
	unsigned long flags;
	struct cdev cdev;
	struct class *cls;
	struct device *device;
	const struct file_operations *fops;
};

struct chardev_ops {
	int (*add)(struct chardev *cdev);
	void (*remove)(struct chardev *cdev);
};

struct chardev {
	struct list_head entry;
	const struct chardev_ops *ops;
	struct {
		union {
			struct chrdev cdev;
			struct miscdevice misc;
		};
	} dev[0];
};

struct appkmsg_cdevs {
	spinlock_t lock;
	struct list_head list;
};

static struct appkmsg_cdevs *cdevs;

static int chardev_add(struct chardev *cdev)
{
	int ret;
	struct chrdev *cd = (struct chrdev *)cdev->dev;
	unsigned long count = flags_get_size(&cd->flags);

	if (MAJOR(cd->devno))
		ret = register_chrdev_region(cd->devno, count, cd->name);
	else
		ret = alloc_chrdev_region(&cd->devno, MINOR(cd->devno), count,
				cd->name);

	if (ret < 0)
		goto out;
	
	cdev_init(&cd->cdev, cd->fops);
	cd->cdev.owner = THIS_MODULE;
	ret = cdev_add(&cd->cdev, cd->devno, count);
	if (ret < 0)
		goto err_cdev_add;

	if (!cd->cls && test_bit(CLASS_NEW, &cd->flags)) {
		cd->cls = class_create(THIS_MODULE, cd->name);
		if (IS_ERR(cd->cls)) {
			ret = PTR_ERR(cd->cls);
			goto err_class_create;
		}
	}

	cd->device = device_create(cd->cls, NULL, cd->devno, NULL, "%s", cd->name);
	if (IS_ERR(cd->device)) {
		ret = PTR_ERR(cd->device);
		goto err_device_create;
	}
	
	return 0;

err_device_create:
	if (test_bit(CLASS_NEW, &cd->flags))
		class_destroy(cd->cls);
err_class_create:
	cdev_del(&cd->cdev);
err_cdev_add:
	unregister_chrdev(MAJOR(cd->devno), cd->name);
out:
	return ret;
}

static void chardev_remove(struct chardev *cdev)
{
	struct chrdev *cd = (struct chrdev *)cdev->dev;
	
	device_destroy(cd->cls, cd->devno);
	if (test_bit(CLASS_NEW, &cd->flags))
		class_destroy(cd->cls);
	cdev_del(&cd->cdev);
	unregister_chrdev(MAJOR(cd->devno), cd->name);
}

static const struct chardev_ops cdev_generic_ops = {
	.add = chardev_add,
	.remove = chardev_remove,
};

static inline int chardev_misc_add(struct chardev *cdev)
{
	return misc_register((struct miscdevice *)cdev->dev);
}

static inline void chardev_misc_remove(struct chardev *cdev)
{
	misc_deregister((struct miscdevice *)cdev->dev);
}

static const struct chardev_ops cdev_misc_ops = {
	.add = chardev_misc_add,
	.remove = chardev_misc_remove,
};

static struct chardev *__chrdev_add(const char *name, int major, int minor,
	const struct file_operations *fops, unsigned long type, struct class *cls)
{
	int ret = -ENOMEM;
	struct chardev *cdev;
	struct chrdev *cd;
	struct miscdevice *md;

	if (!fops) {
		ret = -EINVAL;
		goto out;
	}

	switch (type) {
	case CDEV_GENERIC:
		cdev = kzalloc(sizeof(*cdev) + sizeof(struct chrdev), GFP_KERNEL);
		if (!cdev)
			goto out;
		
		cd = (struct chrdev *)cdev->dev;
		cd->name = name;
		cd->devno = MKDEV(major, minor);
		cd->fops = fops;
		cd->cls = cls;
		cdev->ops = &cdev_generic_ops;
		__set_bit(cls ? CLASS_ORIGIN : CLASS_NEW, &cd->flags);
		break;
	case CDEV_MISC:
		cdev = kzalloc(sizeof(*cdev) + sizeof(struct miscdevice), GFP_KERNEL);
		if (!cdev)
			goto out;
		
		md = (struct miscdevice *)cdev->dev;
		md->name = name;
		md->minor = minor;
		md->fops = fops;
		cdev->ops = &cdev_misc_ops;
		break;
	default:
		ret = -EINVAL;
		goto out;
	};

	ret = cdev->ops->add(cdev);
	if (ret)
		goto err_cdev_add;

	spin_lock(&cdevs->lock);
	list_add_tail(&cdev->entry, &cdevs->list);
	spin_unlock(&cdevs->lock);
	return cdev;

err_cdev_add:
	kfree(cdev);
out:
	return ERR_PTR(ret);
}

struct chardev *appkmsg_chrdev_register(const char *name, int major, int minor,
	const struct file_operations *fops, struct class *cls)
{
	if (!major)
		return ERR_PTR(-EINVAL);
	
	return __chrdev_add(name, major, minor, fops, CDEV_GENERIC, cls);
}

struct chardev *appkmsg_chrdev_register_misc(const char *name, int minor,
	const struct file_operations *fops)
{
	return __chrdev_add(name, 0, minor, fops, CDEV_MISC, NULL);
}

struct chardev *appkmsg_chrdev_alloc_misc(const char *name,
	const struct file_operations *fops)
{
	return __chrdev_add(name, 0, MISC_DYNAMIC_MINOR, fops, CDEV_MISC, NULL);
}

struct chardev *appkmsg_chrdev_alloc(const char *name, int minor,
	const struct file_operations *fops, struct class *cls)
{
	return __chrdev_add(name, 0, minor, fops, CDEV_GENERIC, cls);
}

struct chardev *appkmsg_chrdev_alloc_simple(const char *name,
	const struct file_operations *fops)
{
	return __chrdev_add(name, 0, 0, fops, CDEV_GENERIC, NULL);
}

void appkmsg_chrdev_del(struct chardev *cd)
{
	cd->ops->remove(cd);
	spin_lock(&cdevs->lock);
	list_del(&cd->entry);
	spin_unlock(&cdevs->lock);
	kfree(cd);
}

int appkmsg_cdevs_init(void)
{
	cdevs = kzalloc(sizeof(*cdevs), GFP_KERNEL);
	if (!cdevs)
		return -ENOMEM;

	INIT_LIST_HEAD(&cdevs->list);
	spin_lock_init(&cdevs->lock);
	return 0;
}

void appkmsg_cdevs_exit(void)
{
	struct chardev *cdev, *tmp;

	if (!cdevs)
		return;
	
	list_for_each_entry_safe(cdev, tmp, &cdevs->list, entry)
		appkmsg_chrdev_del(cdev);

	kfree(cdevs);
	cdevs = NULL;
}


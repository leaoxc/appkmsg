/* appkmsg_cdev.h -- This file is part of the appkmsg project.
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

#ifndef APPKMSG_CDEV_H
#define APPKMSG_CDEV_H

struct class;
struct file_operations;
struct chardev;

extern struct chardev *appkmsg_chrdev_register(const char *name, int major,
	int minor, const struct file_operations *fops, struct class *cls);
extern struct chardev *appkmsg_chrdev_register_misc(const char *name, int minor,
	const struct file_operations *fops);
extern struct chardev *appkmsg_chrdev_alloc_misc(const char *name,
	const struct file_operations *fops);
extern struct chardev *appkmsg_chrdev_alloc(const char *name, int minor,
	const struct file_operations *fops, struct class *cls);
extern struct chardev *appkmsg_chrdev_alloc_simple(const char *name,
	const struct file_operations *fops);
extern void appkmsg_chrdev_del(struct chardev *cd);
extern int appkmsg_cdevs_init(void);
extern void appkmsg_cdevs_exit(void);

#endif /* APPKMSG_CDEV_H */

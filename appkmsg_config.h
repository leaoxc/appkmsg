/* appkmsg_config.h -- This file is part of the appkmsg project.
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

#ifndef APPKMSG_CONFIG_H
#define APPKMSG_CONFIG_H

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
#define appkmsg_time_to_tm time64_to_tm 	/* time64_to_tm: linux/time.h */
#else
#define appkmsg_time_to_tm time_to_tm		/* time_to_tm:   linux/time.h */
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/mm.h>     /* get_task_mm: linux/sched/mm.h  	(4.11+) */
#include <linux/sched/task.h>   /* task_lock:   linux/sched/task.h	(4.11+) */
#else
#include <linux/mm.h>           /* get_task_mm: linux/mm.h    		(4.10) */
#include <linux/sched.h>        /* task_unlock: linux/sched.h		(4.10) */
#endif

/* linux/fs.h */
/* (>=4.14) kernel_read  [arg 2]: void * 		[arg 4]: loff_t *		*/
/* ( <4.14) kernel_read  [arg 2]: loff_t		[arg 4]: unsigned long	*/
/* (>=4.14) kernel_write [arg 2]: const void *	[arg 4]: loff_t *		*/
/* ( <4.14) kernel_write [arg 2]: const char *	[arg 4]: loff_t			*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#define HAVE_NEW_KERNEL_READ
#define HAVE_NEW_KERNEL_WRITE
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
#define HAVE_TTY_FILES_LOCK
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
#define get_file_rcu(x) atomic_long_inc_not_zero(&(x)->f_count)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
#define appkmsg_get_real_seconds ktime_get_real_seconds
#else
#define appkmsg_get_real_seconds get_seconds
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
#define appkmsg_access_ok(t, x, y)  access_ok(x, y)
#else
#define appkmsg_access_ok(...)      access_ok(__VA_ARGS__)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
#define HAVE_PROC_OPS
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
#define HAVE_PROC_SEQ
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
#define HAVE_SEQ_FILE_FILE
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
#define HAVE_KOBJ_TYPE_ATTRIBUTE_GROUP
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
#define PDE_DATA pde_data
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#define HAVE_LOCAL_LOCK
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0)
#define array_size(x, y) ((x) * (y))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
#define ZS_MALLOC(x, y, z)		zs_malloc((x), (y))
#define ZS_CREATE_POOL(a, b)	zs_create_pool((a), (b))
#else
#define ZS_MALLOC(x, y, z)		zs_malloc((x), (y), (z))
#define ZS_CREATE_POOL(a, b)	zs_create_pool((a))
#endif

#define APPKMSG_TRUE				1
#define APPKMSG_FALSE				0
									
#define APPKMSG_ENABLE				APPKMSG_TRUE
#define APPKMSG_DISABLE				APPKMSG_FALSE

#define DEF_NAME(x)					__stringify(x)
#define APPKMSG_NAME 				DEF_NAME(appkmsg)
#define APPKMSGD_NAME 				DEF_NAME(appkmsgd)

#define APPKMSG_MAJOR				0
#define APPKMSG_MINOR				1
#define APPKMSG_PATCH				0
#define APPKMSG_VERSION 			((APPKMSG_MAJOR << 16) | \
						 			(APPKMSG_MINOR << 8) | \
						  			(APPKMSG_PATCH))

#define APPKMSG_RDONLY				(S_IRUGO)
#define APPKMSG_WRONLY				(S_IWUSR)
#define APPKMSG_RDWR				(S_IRUGO | S_IWUSR | S_IWGRP)


#define CONFIG_STUPID_CODE

#endif /* APPKMSG_CONFIG_H */


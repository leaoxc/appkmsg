/* appkmsg_data.h -- This file is part of the appkmsg project.
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

#ifndef APPKMSG_DATA_H
#define APPKMSG_DATA_H

struct appkmsg_data;
struct record;
struct segment;
struct iov_iter;

extern void appkmsg_record_free_all(void);
extern struct record *appkmsg_record_create(void);
extern ssize_t appkmsg_record_read(struct record *r, void *buf, size_t count,
	loff_t pos, unsigned long io_type);
extern ssize_t record_read_to_iter(struct record *r, struct iov_iter *iter,
	size_t count, loff_t pos);
extern ssize_t record_read_to_user(struct record *r, void __user *buf,
	size_t count, loff_t pos);
extern ssize_t record_read_to_kbuf(struct record *r, void *buf, size_t count,
	loff_t pos);
extern ssize_t appkmsg_record_write(struct record *r, const void *buf,
	size_t count, unsigned long io_type);
extern ssize_t record_write_from_iter(struct record *r, struct iov_iter *iter,
	size_t count);
extern ssize_t record_write_from_user(struct record *r, const void __user *buf,
	size_t count);
extern ssize_t record_write_from_kbuf(struct record *r, const void *buf,
	size_t count);
extern struct record *appkmsg_record_search(pid_t pid);
extern int appkmsg_record_flush(struct record *r);
extern int appkmsg_record_sync(struct record *r);
extern int appkmsg_data_init(void);
extern void appkmsg_data_exit(void);

#endif /* APPKMSG_DATA_H */

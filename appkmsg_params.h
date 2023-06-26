/* appkmsg_params.h -- This file is part of the appkmsg project.
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

#ifndef APPKMSG_PARAM_H
#define APPKMSG_PARAM_H

struct appkmsg_params;
struct param;

struct param_ops {
	int (*init)(struct param *p, void *val);
	ssize_t (*set)(struct param *p, void *val, size_t count);
	ssize_t (*get)(struct param *p, void *buf, size_t size);
	void (*free)(struct param *p);
};

extern int param_create_ulong(const char *name, unsigned long value,
		umode_t mode);
extern int param_create_string(const char *name, const char *str,
		umode_t mode);
extern int param_create_data(const char *name, void *data, umode_t mode,
		const struct param_ops *ops);
extern const char *param_get_name(struct param *p);
extern void *param_get_data(struct param *p);
extern struct param *appkmsg_param_fetch(unsigned long id);
extern int appkmsg_params_sync(void);
extern int appkmsg_params_init(void);
extern void appkmsg_params_exit(void);

#endif /* APPKMSG_PARAM_H */

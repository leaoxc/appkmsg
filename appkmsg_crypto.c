/* appkmsg_crypto.c -- This file is part of the appkmsg project.
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

#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/slab.h>
#include <linux/zsmalloc.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#ifdef HAVE_LOCAL_LOCK
#include <linux/local_lock.h>
#endif /* HAVE_LOCAL_LOCK */
#include "appkmsg_config.h"
#include "appkmsg_crypto.h"
#include "appkmsg_data.h"
#include "appkmsg_params.h"

struct compressor {
	struct crypto_comp *cc;
	void *cache;
#ifdef HAVE_LOCAL_LOCK
	local_lock_t lock;
#endif /* HAVE_LOCAL_LOCK */
};

struct appkmsg_crypto {
	char algo[CRYPTO_MAX_ALG_NAME];
	struct compressor __percpu *cpr;
	const struct crypto_ops *ops;
};

struct crypto_ops {
	int (*create)(struct compressor *cpr, const char *algo_name);
	int (*compress)(struct compressor *cpr, const void *src,
			unsigned int src_len, void *dst, unsigned int *dst_len);
	int (*decompress)(struct compressor *cpr, const void *src,
			unsigned int src_len, void *dst, unsigned int *dst_len);
	void (*dump)(struct compressor *cpr, void *dst, unsigned int dst_len);
	void (*free)(struct compressor *cpr);
};

static const char * const crypto_alg[] = {
#if IS_ENABLED(CONFIG_CRYPTO_LZO)
	"lzo",
	"lzo-rle",
#endif
#if IS_ENABLED(CONFIG_CRYPTO_LZ4)
	"lz4",
#endif
#if IS_ENABLED(CONFIG_CRYPTO_LZ4HC)
	"lz4hc",
#endif
#if IS_ENABLED(CONFIG_CRYPTO_842)
	"842",
#endif
#if IS_ENABLED(CONFIG_CRYPTO_ZSTD)
	"zstd",
#endif
};

static inline int crypto_create_compressor(struct compressor *cpr,
		const char *algo_name)
{
	int ret;

	cpr->cc = crypto_alloc_comp(algo_name, 0, 0);
	if (IS_ERR(cpr->cc)) {
		ret = PTR_ERR(cpr->cc);
		goto out;
	}

	cpr->cache = (void *)__get_free_pages(GFP_KERNEL, 1); /* PAGE_SIZE << 1 */
	if (!cpr->cache) {
		ret = -ENOMEM;
		goto err_alloc_cache;
	}

#ifdef HAVE_LOCAL_LOCK
	local_lock_init(&cpr->lock);
#endif /* HAVE_LOCAL_LOCK */

	return 0;

err_alloc_cache:
	crypto_free_comp(cpr->cc);
out:
	return ret;
}

static inline int crypto_compress(struct compressor *cpr, const void *src,
		unsigned int src_len, void *dst, unsigned int *dst_len)
{
	*dst_len = PAGE_SIZE << 1;
	return crypto_comp_compress(cpr->cc, src, src_len, cpr->cache, dst_len);
}

static inline int crypto_decompress(struct compressor *cpr, const void *src,
		unsigned int src_len, void *dst, unsigned int *dst_len)
{
	*dst_len = PAGE_SIZE;
	return crypto_comp_decompress(cpr->cc, src, src_len, cpr->cache, dst_len);
}

static inline void crypto_dump(struct compressor *cpr,
		void *dst, unsigned int dst_len)
{
	if (dst_len > (PAGE_SIZE << 1))
		dst_len = PAGE_SIZE << 1;
	
	memcpy(dst, cpr->cache, dst_len);
}

static inline void crypto_free_compressor(struct compressor *cpr)
{
	free_pages((unsigned long)cpr->cache, 1);
	crypto_free_comp(cpr->cc);
}

static const struct crypto_ops default_crypto_ops = {
	.create 	= crypto_create_compressor,
	.compress 	= crypto_compress,
	.decompress = crypto_decompress,
	.dump 		= crypto_dump,
	.free 		= crypto_free_compressor,
};

static struct appkmsg_crypto *crypto;

int appkmsg_crypto_compress(struct compressor *cpr, const void *src,
		unsigned int src_len, unsigned int *dst_len)
{
	return crypto->ops->compress(cpr, src, src_len, cpr->cache, dst_len);
}

int appkmsg_crypto_decompress(struct compressor *cpr, const void *src,
		unsigned int src_len, unsigned int *dst_len)
{
	return crypto->ops->decompress(cpr, src, src_len, cpr->cache, dst_len);
}

void appkmsg_crypto_dump(struct compressor *cpr, void *dst,
		unsigned int dst_len)
{
	crypto->ops->dump(cpr, dst, dst_len);
}

void appkmsg_crypto_copy_to_cache(struct compressor *cpr, void *src,
		unsigned int src_len)
{
	if (src_len > (PAGE_SIZE << 1))
		src_len = PAGE_SIZE << 1;
	
	memcpy(cpr->cache, src, src_len);
}

void *appkmsg_crypto_cache(struct compressor *cpr)
{
	return cpr->cache;
}

static int crypto_compressor_create(struct appkmsg_crypto *ac, const char *algo)
{
	int cpu, fail = 0;
	int ret = -ENOMEM;
	struct compressor *cpr;
	
	ac->cpr = alloc_percpu(struct compressor);
	if (!ac->cpr)
		goto out;

	strlcpy(ac->algo, algo, sizeof(ac->algo));

	for_each_possible_cpu(cpu) {
		cpr = per_cpu_ptr(ac->cpr, cpu);
		ret = crypto_create_compressor(cpr, ac->algo);
		if (ret < 0) {
			fail = cpu;
			goto clean;
		}
	}
	
	return 0;

clean:
	for_each_possible_cpu(cpu) {
		if (fail <= cpu)
			break;
		cpr = per_cpu_ptr(ac->cpr, cpu);
		crypto_free_compressor(cpr);
	}
	
	free_percpu(ac->cpr);
out:
	return ret;
}

static inline void crypto_compressor_destroy(struct appkmsg_crypto *ac)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct compressor *cpr = per_cpu_ptr(ac->cpr, cpu);
		crypto_free_compressor(cpr);
	}
	
	free_percpu(ac->cpr);
}

static ssize_t crypto_sysfs_ctrl(struct param *p, void *val, size_t count)
{
	ssize_t ret;
	char *tmp = val;
	size_t len = strlen(tmp);
	struct appkmsg_crypto *ac = param_get_data(p);

	ret = module_refcount(THIS_MODULE);
	if (ret)
		return -EBUSY;

	if (tmp[len - 1] == '\n')
		tmp[len - 1] = '\0';

	if (crypto_has_alg(tmp, 0, 0) != APPKMSG_TRUE)
		return -EINVAL;

	crypto_compressor_destroy(ac);
	ret = crypto_compressor_create(ac, tmp);
	appkmsg_record_free_all();
	return (ret < 0) ? ret : count;
}

static ssize_t crypto_sysfs_show(struct param *p, void *buf, size_t size)
{
	int i;
	size_t ret = 0;
	bool known_algo = false;
	struct appkmsg_crypto *ac = param_get_data(p);

	for (i = 0; i < ARRAY_SIZE(crypto_alg); i++) {
		if (!strcmp(ac->algo, crypto_alg[i])) {
			known_algo = true;
			ret += scnprintf(buf + ret, size - ret - 2, "[%s] ", crypto_alg[i]);
		} else {
			ret += scnprintf(buf + ret, size - ret - 2, "%s ", crypto_alg[i]);
		}
	}
	
	if (!known_algo && crypto_has_alg(ac->algo, 0, 0) == 1)
		ret += scnprintf(buf + ret, size - ret - 2, "[%s] ", ac->algo);
	
	ret += scnprintf(buf + ret, size - ret, "\n");
	return ret;
}

static const struct param_ops crypto_sysfs_ops = {
	.set = crypto_sysfs_ctrl,
	.get = crypto_sysfs_show,
};

struct compressor *crypto_compressor_get(void)
{
	struct compressor *cpr;
	
#ifdef HAVE_LOCAL_LOCK
	local_lock(&crypto->cpr->lock);
	cpr = this_cpu_ptr(crypto->cpr);
#else
	cpr = get_cpu_ptr(crypto->cpr);
#endif /* HAVE_LOCAL_LOCK */

	return cpr;
}

void crypto_compressor_put(void)
{
#ifdef HAVE_LOCAL_LOCK
	local_unlock(&crypto->cpr->lock);
#else
	put_cpu_ptr(crypto->cpr);
#endif /* HAVE_LOCAL_LOCK */
}

int appkmsg_crypto_init(void)
{
	int ret;
	const char *default_algo = crypto_alg[0];
	struct appkmsg_crypto *ac;

	ac = kzalloc(sizeof(*ac), GFP_KERNEL);
	if (!ac) {
		ret = -ENOMEM;
		goto out;
	}

	if (crypto_has_alg(default_algo, 0, 0) != APPKMSG_TRUE) {
		ret = -EINVAL;
		goto err_no_alg;
	}

	ret = crypto_compressor_create(ac, default_algo);
	if (ret < 0) 
		goto err_cpr_create;

	ac->ops = &default_crypto_ops;
	crypto = ac;
	
	ret = param_create_data("compress_algo", crypto, 0644, &crypto_sysfs_ops);
	if (ret < 0)
		return ret;
	
	return 0;

err_cpr_create:
err_no_alg:
	kfree(ac);
out:
	return ret;
}

void appkmsg_crypto_exit(void)
{
	if (!crypto)
		return;

	crypto_compressor_destroy(crypto);
	kfree(crypto);
	crypto = NULL;
}


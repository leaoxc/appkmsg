/* appkmsg_base.c -- This file is part of the appkmsg project.
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

#include <linux/init.h>
#include <linux/module.h>
#include "appkmsg_params.h"
#include "appkmsg_crypto.h"
#include "appkmsg_data.h"
#include "appkmsg_cdev.h"

static int __init appkmsg_init(void)
{
	int ret;

	ret = appkmsg_params_init();
	if (ret) {
		pr_err("appkmsg_params_init error. ret=%d\n", ret);
		goto err_params_init;
	}
	
	ret = appkmsg_crypto_init();
	if (ret) {
		pr_err("appkmsg_crypto_init error. ret=%d\n", ret);
		goto err_crypto_init;
	}

	ret = appkmsg_cdevs_init();
	if (ret) {
		pr_err("appkmsg_cdevs_init error. ret=%d\n", ret);
		goto err_cdevs_init;
	}

	ret = appkmsg_data_init();
	if (ret) {
		pr_err("appkmsg_data_init error. ret=%d\n", ret);
		goto err_data_init;
	}

	return 0;

err_data_init:
	appkmsg_cdevs_exit();
err_cdevs_init:
	appkmsg_crypto_exit();
err_crypto_init:
	appkmsg_params_exit();
err_params_init:
	return ret;
}

static void __exit appkmsg_exit(void)
{
	appkmsg_data_exit();
	appkmsg_cdevs_exit();
	appkmsg_crypto_exit();
	appkmsg_params_exit();
}

module_init(appkmsg_init);
module_exit(appkmsg_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Liao jian <leaoxc@gmail.com>");

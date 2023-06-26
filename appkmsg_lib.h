/* appkmsg_lib.h -- This file is part of the appkmsg project.
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

#ifndef APPKMSG_LIB_H
#define APPKMSG_LIB_H

#define FLAG_SHIFT 24

static inline void flags_set_bit(unsigned long *f, unsigned long nr)
{
	*f &= ~BIT(nr);
	*f |= BIT(nr);
}

static inline void flags_clear_bit(unsigned long *f, unsigned long nr)
{
	*f &= ~BIT(nr);
}

static inline bool flags_test_bit(unsigned long *f, unsigned long nr)
{
	return !!(*f & BIT(nr));
}

static inline size_t flags_opr_mask(unsigned long *f, unsigned long mask)
{
	return *f & mask;
}

static inline void flags_set_size(unsigned long *f, size_t size)
{
	*f &= ~(BIT(FLAG_SHIFT) - 1);
	*f |= (BIT(FLAG_SHIFT) - 1) & size;
}

static inline size_t flags_get_size(unsigned long *f)
{
	return *f & (BIT(FLAG_SHIFT) - 1);
}

#endif /* APPKMSG_LIB_H */

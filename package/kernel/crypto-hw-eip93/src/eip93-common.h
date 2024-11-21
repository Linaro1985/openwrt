/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 - 2021
 *
 * Richard van Schagen <vschagen@icloud.com>
 * Christian Marangi <ansuelsmth@gmail.com
 */

#ifndef _EIP93_COMMON_H_
#define _EIP93_COMMON_H_

void *eip93_get_descriptor(struct eip93_device *mtk);
int eip93_put_descriptor(struct eip93_device *mtk, struct eip93_descriptor *desc);

void eip93_set_sa_record(struct sa_record *sa_record, const unsigned int keylen,
			 const u32 flags);

int eip93_parse_ctrl_stat_err(struct eip93_device *mtk, int err);

int eip93_authenc_setkey(struct crypto_aead *aead, struct sa_record *sa,
			 const u8 *authkey, unsigned int authkeylen);

#endif /* _EIP93_COMMON_H_ */

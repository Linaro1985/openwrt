/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 - 2021
 *
 * Richard van Schagen <vschagen@icloud.com>
 * Christian Marangi <ansuelsmth@gmail.com
 */
#ifndef _EIP93_HASH_H_
#define _EIP93_HASH_H_

#include <crypto/sha2.h>

#include "eip93-main.h"

struct eip93_hash_ctx {
	struct eip93_device	*mtk;
	u32			flags;

	u8			ipad[SHA256_BLOCK_SIZE] __aligned(sizeof(u32));
	u8			opad[SHA256_DIGEST_SIZE] __aligned(sizeof(u32));
};

struct eip93_hash_reqctx {
	struct eip93_device	*mtk;

	struct sa_record	*sa_record;
	dma_addr_t		sa_record_base;

	struct sa_record	*sa_record_hmac;
	dma_addr_t		sa_record_hmac_base;

	struct sa_state		*sa_state;
	dma_addr_t		sa_state_base;

	/* Don't enable HASH_FINALIZE when last block is sent */
	bool			no_finalize;

	/*
	 * EIP93 requires data to be accumulated in block of 64 bytes
	 * for intermediate hash calculation.
	 */
	u64			len;
	u32			left_last;
	struct list_head	blocks;
};

struct mkt_hash_block {
	struct list_head	list;
	u8			data[SHA256_BLOCK_SIZE] __aligned(sizeof(u32));
	dma_addr_t		data_dma;
};

struct eip93_hash_export_state {
	u64			len;
	u32			left_last;
	struct sa_state		*sa_state;
	dma_addr_t		sa_state_base;
	struct list_head	blocks;
};

void eip93_hash_handle_result(struct crypto_async_request *async, int err);

extern struct eip93_alg_template eip93_alg_md5;
extern struct eip93_alg_template eip93_alg_sha1;
extern struct eip93_alg_template eip93_alg_sha224;
extern struct eip93_alg_template eip93_alg_sha256;
extern struct eip93_alg_template eip93_alg_hmac_md5;
extern struct eip93_alg_template eip93_alg_hmac_sha1;
extern struct eip93_alg_template eip93_alg_hmac_sha224;
extern struct eip93_alg_template eip93_alg_hmac_sha256;

#endif /* _EIP93_HASH_H_ */

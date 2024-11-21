// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024
 *
 * Christian Marangi <ansuelsmth@gmail.com
 */

#include <crypto/sha1.h>
#include <crypto/sha2.h>
#include <crypto/md5.h>
#include <crypto/hmac.h>
#include <linux/dma-mapping.h>
#include <linux/delay.h>

#include "eip93-cipher.h"
#include "eip93-hash.h"
#include "eip93-main.h"
#include "eip93-common.h"
#include "eip93-regs.h"

static void eip93_hash_free_data_blocks(struct ahash_request *req)
{
	struct eip93_hash_reqctx *rctx = ahash_request_ctx(req);
	struct mkt_hash_block *block, *tmp;

	list_for_each_entry_safe(block, tmp, &rctx->blocks, list) {
		dma_unmap_single(rctx->mtk->dev, block->data_dma,
				 SHA256_BLOCK_SIZE, DMA_TO_DEVICE);
		kfree(block);
	}
}

static void eip93_hash_free_sa_record(struct ahash_request *req)
{
	struct eip93_hash_reqctx *rctx = ahash_request_ctx(req);
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	struct eip93_hash_ctx *ctx = crypto_ahash_ctx(ahash);

	if (IS_HMAC(ctx->flags)) {
		dma_unmap_single(rctx->mtk->dev, rctx->sa_record_hmac_base,
				 sizeof(*rctx->sa_record_hmac), DMA_TO_DEVICE);
		kfree(rctx->sa_record_hmac);
	}

	dma_unmap_single(rctx->mtk->dev, rctx->sa_record_base,
			 sizeof(*rctx->sa_record), DMA_TO_DEVICE);
	kfree(rctx->sa_record);
}

static void eip93_hash_free_sa_state(struct ahash_request *req)
{
	struct eip93_hash_reqctx *rctx = ahash_request_ctx(req);

	dma_unmap_single(rctx->mtk->dev, rctx->sa_state_base,
			 sizeof(*rctx->sa_state), DMA_TO_DEVICE);
	kfree(rctx->sa_state);
}

static void eip93_hash_init_sa_state_digest(u32 hash, u8 *digest)
{
	u32 sha256_init[] = { SHA256_H0, SHA256_H1, SHA256_H2, SHA256_H3,
			      SHA256_H4, SHA256_H5, SHA256_H6, SHA256_H7 };
	u32 sha224_init[] = { SHA224_H0, SHA224_H1, SHA224_H2, SHA224_H3,
			      SHA224_H4, SHA224_H5, SHA224_H6, SHA224_H7 };
	u32 sha1_init[] = { SHA1_H0, SHA1_H1, SHA1_H2, SHA1_H3, SHA1_H4 };
	u32 md5_init[] = { MD5_H0, MD5_H1, MD5_H2, MD5_H3 };

	/* Init HASH constant */
	switch (hash) {
	case EIP93_HASH_SHA256:
		memcpy(digest, sha256_init, sizeof(sha256_init));
		return;
	case EIP93_HASH_SHA224:
		memcpy(digest, sha224_init, sizeof(sha224_init));
		return;
	case EIP93_HASH_SHA1:
		memcpy(digest, sha1_init, sizeof(sha1_init));
		return;
	case EIP93_HASH_MD5:
		memcpy(digest, md5_init, sizeof(md5_init));
		return;
	default: /* Impossible */
		return;
	}
}

static struct sa_state *eip93_hash_get_sa_state(struct ahash_request *req,
						dma_addr_t *sa_state_base)
{
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	struct eip93_hash_ctx *ctx = crypto_ahash_ctx(ahash);
	struct eip93_device *mtk = ctx->mtk;
	struct sa_state *sa_state;
	int ret;

	sa_state = kzalloc(sizeof(*sa_state), GFP_KERNEL);
	if (!sa_state)
		return ERR_PTR(-ENOMEM);

	eip93_hash_init_sa_state_digest(ctx->flags & EIP93_HASH_MASK,
					sa_state->state_i_digest);

	*sa_state_base = dma_map_single(mtk->dev, sa_state,
					sizeof(*sa_state), DMA_TO_DEVICE);
	ret = dma_mapping_error(mtk->dev, *sa_state_base);
	if (ret) {
		kfree(sa_state);
		return ERR_PTR(ret);
	}

	return sa_state;
}

static int _eip93_hash_init(struct ahash_request *req, struct sa_state *sa_state,
			    dma_addr_t sa_state_base)
{
	struct eip93_hash_reqctx *rctx = ahash_request_ctx(req);
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	struct eip93_hash_ctx *ctx = crypto_ahash_ctx(ahash);
	struct sa_record *sa_record, *sa_record_hmac;
	struct eip93_device *mtk = rctx->mtk;
	int digestsize;
	int ret;

	sa_record = kzalloc(sizeof(*sa_record), GFP_KERNEL);
	if (!sa_record)
		return -ENOMEM;

	if (IS_HMAC(ctx->flags)) {
		sa_record_hmac = kzalloc(sizeof(*sa_record_hmac), GFP_KERNEL);
		if (!sa_record_hmac) {
			ret = -ENOMEM;
			goto free_sa_record;
		}
	}

	digestsize = crypto_ahash_digestsize(ahash);

	eip93_set_sa_record(sa_record, 0, ctx->flags);
	sa_record->sa_cmd0_word |= EIP93_SA_CMD_HASH_FROM_STATE;
	sa_record->sa_cmd0_word |= EIP93_SA_CMD_SAVE_HASH;
	sa_record->sa_cmd0_word &= ~EIP93_SA_CMD_OPCODE;
	sa_record->sa_cmd0_word |= FIELD_PREP(EIP93_SA_CMD_OPCODE,
					      EIP93_SA_CMD_OPCODE_BASIC_OUT_HASH);
	sa_record->sa_cmd0_word &= ~EIP93_SA_CMD_DIGEST_LENGTH;
	sa_record->sa_cmd0_word |= FIELD_PREP(EIP93_SA_CMD_DIGEST_LENGTH,
					      digestsize / sizeof(u32));

	/*
	 * HMAC special handling
	 * Enabling CMD_HMAC force the inner hash to be always finalized.
	 * This cause problems on handling message > 64 byte as we
	 * need to produce intermediate inner hash on sending intermediate
	 * 64 bytes blocks.
	 *
	 * To handle this, enable CMD_HMAC only on the last block.
	 * We make a duplicate of sa_record and on the last descriptor,
	 * we pass a dedicated sa_record with CMD_HMAC enabled to make
	 * EIP93 apply the outer hash.
	 */
	if (IS_HMAC(ctx->flags)) {
		memcpy(sa_record_hmac, sa_record, sizeof(*sa_record));
		/* Copy pre-hashed opad for HMAC */
		memcpy(sa_record_hmac->sa_o_digest, ctx->opad, SHA256_DIGEST_SIZE);

		/* Disable HMAC for hash normal sa_record */
		sa_record->sa_cmd1_word &= ~EIP93_SA_CMD_HMAC;
	}

	rctx->mtk = ctx->mtk;
	rctx->sa_record = sa_record;
	rctx->sa_record_base = dma_map_single(mtk->dev, rctx->sa_record,
					      sizeof(*rctx->sa_record),
					      DMA_TO_DEVICE);
	ret = dma_mapping_error(mtk->dev, rctx->sa_record_base);
	if (ret)
		goto free_sa_record;

	if (IS_HMAC(ctx->flags)) {
		rctx->sa_record_hmac = sa_record_hmac;
		rctx->sa_record_hmac_base = dma_map_single(mtk->dev,
							   rctx->sa_record_hmac,
							   sizeof(*rctx->sa_record_hmac),
							   DMA_TO_DEVICE);
		ret = dma_mapping_error(mtk->dev, rctx->sa_record_hmac_base);
		if (ret)
			goto free_sa_record_base;
	}

	rctx->sa_state = sa_state;
	rctx->sa_state_base = sa_state_base;

	rctx->len = 0;
	rctx->left_last = 0;
	rctx->no_finalize = false;
	INIT_LIST_HEAD(&rctx->blocks);

	return 0;

free_sa_record_base:
	dma_unmap_single(mtk->dev, rctx->sa_record_base, sizeof(*rctx->sa_record),
			 DMA_TO_DEVICE);
free_sa_record:
	kfree(sa_record);
	return ret;
}

static int eip93_hash_init(struct ahash_request *req)
{
	struct eip93_hash_reqctx *rctx = ahash_request_ctx(req);
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	struct eip93_hash_ctx *ctx = crypto_ahash_ctx(ahash);
	struct sa_state *sa_state;
	dma_addr_t sa_state_base;
	int ret;

	sa_state = eip93_hash_get_sa_state(req, &sa_state_base);
	if (IS_ERR(sa_state))
		return PTR_ERR(sa_state);

	ret = _eip93_hash_init(req, sa_state, sa_state_base);
	if (ret)
		eip93_hash_free_sa_state(req);

	/* For HMAC setup the initial block for ipad */
	if (IS_HMAC(ctx->flags)) {
		struct mkt_hash_block *block;

		block = kzalloc(sizeof(*block), GFP_KERNEL);
		if (!block) {
			eip93_hash_free_sa_record(req);
			eip93_hash_free_sa_state(req);
			return -ENOMEM;
		}

		memcpy(block->data, ctx->ipad, SHA256_BLOCK_SIZE);

		list_add(&block->list, &rctx->blocks);

		rctx->len += SHA256_BLOCK_SIZE;
	}

	return ret;
}

static void eip93_send_hash_req(struct crypto_async_request *async, dma_addr_t src_addr,
				u32 len, bool last)
{
	struct ahash_request *req = ahash_request_cast(async);
	struct eip93_hash_reqctx *rctx = ahash_request_ctx(req);
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	struct eip93_hash_ctx *ctx = crypto_ahash_ctx(ahash);
	struct eip93_device *mtk = rctx->mtk;
	struct eip93_descriptor cdesc = { };
	int ret;

	cdesc.pe_ctrl_stat_word = FIELD_PREP(EIP93_PE_CTRL_PE_READY_DES_TRING_OWN,
					     EIP93_PE_CTRL_HOST_READY);
	cdesc.sa_addr = rctx->sa_record_base;
	cdesc.arc4_addr = 0;

	cdesc.state_addr = rctx->sa_state_base;
	cdesc.src_addr = src_addr;
	cdesc.pe_length_word = FIELD_PREP(EIP93_PE_LENGTH_HOST_PE_READY,
					  EIP93_PE_LENGTH_HOST_READY);
	cdesc.pe_length_word |= FIELD_PREP(EIP93_PE_LENGTH_LENGTH,
					   len);

	cdesc.user_id |= FIELD_PREP(EIP93_PE_USER_ID_DESC_FLAGS, EIP93_DESC_HASH);

	if (last) {
		int crypto_async_idr;

		/* For last block, pass sa_record with CMD_HMAC enabled */
		if (IS_HMAC(ctx->flags))
			cdesc.sa_addr = rctx->sa_record_hmac_base;

		if (!rctx->no_finalize)
			cdesc.pe_ctrl_stat_word |= EIP93_PE_CTRL_PE_HASH_FINAL;

		spin_lock_bh(&mtk->ring->idr_lock);
		crypto_async_idr = idr_alloc(&mtk->ring->crypto_async_idr, async, 0,
					     EIP93_RING_NUM - 1, GFP_ATOMIC);
		spin_unlock_bh(&mtk->ring->idr_lock);

		cdesc.user_id |= FIELD_PREP(EIP93_PE_USER_ID_CRYPTO_IDR, (u16)crypto_async_idr) |
				 FIELD_PREP(EIP93_PE_USER_ID_DESC_FLAGS, EIP93_DESC_LAST);
	}

again:
	ret = eip93_put_descriptor(mtk, &cdesc);
	if (ret) {
		usleep_range(EIP93_RING_BUSY_DELAY,
			     EIP93_RING_BUSY_DELAY * 2);
		goto again;
	}

	/* Writing new descriptor count starts DMA action */
	writel(1, mtk->base + EIP93_REG_PE_CD_COUNT);
}

static int eip93_hash_update(struct ahash_request *req)
{
	struct crypto_async_request *async = &req->base;
	struct eip93_hash_reqctx *rctx = ahash_request_ctx(req);
	unsigned int to_consume = req->nbytes;
	struct eip93_device *mtk = rctx->mtk;
	struct mkt_hash_block *block;
	int read = 0;
	int ret;

	/* If the request is 0 length, do nothing */
	if (!to_consume)
		return 0;

	/*
	 * Check if we are at a second iteration.
	 * 1. Try to fill the first block to 64byte (if not already)
	 * 2. Send full block (if we have more data to consume)
	 */
	if (rctx->len > 0) {
		int offset = SHA256_BLOCK_SIZE - rctx->left_last;

		block = list_first_entry(&rctx->blocks,
					 struct mkt_hash_block, list);

		/* Fill the first block */
		if (rctx->left_last) {
			read += sg_pcopy_to_buffer(req->src, sg_nents(req->src),
						   block->data + offset,
						   min(to_consume, rctx->left_last),
						   0);
			to_consume -= read;
			rctx->left_last -= read;
		}

		/* Send descriptor if we have more data to consume */
		if (to_consume > 0) {
			block->data_dma = dma_map_single(mtk->dev, block->data,
							 SHA256_BLOCK_SIZE,
							 DMA_TO_DEVICE);
			ret = dma_mapping_error(mtk->dev, block->data_dma);
			if (ret)
				return ret;

			eip93_send_hash_req(async, block->data_dma,
					    SHA256_BLOCK_SIZE, false);
		}
	}

	/*
	 * Consume remaining data.
	 * 1. Loop until we consume all the data in block of 64bytes
	 * 2. Send full block of 64bytes
	 * 3. Skip sending last block for future update() or for final() to
	 *    enable HASH_FINALIZE bit.
	 */
	while (to_consume > 0) {
		int to_read = min(to_consume, SHA256_BLOCK_SIZE);

		block = kzalloc(sizeof(*block), GFP_KERNEL);
		if (!block)
			return -ENOMEM;

		read += sg_pcopy_to_buffer(req->src, sg_nents(req->src),
					   block->data, to_read,
					   read);

		list_add(&block->list, &rctx->blocks);

		to_consume -= to_read;
		rctx->left_last = SHA256_BLOCK_SIZE - to_read;

		/* Send descriptor if we have more data to consume */
		if (to_consume > 0) {
			block->data_dma = dma_map_single(mtk->dev, block->data,
							 SHA256_BLOCK_SIZE,
							 DMA_TO_DEVICE);
			ret = dma_mapping_error(mtk->dev, block->data_dma);
			if (ret)
				return ret;

			eip93_send_hash_req(async, block->data_dma,
					    SHA256_BLOCK_SIZE, false);
		}
	}

	/*
	 * Update counter with processed bytes.
	 * This is also used to check if we are at the second iteration
	 * of an update().
	 */
	rctx->len += req->nbytes;

	return 0;
}

void eip93_hash_handle_result(struct crypto_async_request *async, int err)
{
	struct ahash_request *req = ahash_request_cast(async);
	struct eip93_hash_reqctx *rctx = ahash_request_ctx(req);
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	struct eip93_hash_ctx *ctx = crypto_ahash_ctx(ahash);
	int digestsize = crypto_ahash_digestsize(ahash);
	struct sa_state *sa_state = rctx->sa_state;
	int i;

	/* Unmap and sync sa_state for host */
	dma_unmap_single(rctx->mtk->dev, rctx->sa_state_base,
			 sizeof(*sa_state), DMA_FROM_DEVICE);

	/*
	 * With no_finalize assume SHA256_DIGEST_SIZE buffer is passed.
	 * This is to handle SHA224 that have a 32 byte intermediate digest.
	 */
	if (rctx->no_finalize)
		digestsize = SHA256_DIGEST_SIZE;

	/* bytes needs to be swapped for req->result */
	if (!IS_HASH_MD5(ctx->flags)) {
		for (i = 0; i < digestsize / sizeof(u32); i++) {
			u32 *digest = (u32 *)sa_state->state_i_digest;

			digest[i] = be32_to_cpu((__be32 __force)digest[i]);
		}
	}

	memcpy(req->result, sa_state->state_i_digest, digestsize);

	kfree(sa_state);
	eip93_hash_free_data_blocks(req);
	eip93_hash_free_sa_record(req);

	ahash_request_complete(req, err);
}

static int eip93_hash_final(struct ahash_request *req)
{
	struct eip93_hash_reqctx *rctx = ahash_request_ctx(req);
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(req);
	struct eip93_hash_ctx *ctx = crypto_ahash_ctx(ahash);
	struct crypto_async_request *async = &req->base;
	struct eip93_device *mtk = rctx->mtk;
	struct mkt_hash_block *block;
	int ret;

	/* EIP93 can't handle zero bytes hash */
	if (!rctx->len && !IS_HMAC(ctx->flags)) {
		switch ((ctx->flags & EIP93_HASH_MASK)) {
		case EIP93_HASH_SHA256:
			memcpy(req->result, sha256_zero_message_hash,
			       SHA256_DIGEST_SIZE);
			break;
		case EIP93_HASH_SHA224:
			memcpy(req->result, sha224_zero_message_hash,
			       SHA224_DIGEST_SIZE);
			break;
		case EIP93_HASH_SHA1:
			memcpy(req->result, sha1_zero_message_hash,
			       SHA1_DIGEST_SIZE);
			break;
		case EIP93_HASH_MD5:
			memcpy(req->result, md5_zero_message_hash,
			       MD5_DIGEST_SIZE);
			break;
		default: /* Impossible */
			return -EINVAL;
		}

		eip93_hash_free_sa_state(req);
		eip93_hash_free_sa_record(req);

		return 0;
	}

	/* Send last block */
	block = list_first_entry(&rctx->blocks, struct mkt_hash_block, list);

	block->data_dma = dma_map_single(mtk->dev, block->data,
					 SHA256_BLOCK_SIZE, DMA_TO_DEVICE);
	ret = dma_mapping_error(mtk->dev, block->data_dma);
	if (ret)
		return ret;

	eip93_send_hash_req(async, block->data_dma,
			    SHA256_BLOCK_SIZE - rctx->left_last,
			    true);

	return -EINPROGRESS;
}

static int eip93_hash_finup(struct ahash_request *req)
{
	int ret;

	ret = eip93_hash_update(req);
	if (ret)
		return ret;

	return eip93_hash_final(req);
}

static int eip93_hash_hmac_setkey(struct crypto_ahash *ahash, const u8 *key,
				  u32 keylen)
{
	unsigned int digestsize = crypto_ahash_digestsize(ahash);
	struct crypto_tfm *tfm = crypto_ahash_tfm(ahash);
	struct eip93_hash_ctx *ctx = crypto_tfm_ctx(tfm);
	struct crypto_ahash *ahash_tfm;
	struct eip93_hash_reqctx *rctx;
	struct scatterlist sg[1];
	struct ahash_request *req;
	DECLARE_CRYPTO_WAIT(wait);
	const char *alg_name;
	int i, ret = 0;
	u8 *opad;

	switch ((ctx->flags & EIP93_HASH_MASK)) {
	case EIP93_HASH_SHA256:
		alg_name = "sha256-eip93";
		break;
	case EIP93_HASH_SHA224:
		alg_name = "sha224-eip93";
		break;
	case EIP93_HASH_SHA1:
		alg_name = "sha1-eip93";
		break;
	case EIP93_HASH_MD5:
		alg_name = "md5-eip93";
		break;
	default: /* Impossible */
		return -EINVAL;
	}

	ahash_tfm = crypto_alloc_ahash(alg_name, 0, 0);
	if (IS_ERR(ahash_tfm))
		return PTR_ERR(ahash_tfm);

	req = ahash_request_alloc(ahash_tfm, GFP_KERNEL);
	if (!req) {
		ret = -ENOMEM;
		goto err_ahash;
	}

	opad = kzalloc(SHA256_BLOCK_SIZE, GFP_KERNEL);
	if (!opad) {
		ret = -ENOMEM;
		goto err_req;
	}

	rctx = ahash_request_ctx(req);
	crypto_init_wait(&wait);
	ahash_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				   crypto_req_done, &wait);

	/* Hash the key if > SHA256_BLOCK_SIZE */
	if (keylen > SHA256_BLOCK_SIZE) {
		sg_init_one(&sg[0], key, keylen);

		ahash_request_set_crypt(req, sg, ctx->ipad, keylen);
		ret = crypto_wait_req(crypto_ahash_digest(req), &wait);

		keylen = digestsize;
	} else {
		memcpy(ctx->ipad, key, keylen);
	}

	/* Copy to opad */
	memset(ctx->ipad + keylen, 0, SHA256_BLOCK_SIZE - keylen);
	memcpy(opad, ctx->ipad, SHA256_BLOCK_SIZE);

	/* Pad with HMAC constants */
	for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
		ctx->ipad[i] ^= HMAC_IPAD_VALUE;
		opad[i] ^= HMAC_OPAD_VALUE;
	}

	sg_init_one(&sg[0], opad, SHA256_BLOCK_SIZE);

	/* Hash opad */
	ahash_request_set_crypt(req, sg, ctx->opad, SHA256_BLOCK_SIZE);
	ret = crypto_ahash_init(req);
	if (ret)
		goto exit;

	/* Disable HASH_FINALIZE for opad hash */
	rctx->no_finalize = true;

	ret = crypto_wait_req(crypto_ahash_finup(req), &wait);
	if (ret)
		goto exit;

	if (!IS_HASH_MD5(ctx->flags)) {
		u32 *opad_hash = (u32 *)ctx->opad;

		for (i = 0; i < SHA256_DIGEST_SIZE / sizeof(u32); i++)
			opad_hash[i] = (u32 __force)cpu_to_be32(opad_hash[i]);
	}

exit:
	kfree(opad);
err_req:
	ahash_request_free(req);
err_ahash:
	crypto_free_ahash(ahash_tfm);

	return ret;
}

static int eip93_hash_cra_init(struct crypto_tfm *tfm)
{
	struct eip93_hash_ctx *ctx = crypto_tfm_ctx(tfm);
	struct eip93_alg_template *tmpl = container_of(tfm->__crt_alg,
				struct eip93_alg_template, alg.ahash.halg.base);

	crypto_ahash_set_reqsize(__crypto_ahash_cast(tfm),
				 sizeof(struct eip93_hash_reqctx));

	ctx->mtk = tmpl->mtk;
	ctx->flags = tmpl->flags;

	return 0;
}

static int eip93_hash_digest(struct ahash_request *req)
{
	int ret;

	ret = eip93_hash_init(req);
	if (ret)
		return ret;

	return eip93_hash_finup(req);
}

static int eip93_hash_import(struct ahash_request *req, const void *in)
{
	struct eip93_hash_reqctx *rctx = ahash_request_ctx(req);
	const struct eip93_hash_export_state *state = in;
	int ret;

	ret = _eip93_hash_init(req, state->sa_state, state->sa_state_base);
	if (ret)
		goto err;

	rctx->len = state->len;
	rctx->left_last = state->left_last;
	memcpy(&rctx->blocks, &state->blocks, sizeof(rctx->blocks));

	return 0;
err:
	eip93_hash_free_data_blocks(req);
	eip93_hash_free_sa_state(req);
	return ret;
}

static int eip93_hash_export(struct ahash_request *req, void *out)
{
	struct eip93_hash_reqctx *rctx = ahash_request_ctx(req);
	struct eip93_hash_export_state *state = out;

	state->sa_state = rctx->sa_state;
	state->sa_state_base = rctx->sa_state_base;
	state->len = rctx->len;
	state->left_last = rctx->left_last;
	memcpy(&state->blocks, &rctx->blocks, sizeof(rctx->blocks));

	return 0;
}

struct eip93_alg_template eip93_alg_md5 = {
	.type = EIP93_ALG_TYPE_HASH,
	.flags = EIP93_HASH_MD5,
	.alg.ahash = {
		.init = eip93_hash_init,
		.update = eip93_hash_update,
		.final = eip93_hash_final,
		.finup = eip93_hash_finup,
		.digest = eip93_hash_digest,
		.export = eip93_hash_export,
		.import = eip93_hash_import,
		.halg = {
			.digestsize = MD5_DIGEST_SIZE,
			.statesize = sizeof(struct eip93_hash_export_state),
			.base = {
				.cra_name = "md5",
				.cra_driver_name = "md5-eip93",
				.cra_priority = 300,
				.cra_flags = CRYPTO_ALG_ASYNC |
						CRYPTO_ALG_KERN_DRIVER_ONLY |
						CRYPTO_ALG_ALLOCATES_MEMORY,
				.cra_blocksize = MD5_HMAC_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct eip93_hash_ctx),
				.cra_init = eip93_hash_cra_init,
				.cra_module = THIS_MODULE,
			},
		},
	},
};

struct eip93_alg_template eip93_alg_sha1 = {
	.type = EIP93_ALG_TYPE_HASH,
	.flags = EIP93_HASH_SHA1,
	.alg.ahash = {
		.init = eip93_hash_init,
		.update = eip93_hash_update,
		.final = eip93_hash_final,
		.finup = eip93_hash_finup,
		.digest = eip93_hash_digest,
		.export = eip93_hash_export,
		.import = eip93_hash_import,
		.halg = {
			.digestsize = SHA1_DIGEST_SIZE,
			.statesize = sizeof(struct eip93_hash_export_state),
			.base = {
				.cra_name = "sha1",
				.cra_driver_name = "sha1-eip93",
				.cra_priority = 300,
				.cra_flags = CRYPTO_ALG_ASYNC |
						CRYPTO_ALG_KERN_DRIVER_ONLY |
						CRYPTO_ALG_ALLOCATES_MEMORY,
				.cra_blocksize = SHA1_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct eip93_hash_ctx),
				.cra_init = eip93_hash_cra_init,
				.cra_module = THIS_MODULE,
			},
		},
	},
};

struct eip93_alg_template eip93_alg_sha224 = {
	.type = EIP93_ALG_TYPE_HASH,
	.flags = EIP93_HASH_SHA224,
	.alg.ahash = {
		.init = eip93_hash_init,
		.update = eip93_hash_update,
		.final = eip93_hash_final,
		.finup = eip93_hash_finup,
		.digest = eip93_hash_digest,
		.export = eip93_hash_export,
		.import = eip93_hash_import,
		.halg = {
			.digestsize = SHA224_DIGEST_SIZE,
			.statesize = sizeof(struct eip93_hash_export_state),
			.base = {
				.cra_name = "sha224",
				.cra_driver_name = "sha224-eip93",
				.cra_priority = 300,
				.cra_flags = CRYPTO_ALG_ASYNC |
						CRYPTO_ALG_KERN_DRIVER_ONLY |
						CRYPTO_ALG_ALLOCATES_MEMORY,
				.cra_blocksize = SHA224_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct eip93_hash_ctx),
				.cra_init = eip93_hash_cra_init,
				.cra_module = THIS_MODULE,
			},
		},
	},
};

struct eip93_alg_template eip93_alg_sha256 = {
	.type = EIP93_ALG_TYPE_HASH,
	.flags = EIP93_HASH_SHA256,
	.alg.ahash = {
		.init = eip93_hash_init,
		.update = eip93_hash_update,
		.final = eip93_hash_final,
		.finup = eip93_hash_finup,
		.digest = eip93_hash_digest,
		.export = eip93_hash_export,
		.import = eip93_hash_import,
		.halg = {
			.digestsize = SHA256_DIGEST_SIZE,
			.statesize = sizeof(struct eip93_hash_export_state),
			.base = {
				.cra_name = "sha256",
				.cra_driver_name = "sha256-eip93",
				.cra_priority = 300,
				.cra_flags = CRYPTO_ALG_ASYNC |
						CRYPTO_ALG_KERN_DRIVER_ONLY |
						CRYPTO_ALG_ALLOCATES_MEMORY,
				.cra_blocksize = SHA256_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct eip93_hash_ctx),
				.cra_init = eip93_hash_cra_init,
				.cra_module = THIS_MODULE,
			},
		},
	},
};

struct eip93_alg_template eip93_alg_hmac_md5 = {
	.type = EIP93_ALG_TYPE_HASH,
	.flags = EIP93_HASH_HMAC | EIP93_HASH_MD5,
	.alg.ahash = {
		.init = eip93_hash_init,
		.update = eip93_hash_update,
		.final = eip93_hash_final,
		.finup = eip93_hash_finup,
		.digest = eip93_hash_digest,
		.setkey = eip93_hash_hmac_setkey,
		.export = eip93_hash_export,
		.import = eip93_hash_import,
		.halg = {
			.digestsize = MD5_DIGEST_SIZE,
			.statesize = sizeof(struct eip93_hash_export_state),
			.base = {
				.cra_name = "hmac(md5)",
				.cra_driver_name = "hmac(md5-eip93)",
				.cra_priority = 300,
				.cra_flags = CRYPTO_ALG_ASYNC |
						CRYPTO_ALG_KERN_DRIVER_ONLY |
						CRYPTO_ALG_ALLOCATES_MEMORY,
				.cra_blocksize = MD5_HMAC_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct eip93_hash_ctx),
				.cra_init = eip93_hash_cra_init,
				.cra_module = THIS_MODULE,
			},
		},
	},
};

struct eip93_alg_template eip93_alg_hmac_sha1 = {
	.type = EIP93_ALG_TYPE_HASH,
	.flags = EIP93_HASH_HMAC | EIP93_HASH_SHA1,
	.alg.ahash = {
		.init = eip93_hash_init,
		.update = eip93_hash_update,
		.final = eip93_hash_final,
		.finup = eip93_hash_finup,
		.digest = eip93_hash_digest,
		.setkey = eip93_hash_hmac_setkey,
		.export = eip93_hash_export,
		.import = eip93_hash_import,
		.halg = {
			.digestsize = SHA1_DIGEST_SIZE,
			.statesize = sizeof(struct eip93_hash_export_state),
			.base = {
				.cra_name = "hmac(sha1)",
				.cra_driver_name = "hmac(sha1-eip93)",
				.cra_priority = 300,
				.cra_flags = CRYPTO_ALG_ASYNC |
						CRYPTO_ALG_KERN_DRIVER_ONLY |
						CRYPTO_ALG_ALLOCATES_MEMORY,
				.cra_blocksize = SHA1_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct eip93_hash_ctx),
				.cra_init = eip93_hash_cra_init,
				.cra_module = THIS_MODULE,
			},
		},
	},
};

struct eip93_alg_template eip93_alg_hmac_sha224 = {
	.type = EIP93_ALG_TYPE_HASH,
	.flags = EIP93_HASH_HMAC | EIP93_HASH_SHA224,
	.alg.ahash = {
		.init = eip93_hash_init,
		.update = eip93_hash_update,
		.final = eip93_hash_final,
		.finup = eip93_hash_finup,
		.digest = eip93_hash_digest,
		.setkey = eip93_hash_hmac_setkey,
		.export = eip93_hash_export,
		.import = eip93_hash_import,
		.halg = {
			.digestsize = SHA224_DIGEST_SIZE,
			.statesize = sizeof(struct eip93_hash_export_state),
			.base = {
				.cra_name = "hmac(sha224)",
				.cra_driver_name = "hmac(sha224-eip93)",
				.cra_priority = 300,
				.cra_flags = CRYPTO_ALG_ASYNC |
						CRYPTO_ALG_KERN_DRIVER_ONLY |
						CRYPTO_ALG_ALLOCATES_MEMORY,
				.cra_blocksize = SHA224_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct eip93_hash_ctx),
				.cra_init = eip93_hash_cra_init,
				.cra_module = THIS_MODULE,
			},
		},
	},
};

struct eip93_alg_template eip93_alg_hmac_sha256 = {
	.type = EIP93_ALG_TYPE_HASH,
	.flags = EIP93_HASH_HMAC | EIP93_HASH_SHA256,
	.alg.ahash = {
		.init = eip93_hash_init,
		.update = eip93_hash_update,
		.final = eip93_hash_final,
		.finup = eip93_hash_finup,
		.digest = eip93_hash_digest,
		.setkey = eip93_hash_hmac_setkey,
		.export = eip93_hash_export,
		.import = eip93_hash_import,
		.halg = {
			.digestsize = SHA256_DIGEST_SIZE,
			.statesize = sizeof(struct eip93_hash_export_state),
			.base = {
				.cra_name = "hmac(sha256)",
				.cra_driver_name = "hmac(sha256-eip93)",
				.cra_priority = 300,
				.cra_flags = CRYPTO_ALG_ASYNC |
						CRYPTO_ALG_KERN_DRIVER_ONLY |
						CRYPTO_ALG_ALLOCATES_MEMORY,
				.cra_blocksize = SHA256_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct eip93_hash_ctx),
				.cra_init = eip93_hash_cra_init,
				.cra_module = THIS_MODULE,
			},
		},
	},
};

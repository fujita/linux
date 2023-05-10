// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2021 IBM Corporation
 */

#include <linux/module.h>
#include <crypto/internal/akcipher.h>
#include <crypto/internal/ecc.h>
#include <crypto/akcipher.h>
#include <crypto/ecdh.h>
#include <crypto/rng.h>
#include <linux/asn1_decoder.h>
#include <linux/scatterlist.h>

#include "ecdsasignature.asn1.h"

extern void vli_rshift1(u64 *vli, unsigned int ndigits);
extern u64 vli_lshift(u64 *result, const u64 *in, unsigned int shift,
	       unsigned int ndigits);
extern void vli_clear(u64 *vli, unsigned int ndigits);
extern u64 vli_test_bit(const u64 *vli, unsigned int bit);
extern void vli_set(u64 *dest, const u64 *src, unsigned int ndigits);
extern void vli_mod_add(u64 *result, const u64 *left, const u64 *right,
			const u64 *mod, unsigned int ndigits);
extern void ecc_point_mult(struct ecc_point *result,
			   const struct ecc_point *point, const u64 *scalar,
		    u64 *initial_z, const struct ecc_curve *curve,
		    unsigned int ndigits);

struct ecc_ctx {
	unsigned int curve_id;
	const struct ecc_curve *curve;

	bool pub_key_set;
	u64 x[ECC_MAX_DIGITS]; /* pub key x and y coordinates */
	u64 y[ECC_MAX_DIGITS];
	u64 private_key[ECC_MAX_DIGITS];
	struct ecc_point pub_key;
};

struct ecdsa_signature_ctx {
	const struct ecc_curve *curve;
	u64 r[ECC_MAX_DIGITS];
	u64 s[ECC_MAX_DIGITS];
};

/*
 * Get the r and s components of a signature from the X509 certificate.
 */
static int ecdsa_get_signature_rs(u64 *dest, size_t hdrlen, unsigned char tag,
				  const void *value, size_t vlen, unsigned int ndigits)
{
	size_t keylen = ndigits * sizeof(u64);
	ssize_t diff = vlen - keylen;
	const char *d = value;
	u8 rs[ECC_MAX_BYTES];

	if (!value || !vlen)
		return -EINVAL;

	/* diff = 0: 'value' has exacly the right size
	 * diff > 0: 'value' has too many bytes; one leading zero is allowed that
	 *           makes the value a positive integer; error on more
	 * diff < 0: 'value' is missing leading zeros, which we add
	 */
	if (diff > 0) {
		/* skip over leading zeros that make 'value' a positive int */
		if (*d == 0) {
			vlen -= 1;
			diff--;
			d++;
		}
		if (diff)
			return -EINVAL;
	}
	if (-diff >= keylen)
		return -EINVAL;

	if (diff) {
		/* leading zeros not given in 'value' */
		memset(rs, 0, -diff);
	}

	memcpy(&rs[-diff], d, vlen);

	ecc_swap_digits((u64 *)rs, dest, ndigits);

	return 0;
}

int ecdsa_get_signature_r(void *context, size_t hdrlen, unsigned char tag,
			  const void *value, size_t vlen)
{
	struct ecdsa_signature_ctx *sig = context;

	return ecdsa_get_signature_rs(sig->r, hdrlen, tag, value, vlen,
				      sig->curve->g.ndigits);
}

int ecdsa_get_signature_s(void *context, size_t hdrlen, unsigned char tag,
			  const void *value, size_t vlen)
{
	struct ecdsa_signature_ctx *sig = context;

	return ecdsa_get_signature_rs(sig->s, hdrlen, tag, value, vlen,
				      sig->curve->g.ndigits);
}

static int _ecdsa_verify(struct ecc_ctx *ctx, const u64 *hash, const u64 *r, const u64 *s)
{
	const struct ecc_curve *curve = ctx->curve;
	unsigned int ndigits = curve->g.ndigits;
	u64 s1[ECC_MAX_DIGITS];
	u64 u1[ECC_MAX_DIGITS];
	u64 u2[ECC_MAX_DIGITS];
	u64 x1[ECC_MAX_DIGITS];
	u64 y1[ECC_MAX_DIGITS];
	struct ecc_point res = ECC_POINT_INIT(x1, y1, ndigits);

	/* 0 < r < n  and 0 < s < n */
	if (vli_is_zero(r, ndigits) || vli_cmp(r, curve->n, ndigits) >= 0 ||
	    vli_is_zero(s, ndigits) || vli_cmp(s, curve->n, ndigits) >= 0)
		return -EBADMSG;

	/* hash is given */
	pr_devel("hash : %016llx %016llx ... %016llx\n",
		 hash[ndigits - 1], hash[ndigits - 2], hash[0]);

	/* s1 = (s^-1) mod n */
	vli_mod_inv(s1, s, curve->n, ndigits);
	/* u1 = (hash * s1) mod n */
	vli_mod_mult_slow(u1, hash, s1, curve->n, ndigits);
	/* u2 = (r * s1) mod n */
	vli_mod_mult_slow(u2, r, s1, curve->n, ndigits);
	/* res = u1*G + u2 * pub_key */
	ecc_point_mult_shamir(&res, u1, &curve->g, u2, &ctx->pub_key, curve);

	/* res.x = res.x mod n (if res.x > order) */
	if (unlikely(vli_cmp(res.x, curve->n, ndigits) == 1))
		/* faster alternative for NIST p384, p256 & p192 */
		vli_sub(res.x, res.x, curve->n, ndigits);

	if (!vli_cmp(res.x, r, ndigits))
		return 0;

	return -EKEYREJECTED;
}

/*
 * Verify an ECDSA signature.
 */
static int ecdsa_verify(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct ecc_ctx *ctx = akcipher_tfm_ctx(tfm);
	size_t keylen = ctx->curve->g.ndigits * sizeof(u64);
	struct ecdsa_signature_ctx sig_ctx = {
		.curve = ctx->curve,
	};
	u8 rawhash[ECC_MAX_BYTES];
	u64 hash[ECC_MAX_DIGITS];
	unsigned char *buffer;
	ssize_t diff;
	int ret;

	if (unlikely(!ctx->pub_key_set))
		return -EINVAL;

	buffer = kmalloc(req->src_len + req->dst_len, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	sg_pcopy_to_buffer(req->src,
		sg_nents_for_len(req->src, req->src_len + req->dst_len),
		buffer, req->src_len + req->dst_len, 0);

	ret = asn1_ber_decoder(&ecdsasignature_decoder, &sig_ctx,
			       buffer, req->src_len);
	if (ret < 0) {
		printk(KERN_INFO "bad asn1 format %d\n", ret);
		goto error;
	}

	/* if the hash is shorter then we will add leading zeros to fit to ndigits */
	diff = keylen - req->dst_len;
	if (diff >= 0) {
		if (diff)
			memset(rawhash, 0, diff);
		memcpy(&rawhash[diff], buffer + req->src_len, req->dst_len);
	} else if (diff < 0) {
		/* given hash is longer, we take the left-most bytes */
		memcpy(&rawhash, buffer + req->src_len, keylen);
	}

	ecc_swap_digits((u64 *)rawhash, hash, ctx->curve->g.ndigits);

	ret = _ecdsa_verify(ctx, hash, sig_ctx.r, sig_ctx.s);

error:
	kfree(buffer);

	return ret;
}

/* Computes result = input % mod.
 * Assumes that input < mod, result != mod.
 */
static void vli_mod(u64 *result, const u64 *input, const u64 *mod,
	     unsigned int ndigits)
{
	if (vli_cmp(input, mod, ndigits) >= 0)
		vli_sub(result, input, mod, ndigits);
	else
		vli_set(result, input, ndigits);
}

/* Computes result = (left * right) % mod.
 * Assumes that left < mod and right < mod, result != mod.
 * Uses:
 *	(a * b) % m = ((a % m) * (b % m)) % m
 *	(a * b) % m = (a + a + ... + a) % m = b modular additions of (a % m)
 */
static void vli_mod_mult(u64 *result, const u64 *left, const u64 *right,
		  const u64 *mod, unsigned int ndigits)
{
	u64 t1[ECC_MAX_DIGITS], mm[ECC_MAX_DIGITS];
	u64 aa[ECC_MAX_DIGITS], bb[ECC_MAX_DIGITS];

	vli_clear(result, ndigits);
	vli_set(aa, left, ndigits);
	vli_set(bb, right, ndigits);
	vli_set(mm, mod, ndigits);

	/* aa = aa % mm */
	vli_mod(aa, aa, mm, ndigits);

	/* bb = bb % mm */
	vli_mod(bb, bb, mm, ndigits);

	while (!vli_is_zero(bb, ndigits)) {

		/* if bb is odd i.e. 0th bit set then add
		 * aa i.e. result = (result + aa) % mm
		 */
		if (vli_test_bit(bb, 0))
			vli_mod_add(result, result, aa, mm, ndigits);

		/* bb = bb / 2 = bb >> 1 */
		vli_rshift1(bb, ndigits);

		/* aa = (aa * 2) % mm */
		vli_sub(t1, mm, aa, ndigits);
		if (vli_cmp(aa, t1, ndigits) == -1)
			/* if aa < t1 then aa = aa * 2 = aa << 1*/
			vli_lshift(aa, aa, 1, ndigits);
		else
			/* if aa >= t1 then aa = aa - t1 */
			vli_sub(aa, aa, t1, ndigits);
	}
}

static inline void ecc_digits_be(const void *in, u64 *out, unsigned int ndigits) {
	const __le64 *src = (__force __le64 *)in;
	int i;

	for (i = 0; i < ndigits; i++) {
		u64 v = get_unaligned_le64(&src[i]);
		put_unaligned_be64(v, &out[ndigits - 1 - i]);
	}
}

static int ecdsa_sign(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct ecc_ctx *ctx = akcipher_tfm_ctx(tfm);
	unsigned int ndigits = ctx->curve->g.ndigits;
	unsigned int nbytes = ndigits << ECC_DIGITS_TO_BYTES_SHIFT;
	const struct ecc_curve *curve = ctx->curve;
	struct ecc_point *x1y1 = NULL;
	u64 z[ECC_MAX_DIGITS], d[ECC_MAX_DIGITS];
	u64 k[ECC_MAX_DIGITS], k_inv[ECC_MAX_DIGITS];
	u64 r[ECC_MAX_DIGITS], s[ECC_MAX_DIGITS];
	u64 dr[ECC_MAX_DIGITS], zdr[ECC_MAX_DIGITS];
	int err;
	u64 tmp[ECC_MAX_DIGITS];

	if (req->dst_len < 2 * nbytes) {
		req->dst_len = 2 * nbytes;
		return -EINVAL;
	}

	sg_pcopy_to_buffer(req->src,
		sg_nents_for_len(req->src, req->src_len),
		tmp, req->src_len, 0);

	ecc_swap_digits(tmp, z, ndigits);

	/* d */
	vli_set(d, (const u64 *)ctx->private_key, ndigits);

	/* k */
	if (crypto_get_default_rng())
		return -EFAULT;
	err = crypto_rng_get_bytes(crypto_default_rng, (u8 *)k, nbytes);
	crypto_put_default_rng();
	if (err)
		return err;

	x1y1 = ecc_alloc_point(ndigits);
	if (!x1y1)
		return -ENOMEM;

	/* (x1, y1) = k x G */
	ecc_point_mult(x1y1, &curve->g, k, NULL, curve, ndigits);

	/* r = x1 mod n */
	vli_mod(r, x1y1->x, curve->n, ndigits);

	/* k^-1 */
	vli_mod_inv(k_inv, k, curve->n, ndigits);

	/* d . r mod n */
	vli_mod_mult(dr, d, r, curve->n, ndigits);

	/* z + dr mod n */
	vli_mod_add(zdr, z, dr, curve->n, ndigits);

	/* k^-1 . ( z + dr) mod n */
	vli_mod_mult(s, k_inv, zdr, curve->n, ndigits);

	/* write signature (r,s) in dst */
	ecc_digits_be(r, tmp, ndigits);
	sg_pcopy_from_buffer(req->dst, sg_nents_for_len(req->dst, req->dst_len), tmp, nbytes, 0);
	ecc_digits_be(s, tmp, ndigits);
	sg_pcopy_from_buffer(req->dst, sg_nents_for_len(req->dst, req->dst_len), tmp, nbytes, nbytes);

	req->dst_len = 2 * nbytes;

	ecc_free_point(x1y1);
	return 0;
}

static int ecdsa_ecc_ctx_init(struct ecc_ctx *ctx, unsigned int curve_id)
{
	ctx->curve_id = curve_id;
	ctx->curve = ecc_get_curve(curve_id);
	if (!ctx->curve)
		return -EINVAL;

	return 0;
}


static void ecdsa_ecc_ctx_deinit(struct ecc_ctx *ctx)
{
	ctx->pub_key_set = false;
}

static int ecdsa_ecc_ctx_reset(struct ecc_ctx *ctx)
{
	unsigned int curve_id = ctx->curve_id;
	int ret;

	ecdsa_ecc_ctx_deinit(ctx);
	ret = ecdsa_ecc_ctx_init(ctx, curve_id);
	if (ret == 0)
		ctx->pub_key = ECC_POINT_INIT(ctx->x, ctx->y,
					      ctx->curve->g.ndigits);
	return ret;
}

/*
 * Set the public key given the raw uncompressed key data from an X509
 * certificate. The key data contain the concatenated X and Y coordinates of
 * the public key.
 */
static int ecdsa_set_pub_key(struct crypto_akcipher *tfm, const void *key, unsigned int keylen)
{
	struct ecc_ctx *ctx = akcipher_tfm_ctx(tfm);
	const unsigned char *d = key;
	const u64 *digits = (const u64 *)&d[1];
	unsigned int ndigits;
	int ret;

	ret = ecdsa_ecc_ctx_reset(ctx);
	if (ret < 0)
		return ret;

	if (keylen < 1 || (((keylen - 1) >> 1) % sizeof(u64)) != 0)
		return -EINVAL;
	/* we only accept uncompressed format indicated by '4' */
	if (d[0] != 4)
		return -EINVAL;

	keylen--;
	ndigits = (keylen >> 1) / sizeof(u64);
	if (ndigits != ctx->curve->g.ndigits)
		return -EINVAL;

	ecc_swap_digits(digits, ctx->pub_key.x, ndigits);
	ecc_swap_digits(&digits[ndigits], ctx->pub_key.y, ndigits);
	ret = ecc_is_pubkey_valid_full(ctx->curve, &ctx->pub_key);

	ctx->pub_key_set = ret == 0;

	return ret;
}

static int ecdsa_set_priv_key(struct crypto_akcipher *tfm, const void *key,
		       unsigned int keylen) {
	struct ecc_ctx *ctx = akcipher_tfm_ctx(tfm);
	const u64 *digits = (const u64 *)key;
	unsigned int ndigits;
	int ret;

	ret = ecdsa_ecc_ctx_reset(ctx);
	if (ret < 0) {
		printk(KERN_INFO "failed to reset %d\n", ret);
		return ret;
	}

	ndigits = keylen / sizeof(u64);
	if (ndigits != ctx->curve->g.ndigits) {
		printk(KERN_INFO "mismatch %d %d\n", ndigits, ctx->curve->g.ndigits);
		return -EINVAL;
	}

	if (ecc_is_key_valid(ctx->curve_id, ctx->curve->g.ndigits, digits, keylen) < 0) {
		printk(KERN_INFO "key invalid\n");
		return -EINVAL;
	}

	ecc_swap_digits(digits, ctx->private_key, ndigits);

	return 0;
}

static void ecdsa_exit_tfm(struct crypto_akcipher *tfm)
{
	struct ecc_ctx *ctx = akcipher_tfm_ctx(tfm);

	ecdsa_ecc_ctx_deinit(ctx);
}

static unsigned int ecdsa_max_size(struct crypto_akcipher *tfm)
{
	struct ecc_ctx *ctx = akcipher_tfm_ctx(tfm);

	return ctx->pub_key.ndigits << ECC_DIGITS_TO_BYTES_SHIFT;
}

static int ecdsa_nist_p384_init_tfm(struct crypto_akcipher *tfm)
{
	struct ecc_ctx *ctx = akcipher_tfm_ctx(tfm);

	return ecdsa_ecc_ctx_init(ctx, ECC_CURVE_NIST_P384);
}

static struct akcipher_alg ecdsa_nist_p384 = {
	.verify = ecdsa_verify,
	.set_pub_key = ecdsa_set_pub_key,
	.max_size = ecdsa_max_size,
	.init = ecdsa_nist_p384_init_tfm,
	.exit = ecdsa_exit_tfm,
	.base = {
		.cra_name = "ecdsa-nist-p384",
		.cra_driver_name = "ecdsa-nist-p384-generic",
		.cra_priority = 100,
		.cra_module = THIS_MODULE,
		.cra_ctxsize = sizeof(struct ecc_ctx),
	},
};

static int ecdsa_nist_p256_init_tfm(struct crypto_akcipher *tfm)
{
	struct ecc_ctx *ctx = akcipher_tfm_ctx(tfm);

	return ecdsa_ecc_ctx_init(ctx, ECC_CURVE_NIST_P256);
}

static struct akcipher_alg ecdsa_nist_p256 = {
	.sign = ecdsa_sign,
	.verify = ecdsa_verify,
	.set_pub_key = ecdsa_set_pub_key,
	.set_priv_key = ecdsa_set_priv_key,
	.max_size = ecdsa_max_size,
	.init = ecdsa_nist_p256_init_tfm,
	.exit = ecdsa_exit_tfm,
	.base = {
		.cra_name = "ecdsa-nist-p256",
		.cra_driver_name = "ecdsa-nist-p256-generic",
		.cra_priority = 100,
		.cra_module = THIS_MODULE,
		.cra_ctxsize = sizeof(struct ecc_ctx),
	},
};

static int ecdsa_nist_p192_init_tfm(struct crypto_akcipher *tfm)
{
	struct ecc_ctx *ctx = akcipher_tfm_ctx(tfm);

	return ecdsa_ecc_ctx_init(ctx, ECC_CURVE_NIST_P192);
}

static struct akcipher_alg ecdsa_nist_p192 = {
	.verify = ecdsa_verify,
	.set_pub_key = ecdsa_set_pub_key,
	.max_size = ecdsa_max_size,
	.init = ecdsa_nist_p192_init_tfm,
	.exit = ecdsa_exit_tfm,
	.base = {
		.cra_name = "ecdsa-nist-p192",
		.cra_driver_name = "ecdsa-nist-p192-generic",
		.cra_priority = 100,
		.cra_module = THIS_MODULE,
		.cra_ctxsize = sizeof(struct ecc_ctx),
	},
};
static bool ecdsa_nist_p192_registered;

static int __init ecdsa_init(void)
{
	int ret;

	/* NIST p192 may not be available in FIPS mode */
	ret = crypto_register_akcipher(&ecdsa_nist_p192);
	ecdsa_nist_p192_registered = ret == 0;

	ret = crypto_register_akcipher(&ecdsa_nist_p256);
	if (ret)
		goto nist_p256_error;

	ret = crypto_register_akcipher(&ecdsa_nist_p384);
	if (ret)
		goto nist_p384_error;

	return 0;

nist_p384_error:
	crypto_unregister_akcipher(&ecdsa_nist_p256);

nist_p256_error:
	if (ecdsa_nist_p192_registered)
		crypto_unregister_akcipher(&ecdsa_nist_p192);
	return ret;
}

static void __exit ecdsa_exit(void)
{
	if (ecdsa_nist_p192_registered)
		crypto_unregister_akcipher(&ecdsa_nist_p192);
	crypto_unregister_akcipher(&ecdsa_nist_p256);
	crypto_unregister_akcipher(&ecdsa_nist_p384);
}

subsys_initcall(ecdsa_init);
module_exit(ecdsa_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Stefan Berger <stefanb@linux.ibm.com>");
MODULE_DESCRIPTION("ECDSA generic algorithm");
MODULE_ALIAS_CRYPTO("ecdsa-generic");

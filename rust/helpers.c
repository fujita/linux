// SPDX-License-Identifier: GPL-2.0
/*
 * Non-trivial C macros cannot be used in Rust. Similarly, inlined C functions
 * cannot be called either. This file explicitly creates functions ("helpers")
 * that wrap those so that they can be called from Rust.
 *
 * Even though Rust kernel modules should never use directly the bindings, some
 * of these helpers need to be exported because Rust generics and inlined
 * functions may not get their code generated in the crate where they are
 * defined. Other helpers, called from non-inline functions, may not be
 * exported, in principle. However, in general, the Rust compiler does not
 * guarantee codegen will be performed for a non-inline function either.
 * Therefore, this file exports all the helpers. In the future, this may be
 * revisited to reduce the number of exports after the compiler is informed
 * about the places codegen is required.
 *
 * All symbols are exported as GPL-only to guarantee no GPL-only feature is
 * accidentally exposed.
 */

#include <crypto/aead.h>
#include <crypto/akcipher.h>
#include <crypto/hash.h>
#include <crypto/kpp.h>
#include <crypto/rng.h>
#include <crypto/skcipher.h>
#include <linux/bug.h>
#include <linux/build_bug.h>
#include <linux/err.h>
#include <linux/refcount.h>
#include <linux/mutex.h>
#include <linux/scatterlist.h>
#include <linux/spinlock.h>
#include <linux/sched/signal.h>
#include <linux/wait.h>
#include <net/tls.h>
#include <uapi/linux/tls.h>

void rust_helper_crypto_free_aead(struct crypto_aead *tfm) {
	crypto_free_aead(tfm);
}
EXPORT_SYMBOL_GPL(rust_helper_crypto_free_aead);

void rust_helper_aead_request_set_crypt(struct aead_request *req, struct scatterlist *src,
                            struct scatterlist *dst, unsigned int cryptlen, u8 *iv) {
	aead_request_set_crypt(req, src, dst, cryptlen, iv);
}
EXPORT_SYMBOL_GPL(rust_helper_aead_request_set_crypt);

void rust_helper_aead_request_set_ad(struct aead_request *req,
	unsigned int assoclen) {
	aead_request_set_ad(req, assoclen);
}
EXPORT_SYMBOL_GPL(rust_helper_aead_request_set_ad);

void rust_helper_aead_request_set_callback(struct aead_request *req,
    u32 flags, crypto_completion_t compl, void *data)
{
	aead_request_set_callback(req, flags, compl, data);
}
EXPORT_SYMBOL_GPL(rust_helper_aead_request_set_callback);

struct aead_request *rust_helper_aead_request_alloc(struct crypto_aead *tfm, gfp_t gfp) {
	return aead_request_alloc(tfm, gfp);
}
EXPORT_SYMBOL_GPL(rust_helper_aead_request_alloc);

void rust_helper_akcipher_request_set_crypt(struct akcipher_request *req,
                                              struct scatterlist *src,
                                              struct scatterlist *dst,
                                              unsigned int src_len,
                                              unsigned int dst_len) {
	akcipher_request_set_crypt(req, src, dst, src_len, dst_len);
}
EXPORT_SYMBOL_GPL(rust_helper_akcipher_request_set_crypt);

void rust_helper_akcipher_request_set_callback(struct akcipher_request *req,
	                                         u32 flgs,
		                                 crypto_completion_t cmpl,
                                                 void *data) {
	return akcipher_request_set_callback(req, flgs, cmpl, data)											;
}
EXPORT_SYMBOL_GPL(rust_helper_akcipher_request_set_callback);

int rust_helper_crypto_akcipher_set_pub_key(struct crypto_akcipher *tfm,
                                              const void *key,
                                              unsigned int keylen) {
	return crypto_akcipher_set_pub_key(tfm, key, keylen);
}
EXPORT_SYMBOL_GPL(rust_helper_crypto_akcipher_set_pub_key);

int rust_helper_crypto_akcipher_set_priv_key(struct crypto_akcipher *tfm,
                                               const void *key,
                                               unsigned int keylen) {
	return crypto_akcipher_set_priv_key(tfm, key, keylen);
}
EXPORT_SYMBOL_GPL(rust_helper_crypto_akcipher_set_priv_key);

int rust_helper_crypto_akcipher_sign(struct akcipher_request *req) {
	return crypto_akcipher_sign(req);
}
EXPORT_SYMBOL_GPL(rust_helper_crypto_akcipher_sign);

int rust_helper_crypto_akcipher_verify(struct akcipher_request *req) {
	return crypto_akcipher_verify(req);
}
EXPORT_SYMBOL_GPL(rust_helper_crypto_akcipher_verify);

void rust_helper_crypto_free_akcipher(struct crypto_akcipher *tfm)
{
	crypto_free_akcipher(tfm);
}
EXPORT_SYMBOL_GPL(rust_helper_crypto_free_akcipher);

struct akcipher_request *rust_helper_akcipher_request_alloc(struct crypto_akcipher *tfm, gfp_t gfp) {
	return akcipher_request_alloc(tfm, gfp);
}
EXPORT_SYMBOL_GPL(rust_helper_akcipher_request_alloc);

void rust_helper_akcipher_request_free(struct akcipher_request *req) {
	akcipher_request_free(req);
}
EXPORT_SYMBOL_GPL(rust_helper_akcipher_request_free);

void rust_helper_crypto_free_shash(struct crypto_shash *tfm)
{
	crypto_free_shash(tfm);
}
EXPORT_SYMBOL_GPL(rust_helper_crypto_free_shash);

unsigned int rust_helper_crypto_shash_digestsize(struct crypto_shash *tfm)
{
    return crypto_shash_digestsize(tfm);
}
EXPORT_SYMBOL_GPL(rust_helper_crypto_shash_digestsize);

unsigned int rust_helper_crypto_shash_descsize(struct crypto_shash *tfm)
{
    return crypto_shash_descsize(tfm);
}
EXPORT_SYMBOL_GPL(rust_helper_crypto_shash_descsize);

int rust_helper_crypto_shash_init(struct shash_desc *desc) {
	return crypto_shash_init(desc);
}
EXPORT_SYMBOL_GPL(rust_helper_crypto_shash_init);

struct kpp_request *rust_helper_kpp_request_alloc(struct crypto_kpp *tfm, gfp_t gfp) {
	return kpp_request_alloc(tfm, gfp);
}
EXPORT_SYMBOL_GPL(rust_helper_kpp_request_alloc);

void rust_helper_kpp_request_free(struct kpp_request *req) {
	kpp_request_free(req);
}
EXPORT_SYMBOL_GPL(rust_helper_kpp_request_free);

void rust_helper_kpp_request_set_input(struct kpp_request *req,
                                         struct scatterlist *input,
                                         unsigned int input_len)
{
	kpp_request_set_input(req, input, input_len);
}
EXPORT_SYMBOL_GPL(rust_helper_kpp_request_set_input);

void rust_helper_kpp_request_set_output(struct kpp_request *req,
                                          struct scatterlist *output,
                                          unsigned int output_len)
{
	kpp_request_set_output(req, output, output_len);
}
EXPORT_SYMBOL_GPL(rust_helper_kpp_request_set_output);

void rust_helper_kpp_request_set_callback(struct kpp_request *req,
                                            u32 flgs,
                                            crypto_completion_t cmpl,
                                            void *data)
{
	kpp_request_set_callback(req, flgs, cmpl, data);
}
EXPORT_SYMBOL_GPL(rust_helper_kpp_request_set_callback);

int rust_helper_crypto_kpp_set_secret(struct crypto_kpp *tfm,
    const void *buffer, unsigned int len) {
	return crypto_kpp_set_secret(tfm, buffer, len);
}
EXPORT_SYMBOL_GPL(rust_helper_crypto_kpp_set_secret);

int rust_helper_crypto_kpp_generate_public_key(struct kpp_request *req) {
	return crypto_kpp_generate_public_key(req);
}
EXPORT_SYMBOL_GPL(rust_helper_crypto_kpp_generate_public_key);

int rust_helper_crypto_kpp_compute_shared_secret(struct kpp_request *req) {
	return crypto_kpp_compute_shared_secret(req);
}
EXPORT_SYMBOL_GPL(rust_helper_crypto_kpp_compute_shared_secret);

void rust_helper_crypto_free_kpp(struct crypto_kpp *tfm)
{
    crypto_free_kpp(tfm);
}
EXPORT_SYMBOL_GPL(rust_helper_crypto_free_kpp);

int rust_helper_crypto_rng_get_bytes(struct crypto_rng *tfm, u8 *rdata, unsigned int dlen) {
	return crypto_rng_get_bytes(tfm, rdata, dlen);
}
EXPORT_SYMBOL_GPL(rust_helper_crypto_rng_get_bytes);

void rust_helper_crypto_free_sync_skcipher(struct crypto_sync_skcipher *tfm) {
	crypto_free_sync_skcipher(tfm);
}
EXPORT_SYMBOL_GPL(rust_helper_crypto_free_sync_skcipher);

struct skcipher_request *rust_helper_skcipher_request_alloc(
	struct crypto_skcipher *tfm, gfp_t gfp)
{
	return skcipher_request_alloc(tfm, gfp);
}
EXPORT_SYMBOL_GPL(rust_helper_skcipher_request_alloc);

void rust_helper_skcipher_request_set_tfm(struct skcipher_request *req,
	struct crypto_skcipher *tfm) {
	return skcipher_request_set_tfm(req, tfm);
}
EXPORT_SYMBOL_GPL(rust_helper_skcipher_request_set_tfm);

void rust_helper_skcipher_request_set_callback(struct skcipher_request *req,
	u32 flags, crypto_completion_t compl, void *data) {
	skcipher_request_set_callback(req, flags, compl, data);
}
EXPORT_SYMBOL_GPL(rust_helper_skcipher_request_set_callback);

void rust_helper_skcipher_request_zero(struct skcipher_request *req) {
	skcipher_request_zero(req);
}
EXPORT_SYMBOL_GPL(rust_helper_skcipher_request_zero);

void rust_helper_skcipher_request_free(struct skcipher_request *req) {
	skcipher_request_free(req);
}
EXPORT_SYMBOL_GPL(rust_helper_skcipher_request_free);

void rust_helper_skcipher_request_set_crypt(struct skcipher_request *req,
	struct scatterlist *src, struct scatterlist *dst,
	unsigned int cryptlen, void *iv) {
	skcipher_request_set_crypt(req, src, dst, cryptlen, iv);
}
EXPORT_SYMBOL_GPL(rust_helper_skcipher_request_set_crypt);

__noreturn void rust_helper_BUG(void)
{
	BUG();
}
EXPORT_SYMBOL_GPL(rust_helper_BUG);

void rust_helper_mutex_lock(struct mutex *lock)
{
	mutex_lock(lock);
}
EXPORT_SYMBOL_GPL(rust_helper_mutex_lock);

void rust_helper_sg_set_buf(struct scatterlist *sg, const void *buf, unsigned int buflen) {
	sg_set_buf(sg, buf, buflen);
}
EXPORT_SYMBOL_GPL(rust_helper_sg_set_buf);

void rust_helper___spin_lock_init(spinlock_t *lock, const char *name,
				  struct lock_class_key *key)
{
#ifdef CONFIG_DEBUG_SPINLOCK
	__raw_spin_lock_init(spinlock_check(lock), name, key, LD_WAIT_CONFIG);
#else
	spin_lock_init(lock);
#endif
}
EXPORT_SYMBOL_GPL(rust_helper___spin_lock_init);

void rust_helper_spin_lock(spinlock_t *lock)
{
	spin_lock(lock);
}
EXPORT_SYMBOL_GPL(rust_helper_spin_lock);

void rust_helper_spin_unlock(spinlock_t *lock)
{
	spin_unlock(lock);
}
EXPORT_SYMBOL_GPL(rust_helper_spin_unlock);

void rust_helper_init_wait(struct wait_queue_entry *wq_entry)
{
	init_wait(wq_entry);
}
EXPORT_SYMBOL_GPL(rust_helper_init_wait);

int rust_helper_signal_pending(struct task_struct *t)
{
	return signal_pending(t);
}
EXPORT_SYMBOL_GPL(rust_helper_signal_pending);

refcount_t rust_helper_REFCOUNT_INIT(int n)
{
	return (refcount_t)REFCOUNT_INIT(n);
}
EXPORT_SYMBOL_GPL(rust_helper_REFCOUNT_INIT);

void rust_helper_refcount_inc(refcount_t *r)
{
	refcount_inc(r);
}
EXPORT_SYMBOL_GPL(rust_helper_refcount_inc);

bool rust_helper_refcount_dec_and_test(refcount_t *r)
{
	return refcount_dec_and_test(r);
}
EXPORT_SYMBOL_GPL(rust_helper_refcount_dec_and_test);

__force void *rust_helper_ERR_PTR(long err)
{
	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(rust_helper_ERR_PTR);

bool rust_helper_IS_ERR(__force const void *ptr)
{
	return IS_ERR(ptr);
}
EXPORT_SYMBOL_GPL(rust_helper_IS_ERR);

long rust_helper_PTR_ERR(__force const void *ptr)
{
	return PTR_ERR(ptr);
}
EXPORT_SYMBOL_GPL(rust_helper_PTR_ERR);

struct task_struct *rust_helper_get_current(void)
{
	return current;
}
EXPORT_SYMBOL_GPL(rust_helper_get_current);

void rust_helper_get_task_struct(struct task_struct *t)
{
	get_task_struct(t);
}
EXPORT_SYMBOL_GPL(rust_helper_get_task_struct);

void rust_helper_put_task_struct(struct task_struct *t)
{
	put_task_struct(t);
}
EXPORT_SYMBOL_GPL(rust_helper_put_task_struct);

/*
 * We use `bindgen`'s `--size_t-is-usize` option to bind the C `size_t` type
 * as the Rust `usize` type, so we can use it in contexts where Rust
 * expects a `usize` like slice (array) indices. `usize` is defined to be
 * the same as C's `uintptr_t` type (can hold any pointer) but not
 * necessarily the same as `size_t` (can hold the size of any single
 * object). Most modern platforms use the same concrete integer type for
 * both of them, but in case we find ourselves on a platform where
 * that's not true, fail early instead of risking ABI or
 * integer-overflow issues.
 *
 * If your platform fails this assertion, it means that you are in
 * danger of integer-overflow bugs (even if you attempt to remove
 * `--size_t-is-usize`). It may be easiest to change the kernel ABI on
 * your platform such that `size_t` matches `uintptr_t` (i.e., to increase
 * `size_t`, because `uintptr_t` has to be at least as big as `size_t`).
 */
static_assert(
	sizeof(size_t) == sizeof(uintptr_t) &&
	__alignof__(size_t) == __alignof__(uintptr_t),
	"Rust code expects C `size_t` to match Rust `usize`"
);

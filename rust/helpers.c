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
 *
 * Sorted alphabetically.
 */

#include <kunit/test-bug.h>
#include <linux/bug.h>
#include <linux/build_bug.h>
#include <linux/buffer_head.h>
#include <linux/err.h>
#include <linux/errname.h>
#include <linux/fs.h>
#include <linux/iversion.h>
#include <linux/mutex.h>
#include <linux/pagemap.h>
#include <linux/refcount.h>
#include <linux/sched/signal.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

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

const char *rust_helper_errname(int err)
{
	return errname(err);
}
EXPORT_SYMBOL_GPL(rust_helper_errname);

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

struct kunit *rust_helper_kunit_get_current_test(void)
{
	return kunit_get_current_test();
}
EXPORT_SYMBOL_GPL(rust_helper_kunit_get_current_test);

void rust_helper_init_work_with_key(struct work_struct *work, work_func_t func,
				    bool onstack, const char *name,
				    struct lock_class_key *key)
{
	__init_work(work, onstack);
	work->data = (atomic_long_t)WORK_DATA_INIT();
	lockdep_init_map(&work->lockdep_map, name, key, 0);
	INIT_LIST_HEAD(&work->entry);
	work->func = func;
}
EXPORT_SYMBOL_GPL(rust_helper_init_work_with_key);

struct buffer_head *rust_helper_sb_getblk(struct super_block *sb,
					  sector_t block)
{
	return sb_getblk(sb, block);
}
EXPORT_SYMBOL_GPL(rust_helper_sb_getblk);

struct buffer_head *rust_helper_sb_bread(struct super_block *sb, sector_t block)
{
	return __bread_gfp(sb->s_bdev, block, sb->s_blocksize, __GFP_MOVABLE);
}
EXPORT_SYMBOL_GPL(rust_helper_sb_bread);

int rust_helper_bh_read(struct buffer_head *bh, blk_opf_t op_flags)
{
	return bh_read(bh, op_flags);
}
EXPORT_SYMBOL_GPL(rust_helper_bh_read);

void rust_helper_brelse(struct buffer_head *bh)
{
	brelse(bh);
}
EXPORT_SYMBOL_GPL(rust_helper_brelse);

void *rust_helper_alloc_inode_sb(struct super_block *sb,
				 struct kmem_cache *cache, gfp_t gfp)
{
	return alloc_inode_sb(sb, cache, gfp);
}
EXPORT_SYMBOL_GPL(rust_helper_alloc_inode_sb);

void rust_helper_i_size_write(struct inode *inode, loff_t i_size)
{
	i_size_write(inode, i_size);
}
EXPORT_SYMBOL_GPL(rust_helper_i_size_write);

void rust_helper_inode_set_iversion(struct inode *inode, u64 val)
{
	inode_set_iversion(inode, val);
}
EXPORT_SYMBOL_GPL(rust_helper_inode_set_iversion);

uid_t rust_helper_i_uid_read(struct inode *inode)
{
	return i_uid_read(inode);
}
EXPORT_SYMBOL_GPL(rust_helper_i_uid_read);

gid_t rust_helper_i_gid_read(struct inode *inode)
{
	return i_gid_read(inode);
}
EXPORT_SYMBOL_GPL(rust_helper_i_gid_read);

void rust_helper_i_uid_write(struct inode *inode, uid_t uid)
{
	i_uid_write(inode, uid);
}
EXPORT_SYMBOL_GPL(rust_helper_i_uid_write);

void rust_helper_i_gid_write(struct inode *inode, gid_t gid)
{
	i_gid_write(inode, gid);
}
EXPORT_SYMBOL_GPL(rust_helper_i_gid_write);

time64_t rust_helper_inode_get_atime_sec(const struct inode *inode)
{
	return inode_get_atime_sec(inode);
}
EXPORT_SYMBOL_GPL(rust_helper_inode_get_atime_sec);

struct timespec64 rust_helper_inode_set_atime(struct inode *inode, time64_t sec,
					      long nsec)
{
	return inode_set_atime(inode, sec, nsec);
}
EXPORT_SYMBOL_GPL(rust_helper_inode_set_atime);

time64_t rust_helper_inode_get_mtime_sec(const struct inode *inode)
{
	return inode_get_mtime_sec(inode);
}
EXPORT_SYMBOL_GPL(rust_helper_inode_get_mtime_sec);

struct timespec64 rust_helper_inode_set_mtime(struct inode *inode, time64_t sec,
					      long nsec)
{
	return inode_set_mtime(inode, sec, nsec);
}
EXPORT_SYMBOL_GPL(rust_helper_inode_set_mtime);

struct timespec64 rust_helper_inode_set_mtime_to_ts(struct inode *inode,
						    struct timespec64 ts)
{
	return inode_set_mtime_to_ts(inode, ts);
}
EXPORT_SYMBOL_GPL(rust_helper_inode_set_mtime_to_ts);

time64_t rust_helper_inode_get_ctime_sec(const struct inode *inode)
{
	return inode_get_ctime_sec(inode);
}
EXPORT_SYMBOL_GPL(rust_helper_inode_get_ctime_sec);

struct timespec64 rust_helper_inode_set_ctime(struct inode *inode, time64_t sec,
					      long nsec)
{
	return inode_set_ctime(inode, sec, nsec);
}
EXPORT_SYMBOL_GPL(rust_helper_inode_set_ctime);

unsigned long rust_helper_dir_pages(struct inode *inode)
{
	return dir_pages(inode);
}
EXPORT_SYMBOL_GPL(rust_helper_dir_pages);

void rust_helper_folio_put(struct folio *folio)
{
	folio_put(folio);
}
EXPORT_SYMBOL_GPL(rust_helper_folio_put);

unsigned long rust_helper_offset_in_folio(struct folio *folio, void *addr)
{
	return offset_in_folio(folio, addr);
}
EXPORT_SYMBOL_GPL(rust_helper_offset_in_folio);

struct folio *rust_helper_filemap_grab_folio(struct address_space *mapping,
					     pgoff_t index)
{
	return filemap_grab_folio(mapping, index);
}
EXPORT_SYMBOL_GPL(rust_helper_filemap_grab_folio);

struct folio *rust_helper_read_mapping_folio(struct address_space *mapping,
					     pgoff_t index, struct file *file)
{
	return read_mapping_folio(mapping, index, file);
}
EXPORT_SYMBOL_GPL(rust_helper_read_mapping_folio);

void *rust_helper_kmap_local_folio(struct folio *folio, size_t offset)
{
	return kmap_local_folio(folio, offset);
}
EXPORT_SYMBOL_GPL(rust_helper_kmap_local_folio);

unsigned long *rust_helper_folio_flags(struct folio *folio, unsigned n)
{
	return folio_flags(folio, n);
}
EXPORT_SYMBOL_GPL(rust_helper_folio_flags);

bool rust_helper_folio_test_checked(struct folio *folio)
{
	return folio_test_checked(folio);
}
EXPORT_SYMBOL_GPL(rust_helper_folio_test_checked);

void rust_helper_folio_set_checked(struct folio *folio)
{
	folio_set_checked(folio);
}
EXPORT_SYMBOL_GPL(rust_helper_folio_set_checked);

void rust_helper_folio_set_error(struct folio *folio)
{
	folio_set_error(folio);
}
EXPORT_SYMBOL_GPL(rust_helper_folio_set_error);

void rust_helper_folio_release_kmap(struct folio *folio, void *addr)
{
	folio_release_kmap(folio, addr);
}
EXPORT_SYMBOL_GPL(rust_helper_folio_release_kmap);

size_t rust_helper_folio_size(struct folio *folio)
{
	return folio_size(folio);
}
EXPORT_SYMBOL_GPL(rust_helper_folio_size);

void rust_helper_folio_lock(struct folio *folio)
{
	folio_lock(folio);
}
EXPORT_SYMBOL_GPL(rust_helper_folio_lock);

void rust_helper_folio_unlock(struct folio *folio)
{
	folio_unlock(folio);
}
EXPORT_SYMBOL_GPL(rust_helper_folio_unlock);

loff_t rust_helper_folio_pos(struct folio *folio)
{
	return folio_pos(folio);
}
EXPORT_SYMBOL_GPL(rust_helper_folio_pos);

struct inode *rust_helper_d_inode(const struct dentry *dentry)
{
	return d_inode(dentry);
}
EXPORT_SYMBOL_GPL(rust_helper_d_inode);

bool rust_helper_inode_eq_iversion(const struct inode *inode, u64 old)
{
	return inode_eq_iversion(inode, old);
}
EXPORT_SYMBOL_GPL(rust_helper_inode_eq_iversion);

bool rust_helper_dir_emit(struct dir_context *ctx, const char *name,
			  int namelen, u64 ino, unsigned type)
{
	return dir_emit(ctx, name, namelen, ino, type);
}
EXPORT_SYMBOL_GPL(rust_helper_dir_emit);

void rust_helper_map_bh(struct buffer_head *bh, struct super_block *sb,
			sector_t block)
{
	map_bh(bh, sb, block);
}
EXPORT_SYMBOL_GPL(rust_helper_map_bh);

void rust_helper_set_buffer_new(struct buffer_head *bh)
{
	set_buffer_new(bh);
}
EXPORT_SYMBOL_GPL(rust_helper_set_buffer_new);

void rust_helper_set_buffer_boundary(struct buffer_head *bh)
{
	set_buffer_boundary(bh);
}
EXPORT_SYMBOL_GPL(rust_helper_set_buffer_boundary);

void rust_helper_filemap_invalidate_lock(struct address_space *mapping)
{
	filemap_invalidate_lock(mapping);
}
EXPORT_SYMBOL_GPL(rust_helper_filemap_invalidate_lock);

void rust_helper_filemap_invalidate_unlock(struct address_space *mapping)
{
	filemap_invalidate_unlock(mapping);
}
EXPORT_SYMBOL_GPL(rust_helper_filemap_invalidate_unlock);

void rust_helper_mark_inode_dirty(struct inode *inode)
{
	mark_inode_dirty(inode);
}
EXPORT_SYMBOL_GPL(rust_helper_mark_inode_dirty);

loff_t rust_helper_i_size_read(const struct inode *inode)
{
	return i_size_read(inode);
}
EXPORT_SYMBOL_GPL(rust_helper_i_size_read);

unsigned long rust_helper_find_next_zero_bit_le(const void *addr,
						unsigned long size,
						unsigned long offset)
{
	return find_next_zero_bit_le(addr, size, offset);
}
EXPORT_SYMBOL_GPL(rust_helper_find_next_zero_bit_le);

int rust_helper_test_and_set_bit_le(int nr, void *addr)
{
	return test_and_set_bit_le(nr, addr);
}
EXPORT_SYMBOL_GPL(rust_helper_test_and_set_bit_le);

void rust_helper_inode_inc_link_count(struct inode *inode)
{
	inode_inc_link_count(inode);
}
EXPORT_SYMBOL_GPL(rust_helper_inode_inc_link_count);

void rust_helper_inode_dec_link_count(struct inode *inode)
{
	inode_dec_link_count(inode);
}
EXPORT_SYMBOL_GPL(rust_helper_inode_dec_link_count);

void rust_helper_inode_inc_iversion(struct inode *inode)
{
	inode_inc_iversion(inode);
}
EXPORT_SYMBOL_GPL(rust_helper_inode_inc_iversion);

void rust_helper_kunmap_local(void *addr)
{
	kunmap_local(addr);
}
EXPORT_SYMBOL_GPL(rust_helper_kunmap_local);
/*
 * `bindgen` binds the C `size_t` type as the Rust `usize` type, so we can
 * use it in contexts where Rust expects a `usize` like slice (array) indices.
 * `usize` is defined to be the same as C's `uintptr_t` type (can hold any
 * pointer) but not necessarily the same as `size_t` (can hold the size of any
 * single object). Most modern platforms use the same concrete integer type for
 * both of them, but in case we find ourselves on a platform where
 * that's not true, fail early instead of risking ABI or
 * integer-overflow issues.
 *
 * If your platform fails this assertion, it means that you are in
 * danger of integer-overflow bugs (even if you attempt to add
 * `--no-size_t-is-usize`). It may be easiest to change the kernel ABI on
 * your platform such that `size_t` matches `uintptr_t` (i.e., to increase
 * `size_t`, because `uintptr_t` has to be at least as big as `size_t`).
 */
static_assert(sizeof(size_t) == sizeof(uintptr_t) &&
		      __alignof__(size_t) == __alignof__(uintptr_t),
	      "Rust code expects C `size_t` to match Rust `usize`");

// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2024 FUJITA Tomonori <fujita.tomonori@gmail.com>

//! ext2 clone in Rust

#![recursion_limit = "256"]
use core::ffi::{c_char, c_int, c_uint, c_ulong, c_void};
use kernel::bindings::{self, loff_t};
use kernel::c_str;
use kernel::prelude::*;
use kernel::types::Opaque;
use kernel::{new_spinlock, pin_init};

use crate::{balloc::*, defs::*, dir::*, ialloc::*, inode::*};

mod balloc;
mod defs;
mod dir;
mod file;
mod ialloc;
mod inode;
mod namei;

module! {
    type: Ext2Rust,
    name: "ext2rust",
    author: "FUJITA Tomonori <fujita.tomonori@gmail.com>",
    description: "Rust clone of ext2",
    license: "GPL v2",
}

struct Ext2Rust {
    ext2_inode_cachep: *mut bindings::kmem_cache,
}

//
unsafe impl Send for Ext2Rust {}

//
unsafe impl Sync for Ext2Rust {}

unsafe extern "C" fn ext2_put_super(sb: *mut bindings::super_block) {
    let sbi: Box<Ext2SbInfo> = unsafe { Box::from_raw((*sb).s_fs_info as _) };

    ext2_sync_super(sb, 1);

    unsafe {
        bindings::brelse((*sbi).s_sbh);
        for i in 0..sbi.s_gdb_count {
            bindings::brelse(sbi.s_group_desc[i as usize]);
        }
        (*sb).s_fs_info = core::ptr::null_mut();
    }
}

unsafe extern "C" fn ext2_alloc_inode(sb: *mut bindings::super_block) -> *mut bindings::inode {
    let ei = unsafe {
        bindings::alloc_inode_sb(
            sb,
            __MOD.as_mut().unwrap().ext2_inode_cachep,
            bindings::GFP_KERNEL,
        ) as *mut Ext2InodeInfo
    };
    if ei.is_null() {
        core::ptr::null_mut()
    } else {
        unsafe {
            bindings::inode_set_iversion((*ei).vfs_inode.get(), 1);
            (*ei).vfs_inode.get()
        }
    }
}

unsafe extern "C" fn ext2_free_in_core_inode(inode: *mut bindings::inode) {
    let ei = unsafe { container_of!(inode, Ext2InodeInfo, vfs_inode) };
    unsafe {
        bindings::kmem_cache_free(__MOD.as_mut().unwrap().ext2_inode_cachep, ei as *mut c_void);
    }
}

unsafe extern "C" fn init_once(foo: *mut c_void) {
    let ei = foo as *mut Ext2InodeInfo;
    unsafe { bindings::inode_init_once((*ei).vfs_inode.get()) };
}

const EXT2_SOPS: bindings::super_operations = bindings::super_operations {
    alloc_inode: Some(ext2_alloc_inode),
    free_inode: Some(ext2_free_in_core_inode),
    write_inode: Some(ext2_write_inode),
    put_super: Some(ext2_put_super),
    sync_fs: Some(ext2_sync_fs),
    statfs: Some(ext2_statfs),
    ..unsafe { core::mem::MaybeUninit::<bindings::super_operations>::zeroed().assume_init() }
};

fn init_inodecache() -> Result<*mut bindings::kmem_cache> {
    let p = unsafe {
        bindings::kmem_cache_create(
            c_str!("ext2_rust_inode_cache").as_char_ptr(),
            core::mem::size_of::<Ext2InodeInfo>() as u32,
            0,
            SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD | SLAB_ACCOUNT,
            Some(init_once),
        )
    };
    if p.is_null() {
        return Err(kernel::error::code::ENOMEM);
    } else {
        Ok(p)
    }
}

fn destroy_inodecache(cachep: *mut bindings::kmem_cache) {
    unsafe {
        bindings::rcu_barrier();
        bindings::kmem_cache_destroy(cachep);
    }
}

fn ext2_setup_super(sb: *mut bindings::super_block) -> Result<()> {
    let sbi = ext2_sb(sb);
    unsafe { (*sbi.s_es).s_mnt_count = u16::to_le(u16::from_le((*sbi.s_es).s_mnt_count) + 1) };
    Ok(())
}

fn ext2_max_size(bits: c_int) -> loff_t {
    let check_lfs = |x, y| {
        let z = x << y;
        if z > MAX_LFS_FILESIZE {
            MAX_LFS_FILESIZE
        } else {
            z
        }
    };

    let mut res: loff_t = bindings::EXT2_NDIR_BLOCKS as loff_t;
    let ppb: c_uint = 1 << (bits - 2);

    let mut upper_limit: c_uint = u32::MAX;
    upper_limit = upper_limit >> (bits - 9);

    res += 1 << (bits - 2);
    res += 1 << (2 * (bits - 2));
    res += 1 << (3 * (bits - 2));

    let mut meta_blocks = 1;
    meta_blocks += 1 + ppb;
    meta_blocks += 1 + ppb + ppb * ppb;
    if res + meta_blocks as i64 <= upper_limit.into() {
        return check_lfs(res, bits);
    }

    res = upper_limit as i64;
    upper_limit -= bindings::EXT2_NDIR_BLOCKS;
    meta_blocks = 1;
    upper_limit -= ppb;
    if upper_limit < ppb * ppb {
        meta_blocks += 1 + upper_limit / ppb + u32::from(upper_limit % ppb != 0);
        res -= meta_blocks as i64;
        return check_lfs(res, bits);
    }
    meta_blocks += 1 + ppb;
    upper_limit -= ppb * ppb;
    meta_blocks += 1
        + upper_limit / ppb
        + u32::from(upper_limit % ppb != 0)
        + upper_limit / (ppb * ppb)
        + u32::from(upper_limit % (ppb * ppb) != 0);
    res -= meta_blocks as i64;

    check_lfs(res, bits)
}

fn descriptor_loc(sbi: &Ext2SbInfo, logic_sb_block: c_ulong, nr: c_int) -> c_ulong {
    let first_meta_bg = unsafe { u32::from_le((*sbi.s_es).s_first_meta_bg) };
    if !ext2_has_incompact_feature((*sbi).s_es, bindings::EXT2_FEATURE_INCOMPAT_META_BG)
        || nr < first_meta_bg as i32
    {
        logic_sb_block + nr as c_ulong + 1
    } else {
        let bg = sbi.s_desc_per_block * nr as u64;
        ext2_group_first_block_no(sbi, bg) + ext2_bg_has_super(sbi.s_es, bg as i32) as u64
    }
}

unsafe extern "C" fn ext2_fill_super(
    sb: *mut bindings::super_block,
    _data: *mut c_void,
    _silent: c_int,
) -> c_int {
    // TODO: get_sb_block to parse options
    let sb_block: c_ulong = 1;

    let blocksize = unsafe { bindings::sb_min_blocksize(sb, BLOCK_SIZE) };
    if blocksize == 0 {
        return -(bindings::EINVAL as i32);
    }
    let (mut logic_sb_block, offset) = if blocksize != BLOCK_SIZE {
        (
            (sb_block * BLOCK_SIZE as c_ulong) / blocksize as c_ulong,
            (sb_block * BLOCK_SIZE as c_ulong) % blocksize as c_ulong,
        )
    } else {
        (sb_block as c_ulong, 0)
    };

    let mut bh = unsafe { bindings::sb_bread(sb, logic_sb_block) };
    if bh.is_null() {
        return -(bindings::EINVAL as i32);
    }

    let (bh, es) = unsafe {
        let mut es: *mut bindings::ext2_super_block =
            (*bh).b_data.add(offset as usize) as *mut bindings::ext2_super_block;

        (*sb).s_magic = u16::from_le((*es).s_magic) as c_ulong;
        if (*sb).s_magic != bindings::EXT2_SUPER_MAGIC as c_ulong {
            return -(bindings::EINVAL as i32);
        }

        if u32::from_le((*es).s_log_block_size)
            > (bindings::EXT2_MAX_BLOCK_LOG_SIZE - bindings::BLOCK_SIZE_BITS)
        {
            pr_err!(
                "Invalid log block size: {}",
                u32::from_le((*es).s_log_block_size)
            );
            return -(bindings::EINVAL as i32);
        }

        let blocksize = BLOCK_SIZE << u32::from_le((*es).s_log_block_size);
        if (*sb).s_blocksize != blocksize as c_ulong {
            bindings::brelse(bh);

            if bindings::sb_set_blocksize(sb, blocksize as i32) == 0 {
                pr_err!("error: bad blocksize {}", blocksize);
                return -1;
            }
            logic_sb_block = (sb_block * BLOCK_SIZE as c_ulong) / blocksize as c_ulong;
            let offset = (sb_block * BLOCK_SIZE as c_ulong) % blocksize as c_ulong;
            bh = bindings::sb_bread(sb, logic_sb_block);
            if bh.is_null() {
                return -(bindings::EINVAL as i32);
            }
            es = (*bh).b_data.add(offset as usize) as *mut bindings::ext2_super_block;

            (*sb).s_magic = u16::from_le((*es).s_magic) as c_ulong;
            if (*sb).s_magic != bindings::EXT2_SUPER_MAGIC as c_ulong {
                return -(bindings::EINVAL as i32);
            }
        }

        (*sb).s_maxbytes = ext2_max_size((*sb).s_blocksize_bits as i32);
        (*sb).s_max_links = bindings::EXT2_LINK_MAX;
        (*sb).s_time_min = i32::MIN as i64;
        (*sb).s_time_max = i32::MAX as i64;

        (*sb).s_op = &EXT2_SOPS;
        (bh, es)
    };
    let (s_inode_size, s_first_ino) = unsafe {
        if u32::from_le((*es).s_rev_level) == bindings::EXT2_GOOD_OLD_REV {
            (
                bindings::EXT2_GOOD_OLD_INODE_SIZE as u16,
                bindings::EXT2_GOOD_OLD_FIRST_INO,
            )
        } else {
            (
                u16::from_le((*es).s_inode_size),
                u32::from_le((*es).s_first_ino),
            )
        }
    };

    let sbi = unsafe {
        let s_blocks_per_group = u32::from_le((*es).s_blocks_per_group);
        let s_inodes_per_group = u32::from_le((*es).s_inodes_per_group);

        let s_inodes_per_block = (*sb).s_blocksize / s_inode_size as u64;

        let s_itb_per_group = s_inodes_per_group as u64 / s_inodes_per_block;
        let s_desc_per_block =
            (*sb).s_blocksize / core::mem::size_of::<bindings::ext2_group_desc>() as u64;

        let s_groups_count =
            ((u32::from_le((*es).s_blocks_count) - u32::from_le((*es).s_first_data_block) - 1)
                / s_blocks_per_group)
                + 1;
        let db_count = (s_groups_count as u64 + s_desc_per_block - 1) / s_desc_per_block;
        let s_group_desc = Vec::new();

        let s_addr_per_block_bits =
            i32::ilog2(((*sb).s_blocksize / core::mem::size_of::<u32>() as u64) as i32) as i32;
        let s_desc_per_block_bits = i32::ilog2(s_desc_per_block as i32) as i32;

        let generation = {
            let mut val: u32 = 0;
            bindings::get_random_bytes(&mut val as *mut u32 as *mut c_void, 4);
            val
        };

        Box::pin_init(pin_init!(
            Ext2SbInfo {
                s_inodes_per_block: s_inodes_per_block as c_ulong,
                s_blocks_per_group: s_blocks_per_group as c_ulong,
                s_inodes_per_group: s_inodes_per_group as c_ulong,
                s_itb_per_group: s_itb_per_group as c_ulong,
                s_gdb_count: db_count as c_ulong,
                s_desc_per_block,
                s_groups_count: s_groups_count as c_ulong,
                s_blocks_last: 0,
                s_sbh: bh,
                s_es: es,
                s_group_desc,

                s_mount_opt: 0,
                s_sb_block: sb_block,
                s_mount_state: u16::from_le((*es).s_state),
                s_addr_per_block_bits,
                s_desc_per_block_bits,
                s_inode_size: s_inode_size as c_int,
                s_first_ino: s_first_ino as c_int,

                s_next_generation: core::sync::atomic::AtomicU32::new(generation),

                s_lock <- new_spinlock!(()),
            }
        ))
        .unwrap()
    };

    let mut s_group_desc = Vec::try_with_capacity(sbi.s_gdb_count as usize).unwrap();
    for i in 0..sbi.s_gdb_count {
        let block = descriptor_loc(&sbi, logic_sb_block, i as i32);
        let bh = unsafe { bindings::sb_bread(sb, block) };
        if bh.is_null() {
            return -(bindings::EINVAL as i32);
        }
        s_group_desc.try_push(bh).unwrap();
    }
    let mut inner = unsafe { Pin::into_inner_unchecked(sbi) };
    inner.as_mut().s_group_desc = s_group_desc;
    unsafe { (*sb).s_fs_info = Box::into_raw(inner) as _ };

    let root = ext2_iget(sb, bindings::EXT2_ROOT_INO as u64).unwrap();

    let s_root = unsafe { bindings::d_make_root(root) };
    if s_root.is_null() {
        pr_err!("error: get root inode failed");
        return -1;
    }
    unsafe { (*sb).s_root = s_root };

    let _ = ext2_setup_super(sb);
    ext2_write_super(sb);

    0
}

fn ext2_sync_super(sb: *mut bindings::super_block, wait: c_int) {
    let sbi = ext2_sb(sb);
    let es = sbi.s_es;
    unsafe {
        let _ = sbi.s_lock.lock();

        (*es).s_free_blocks_count = u32::to_le(ext2_count_free_blocks(sb) as u32);
        (*es).s_free_inodes_count = u32::to_le(ext2_count_free_inodes(sb) as u32);
        (*es).s_wtime = u32::to_le(bindings::ktime_get_real_seconds() as u32);
    }
    unsafe {
        bindings::mark_buffer_dirty(sbi.s_sbh);
        if wait != 0 {
            bindings::sync_dirty_buffer(sbi.s_sbh);
        }
    }
}

unsafe extern "C" fn ext2_sync_fs(sb: *mut bindings::super_block, wait: c_int) -> c_int {
    let sbi = ext2_sb(sb);
    let es = sbi.s_es;
    unsafe {
        let _ = sbi.s_lock.lock();
        if (*es).s_state & u16::to_le(bindings::EXT2_VALID_FS as u16) != 0 {
            (*es).s_state &= u16::to_le(bindings::EXT2_VALID_FS as u16);
        }
    }
    ext2_sync_super(sb, wait);
    0
}

fn ext2_write_super(sb: *mut bindings::super_block) {
    unsafe {
        if (*sb).s_flags & (1 << 0) == 0 {
            ext2_sync_fs(sb, 1);
        }
    };
}

unsafe extern "C" fn ext2_statfs(
    dentry: *mut bindings::dentry,
    buf: *mut bindings::kstatfs,
) -> c_int {
    unsafe {
        let sb = (*dentry).d_sb;
        let sbi = ext2_sb(sb);

        let _ = sbi.s_lock.lock();

        (*buf).f_type = bindings::EXT2_SUPER_MAGIC as i64;
        (*buf).f_bsize = (*sb).s_blocksize as i64;
        (*buf).f_blocks = u64::from_le((*sbi.s_es).s_blocks_count as u64);
        (*buf).f_bfree = ext2_count_free_blocks(sb);
        (*sbi.s_es).s_free_blocks_count = u32::to_le((*buf).f_bfree as u32);
        (*buf).f_bavail = (*buf).f_bfree - u32::from_le((*sbi.s_es).s_r_blocks_count as u32) as u64;
        (*buf).f_files = u32::from_le((*sbi.s_es).s_inodes_count as u32) as u64;
        (*buf).f_ffree = ext2_count_free_inodes(sb);
        (*sbi.s_es).s_free_inodes_count = u32::to_le((*buf).f_ffree as u32);
        (*buf).f_namelen = bindings::EXT2_NAME_LEN as i64;
        // (*buf).f_fsid = uuid_to_fsid(&(*sbi.s_es).s_uuid);
    }
    0
}

unsafe extern "C" fn ext2_mount(
    fs_type: *mut bindings::file_system_type,
    flags: c_int,
    dev_name: *const c_char,
    data: *mut c_void,
) -> *mut kernel::bindings::dentry {
    unsafe { bindings::mount_bdev(fs_type, flags, dev_name, data, Some(ext2_fill_super)) }
}

#[repr(transparent)]
struct FileSystemType(Opaque<bindings::file_system_type>);

const fn create_file_system_type(name: &CStr) -> FileSystemType {
    FileSystemType(Opaque::new(bindings::file_system_type {
        name: name.as_char_ptr(),
        kill_sb: Some(bindings::kill_block_super),
        fs_flags: bindings::FS_REQUIRES_DEV as i32,
        mount: Some(ext2_mount),
        ..unsafe { core::mem::MaybeUninit::<bindings::file_system_type>::zeroed().assume_init() }
    }))
}

static mut EXT2_RUST_FS_TYPE: FileSystemType = create_file_system_type(c_str!("ext2rust"));

impl kernel::Module for Ext2Rust {
    fn init(module: &'static ThisModule) -> Result<Self> {
        let cachep = init_inodecache()?;
        let fs_type = unsafe { &mut EXT2_RUST_FS_TYPE };
        unsafe {
            (*fs_type.0.get()).owner = module.0;
        }
        let ret = unsafe { bindings::register_filesystem(fs_type.0.get()) };
        if ret != 0 {
            return Err(kernel::error::code::EINVAL);
        }
        Ok(Ext2Rust {
            ext2_inode_cachep: cachep,
        })
    }
}

impl Drop for Ext2Rust {
    fn drop(&mut self) {
        let fs_type = unsafe { &mut EXT2_RUST_FS_TYPE };
        unsafe {
            bindings::unregister_filesystem(fs_type.0.get());
        }
        destroy_inodecache(self.ext2_inode_cachep)
    }
}

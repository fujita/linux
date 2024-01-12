// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2024 FUJITA Tomonori <fujita.tomonori@gmail.com>

//! Definitions of ext2rust.

use core::ffi::{c_longlong, c_ulong};
use core::fmt;
use kernel::bindings;
use kernel::prelude::*;
use kernel::{sync::SpinLock, types::Opaque};

pub(crate) const MAX_LFS_FILESIZE: c_longlong = c_longlong::MAX;

pub(crate) const BLOCK_SIZE: i32 = bindings::BLOCK_SIZE as i32;

// bindgen can't handle slab_flags_t
#[cfg(CONFIG_SLUB_TINY)]
pub(crate) const SLAB_RECLAIM_ACCOUNT: u32 = 0;
#[cfg(not(CONFIG_SLUB_TINY))]
pub(crate) const SLAB_RECLAIM_ACCOUNT: u32 = 0x00020000;
pub(crate) const SLAB_MEM_SPREAD: u32 = 0x00100000;
#[cfg(CONFIG_MEMCG_KMEM)]
pub(crate) const SLAB_ACCOUNT: u32 = 0x04000000U;
#[cfg(not(CONFIG_MEMCG_KMEM))]
pub(crate) const SLAB_ACCOUNT: u32 = 0;

pub(crate) const I_DATA_SIZE: usize = 15;

#[repr(C)]
pub(crate) struct Ext2InodeInfo {
    pub(crate) i_data: [u32; I_DATA_SIZE],
    pub(crate) i_flags: u32,
    pub(crate) i_faddr: u32,
    pub(crate) i_frag_no: u8,
    pub(crate) i_frag_size: u8,
    pub(crate) i_state: u16,
    pub(crate) i_file_acl: u32,
    pub(crate) i_dir_acl: u32,
    pub(crate) i_dtime: u32,
    pub(crate) i_block_group: u32,

    pub(crate) vfs_inode: Opaque<bindings::inode>,
}

#[pin_data]
pub(crate) struct Ext2SbInfo {
    pub(crate) s_inodes_per_block: c_ulong,
    pub(crate) s_blocks_per_group: c_ulong,
    pub(crate) s_inodes_per_group: c_ulong,
    pub(crate) s_itb_per_group: c_ulong,
    pub(crate) s_gdb_count: c_ulong,
    pub(crate) s_desc_per_block: c_ulong,
    pub(crate) s_groups_count: c_ulong,
    pub(crate) s_blocks_last: c_ulong,
    pub(crate) s_sbh: *mut bindings::buffer_head,
    pub(crate) s_es: *mut bindings::ext2_super_block,
    pub(crate) s_group_desc: Vec<*mut bindings::buffer_head>,

    pub(crate) s_mount_opt: c_ulong,
    pub(crate) s_sb_block: c_ulong,
    pub(crate) s_mount_state: u16,
    pub(crate) s_addr_per_block_bits: i32,
    pub(crate) s_desc_per_block_bits: i32,
    pub(crate) s_inode_size: i32,
    pub(crate) s_first_ino: i32,

    pub(crate) s_next_generation: core::sync::atomic::AtomicU32,

    #[pin]
    pub(crate) s_lock: SpinLock<()>,
}

pub(crate) fn ext2_sb<'a>(sb: *mut bindings::super_block) -> &'a Ext2SbInfo {
    unsafe {
        let ptr = (*sb).s_fs_info;
        &*ptr.cast()
    }
}

impl fmt::Debug for Ext2SbInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ext2SbInfo")
            .field("s_inodes_per_block", &self.s_inodes_per_block)
            .field("s_blocks_per_group", &self.s_blocks_per_group)
            .field("s_inodes_per_group", &self.s_inodes_per_group)
            .field("s_itb_per_group", &self.s_itb_per_group)
            .field("s_gdb_count", &self.s_gdb_count)
            .field("s_desc_per_block", &self.s_desc_per_block)
            .field("s_groups_count", &self.s_groups_count)
            .field("s_blocks_last", &self.s_blocks_last)
            .field("s_mount_ops", &self.s_mount_opt)
            .field("s_sb_block", &self.s_sb_block)
            .field("s_mount_state", &self.s_mount_state)
            .field("s_addr_per_block_bits", &self.s_addr_per_block_bits)
            .field("s_desc_per_block_bits", &self.s_desc_per_block_bits)
            .field("s_inode_size", &self.s_inode_size)
            .field("s_first_ino", &self.s_first_ino)
            .finish()
    }
}

pub(crate) fn ext2_has_ro_compact_feature(
    s_es: *mut bindings::ext2_super_block,
    mask: u32,
) -> bool {
    unsafe { (*s_es).s_feature_ro_compat & u32::to_le(mask) != 0 }
}

pub(crate) fn ext2_has_incompact_feature(s_es: *mut bindings::ext2_super_block, mask: u32) -> bool {
    unsafe { (*s_es).s_feature_incompat & u32::to_le(mask) != 0 }
}

pub(crate) fn ext2_group_first_block_no(sbi: &Ext2SbInfo, group_no: c_ulong) -> c_ulong {
    unsafe {
        group_no * sbi.s_blocks_per_group + u32::to_le((*(sbi.s_es)).s_first_data_block) as c_ulong
    }
}

pub(crate) fn ext2_group_last_block_no(sbi: &Ext2SbInfo, group_no: c_ulong) -> c_ulong {
    if group_no == sbi.s_groups_count - 1 {
        unsafe { (*sbi.s_es).s_blocks_count as u64 - 1 }
    } else {
        ext2_group_first_block_no(sbi, group_no) + sbi.s_blocks_per_group - 1
    }
}

pub(crate) fn s_islnk(inode: *const bindings::inode) -> bool {
    unsafe { (*inode).i_mode as u32 & bindings::S_IFMT == bindings::S_IFLNK }
}

pub(crate) fn s_isreg(inode: *const bindings::inode) -> bool {
    unsafe { (*inode).i_mode as u32 & bindings::S_IFMT == bindings::S_IFREG }
}

pub(crate) fn s_isdir(inode: *const bindings::inode) -> bool {
    unsafe { (*inode).i_mode as u32 & bindings::S_IFMT == bindings::S_IFDIR }
}

#[allow(dead_code)]
pub(crate) fn s_ischr(inode: *const bindings::inode) -> bool {
    unsafe { (*inode).i_mode as u32 & bindings::S_IFMT == bindings::S_IFCHR }
}

#[allow(dead_code)]
pub(crate) fn s_isblk(inode: *const bindings::inode) -> bool {
    unsafe { (*inode).i_mode as u32 & bindings::S_IFMT == bindings::S_IFBLK }
}

pub(crate) fn ext2_mask_flags(inode: *const bindings::inode, flags: u32) -> u32 {
    if s_isdir(inode) {
        return flags;
    } else if s_isreg(inode) {
        return flags & bindings::EXT2_REG_FLMASK as u32;
    } else {
        return flags & bindings::EXT2_OTHER_FLMASK;
    }
}

#[allow(missing_docs)]
#[macro_export]
macro_rules! container_of {
    ($ptr:expr, $type:path, $field:ident) => {
        $ptr.cast::<u8>()
            .sub(core::mem::offset_of!($type, $field))
            .cast::<$type>()
    };
}

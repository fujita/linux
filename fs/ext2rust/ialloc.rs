// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2024 FUJITA Tomonori <fujita.tomonori@gmail.com>

use core::ffi::{c_int, c_ulong, c_void};
use core::sync::atomic::Ordering;
use kernel::bindings;
use kernel::error;
use kernel::prelude::*;

use crate::{container_of, defs::ext2_mask_flags, ext2_get_group_desc, ext2_sb, s_isdir};

fn read_inode_bitmap(
    sb: *mut bindings::super_block,
    block_group: c_ulong,
) -> *mut bindings::buffer_head {
    unsafe {
        let (desc, _) = ext2_get_group_desc(sb, block_group as u32).unwrap();
        let bitmap_bh = bindings::sb_bread(sb, u32::from_le((*desc).bg_inode_bitmap) as u64);
        bitmap_bh
    }
}

pub(crate) fn ext2_count_free_inodes(sb: *mut bindings::super_block) -> c_ulong {
    let mut free_inodes = 0;
    for i in 0..ext2_sb(sb).s_groups_count {
        let (desc, _) = ext2_get_group_desc(sb, i as u32).unwrap();
        free_inodes += unsafe { u16::from_le((*desc).bg_free_inodes_count) } as c_ulong;
    }
    free_inodes
}

pub(crate) fn ext2_new_inode(
    dir: *mut bindings::inode,
    mode: bindings::umode_t,
    _qstr: *const bindings::qstr,
) -> *mut bindings::inode {
    unsafe {
        let sb = (*dir).i_sb;
        let sbi = ext2_sb(sb);
        let inode = bindings::new_inode(sb);
        for i in 0..sbi.s_groups_count {
            let (gdp, bh) = ext2_get_group_desc(sb, i as u32).unwrap();
            let bitmap_bh = read_inode_bitmap(sb, i);

            let mut ino = bindings::find_next_zero_bit_le(
                (*bitmap_bh).b_data as *const c_void,
                sbi.s_inodes_per_group,
                0,
            );
            if ino < sbi.s_inodes_per_group {
                if bindings::test_and_set_bit_le(ino as c_int, (*bitmap_bh).b_data as *mut c_void)
                    == 0
                {
                    bindings::mark_buffer_dirty(bitmap_bh);
                    ino += i * sbi.s_inodes_per_group + 1;
                    bindings::brelse(bitmap_bh);

                    {
                        // let _ = sbi.s_lock.lock();
                        (*gdp).bg_free_inodes_count =
                            u16::to_le(u16::from_le((*gdp).bg_free_inodes_count) - 1);
                        if s_isdir(inode) {
                            (*gdp).bg_used_dirs_count =
                                u16::to_le(u16::from_le((*gdp).bg_used_dirs_count) + 1);
                        }
                    }
                    bindings::mark_buffer_dirty(bh);
                    bindings::inode_init_owner(
                        &mut bindings::nop_mnt_idmap as *mut kernel::bindings::mnt_idmap,
                        inode,
                        dir,
                        mode,
                    );
                    (*inode).i_ino = ino;
                    (*inode).i_blocks = 0;
                    bindings::simple_inode_init_ts(inode);
                    let ei = container_of!(inode, bindings::ext2_inode_info, vfs_inode);
                    (*ei).i_data = [0; 15];
                    (*ei).i_flags = ext2_mask_flags(
                        inode,
                        (*container_of!(dir, bindings::ext2_inode_info, vfs_inode)).i_flags
                            & bindings::EXT2_FL_INHERITED,
                    );
                    (*ei).i_faddr = 0;
                    (*ei).i_frag_no = 0;
                    (*ei).i_frag_size = 0;
                    (*ei).i_state = 0;
                    (*ei).i_file_acl = 0;
                    (*ei).i_dir_acl = 0;
                    (*ei).i_dtime = 0;
                    (*ei).i_block_group = i as u32;
                    (*ei).i_state = bindings::EXT2_STATE_NEW as u16;
                    (*inode).i_flags &= !(bindings::S_SYNC
                        | bindings::S_APPEND
                        | bindings::S_IMMUTABLE
                        | bindings::S_NOATIME
                        | bindings::S_DIRSYNC
                        | bindings::S_DAX);
                    (*inode).i_generation = sbi.s_next_generation.fetch_add(1, Ordering::Relaxed);
                    if bindings::insert_inode_locked(inode) < 0 {
                        pr_err!("failed to insert inode {}", ino);
                    }

                    // if bindings::dquot_initialize(inode) != 0 {
                    //     pr_err!("failed to initialize dquot for inode {}", ino);
                    // }

                    // if bindings::dquot_alloc_inode(inode) != 0 {
                    //     pr_err!("failed to allocate dquot for inode {}", ino);
                    // }

                    bindings::mark_inode_dirty(inode);
                    return inode;
                }
            }
            bindings::brelse(bitmap_bh);
        }

        // bindings::dquot_free_inode(inode);
        bindings::ERR_PTR(error::code::ENOMEM.to_errno().into()) as *mut bindings::inode
    }
}

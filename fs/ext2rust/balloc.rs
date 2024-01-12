// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2024 FUJITA Tomonori <fujita.tomonori@gmail.com>

use core::ffi::{c_int, c_uint, c_ulong, c_void};
use kernel::bindings;
use kernel::prelude::*;

use crate::{defs::*, ext2_has_ro_compact_feature};

pub(crate) fn ext2_get_group_desc(
    sb: *mut bindings::super_block,
    block_group: u32,
) -> Result<(*mut bindings::ext2_group_desc, *mut bindings::buffer_head)> {
    let sbi = ext2_sb(sb);
    if block_group as u64 >= sbi.s_groups_count {
        return Err(kernel::error::code::EINVAL);
    }

    let group_desc = block_group as usize >> sbi.s_desc_per_block_bits;
    let offset = block_group as usize & (sbi.s_desc_per_block - 1) as usize;
    let desc = unsafe {
        (*sbi.s_group_desc[group_desc])
            .b_data
            .add(offset * core::mem::size_of::<bindings::ext2_group_desc>())
            as *mut bindings::ext2_group_desc
    };
    let bh = sbi.s_group_desc[group_desc];
    Ok((desc, bh))
}

pub(crate) fn ext2_count_free_blocks(sb: *mut bindings::super_block) -> c_ulong {
    let mut free_blocks = 0;
    for i in 0..ext2_sb(sb).s_groups_count {
        let (desc, _) = ext2_get_group_desc(sb, i as u32).unwrap();
        free_blocks += unsafe { u16::from_le((*desc).bg_free_blocks_count) } as c_ulong;
    }
    free_blocks
}

fn test_root(a: c_int, b: c_int) -> bool {
    let mut num = b;

    while a > num {
        num *= b;
    }
    num == a
}

fn ext2_group_sparse(group: c_int) -> bool {
    if group <= 1 {
        return true;
    }
    if test_root(group, 3) || test_root(group, 5) || test_root(group, 7) {
        true
    } else {
        false
    }
}

pub(crate) fn ext2_bg_has_super(s_es: *mut bindings::ext2_super_block, group: c_int) -> c_int {
    if ext2_has_ro_compact_feature(s_es, bindings::EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER)
        && !ext2_group_sparse(group)
    {
        0
    } else {
        1
    }
}

fn read_block_bitmap(
    sb: *mut bindings::super_block,
    block_group: c_uint,
) -> *mut bindings::buffer_head {
    let (desc, _) = ext2_get_group_desc(sb, block_group).unwrap();
    unsafe {
        let bitmap_blk = u32::from_le((*desc).bg_block_bitmap);
        let bh = bindings::sb_getblk(sb, bitmap_blk as u64);
        let _ = bindings::bh_read(bh, 0);
        bh
    }
}

fn ext2_try_to_allocate(sb: *mut bindings::super_block, group: i32) -> Result<c_ulong> {
    let sbi = ext2_sb(sb);
    let group_first_block = ext2_group_first_block_no(sbi, group as u64);
    let group_last_block = ext2_group_last_block_no(sbi, group as u64);
    let end = group_last_block - group_first_block + 1;

    let bitmap_bh = read_block_bitmap(sb, group as u32);
    unsafe {
        for i in 0..end {
            if bindings::test_and_set_bit_le(i as i32, (*bitmap_bh).b_data as *mut c_void) == 0 {
                bindings::brelse(bitmap_bh);
                return Ok(i + group_first_block);
            }
        }
        bindings::brelse(bitmap_bh);
    }
    return Err(kernel::error::code::ENOSPC);
}

pub(crate) fn ext2_new_blocks(
    inode: *mut bindings::inode,
    _goal: c_ulong,
    count: c_ulong,
    _flags: c_uint,
) -> Result<c_ulong> {
    assert_eq!(count, 1);
    unsafe {
        let sb = (*inode).i_sb;
        let sbi = ext2_sb(sb);

        for i in 0..sbi.s_groups_count {
            let (desc, _) = ext2_get_group_desc(sb, i as u32).unwrap();
            let free_blocks = u16::from_le((*desc).bg_free_blocks_count);
            if free_blocks >= count as u16 {
                (*desc).bg_free_blocks_count = u16::to_le(free_blocks - count as u16);
                return ext2_try_to_allocate(sb, i as i32);
            }
        }
    }
    Err(kernel::error::code::ENOSPC)
}

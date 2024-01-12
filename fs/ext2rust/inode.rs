// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2024 FUJITA Tomonori <fujita.tomonori@gmail.com>

use core::ffi::{c_int, c_long, c_uint, c_ulong, c_void};
use kernel::bindings;
use kernel::error;
use kernel::prelude::*;

use crate::{
    balloc::ext2_new_blocks, container_of, ext2_get_group_desc, ext2_sb, s_isdir, s_islnk, s_isreg,
};
use crate::{
    dir::EXT2_DIR_OPERATIONS, file::EXT2_FILE_INODE_OPERATIONS, file::EXT2_FILE_OPERATIONS,
    namei::EXT2_DIR_INODE_OPERATIONS, Ext2InodeInfo, Ext2SbInfo,
};

#[derive(Clone, Copy)]
struct Indirect {
    p: *mut u32,
    key: u32,
    bh: *mut bindings::buffer_head,
}

fn add_chain(p: &mut Indirect, bh: *mut bindings::buffer_head, v: *mut u32) {
    p.p = v;
    unsafe { p.key = *v };
    p.bh = bh;
}

enum Ext2Branch {
    Found,
    NotFound(u32),
    Error,
}

fn ext2_get_branch(
    inode: *mut bindings::inode,
    mut depth: i32,
    offsets: &[i64; 4],
    chain: &mut [Indirect; 4],
) -> Ext2Branch {
    let ei = unsafe { container_of!(inode, Ext2InodeInfo, vfs_inode) };

    unsafe {
        add_chain(
            &mut chain[0],
            core::ptr::null_mut(),
            &mut ((*ei).i_data[offsets[0] as usize]) as *mut u32,
        )
    };
    if chain[0].key == 0 {
        return Ext2Branch::NotFound(0);
    }
    depth -= 1;
    let mut i = 0;
    while depth > 0 {
        let bh = unsafe { bindings::sb_bread((*inode).i_sb, chain[i].key as u64) };
        if bh.is_null() {
            return Ext2Branch::Error;
        }
        i += 1;
        add_chain(&mut chain[i], bh, unsafe {
            (*bh).b_data.add(4 * offsets[i] as usize) as *mut u32
        });
        if chain[i].key == 0 {
            return Ext2Branch::NotFound(i as u32);
        }
        depth -= 1;
    }
    Ext2Branch::Found
}

fn ext2_block_to_path(
    sbi: &Ext2SbInfo,
    inode: *mut bindings::inode,
    offsets: &mut [c_long; 4],
    mut i_block: c_long,
) -> (c_int, i64) {
    unsafe {
        let ptrs = ((*(*inode).i_sb).s_blocksize / core::mem::size_of::<u32>() as u64) as i64;
        let ptrs_bits = sbi.s_addr_per_block_bits;
        let direct_blocks = bindings::EXT2_NDIR_BLOCKS as c_long;
        let indirect_blocks = ptrs;
        let double_blocks = (1 << (ptrs_bits * 2)) as c_long;
        let is_boundary = |i_block, last| last - 1 - (i_block & (ptrs - 1));

        if i_block < direct_blocks {
            offsets[0] = i_block;
            return (1, is_boundary(i_block, direct_blocks));
        }

        i_block -= direct_blocks;
        if i_block < indirect_blocks {
            offsets[0] = bindings::EXT2_IND_BLOCK as c_long;
            offsets[1] = i_block;
            return (2, is_boundary(i_block, ptrs));
        }

        i_block -= indirect_blocks;
        if i_block < double_blocks {
            offsets[0] = bindings::EXT2_DIND_BLOCK as c_long;
            offsets[1] = i_block >> ptrs_bits;
            offsets[2] = i_block & (ptrs - 1);
            return (3, is_boundary(i_block, ptrs));
        }

        i_block -= double_blocks;
        if i_block >> ptrs_bits * 2 < ptrs {
            offsets[0] = bindings::EXT2_TIND_BLOCK as c_long;
            offsets[1] = i_block >> (ptrs_bits * 2);
            offsets[2] = (i_block >> ptrs_bits) & (ptrs - 1);
            offsets[3] = i_block & (ptrs - 1);
            return (4, is_boundary(i_block, ptrs));
        }
    }
    (0, 0)
}

struct Ext2Blocks {
    count: u32,
    block_no: u64,
    new: bool,
    boundary: bool,
}

fn ext2_get_blocks(
    sbi: &Ext2SbInfo,
    inode: *mut bindings::inode,
    iblock: u64,
    _max_blocks: u64,
    _create: c_int,
) -> Result<Ext2Blocks> {
    let mut offsets = [0i64; 4];
    let (depth, _is_boundary) = ext2_block_to_path(sbi, inode, &mut offsets, iblock as c_long);

    // FIXME: can handle only direct blocks for now
    assert_eq!(depth, 1);

    let mut chain = [Indirect {
        p: core::ptr::null_mut(),
        key: 0,
        bh: core::ptr::null_mut(),
    }; 4];

    match ext2_get_branch(inode, depth, &offsets, &mut chain) {
        Ext2Branch::Found => Ok(Ext2Blocks {
            count: 1,
            block_no: chain[depth as usize - 1].key as u64,
            new: false,
            boundary: false,
        }),
        Ext2Branch::NotFound(_) => {
            let allocated_block = ext2_new_blocks(inode, 0, 1, 0).unwrap();
            unsafe {
                *chain[0].p = u32::to_le(allocated_block as u32);
                bindings::inode_set_ctime_current(inode);
                bindings::mark_inode_dirty(inode)
            };

            Ok(Ext2Blocks {
                count: 1,
                block_no: allocated_block,
                new: true,
                boundary: false,
            })
        }
        Ext2Branch::Error => return Err(kernel::error::code::EIO),
    }
}

pub(crate) unsafe extern "C" fn ext2_get_block(
    inode: *mut bindings::inode,
    iblock: u64,
    bh_result: *mut bindings::buffer_head,
    create: c_int,
) -> c_int {
    unsafe {
        let sbi = ext2_sb((*inode).i_sb);
        let max_blocks = (*bh_result).b_size >> (*inode).i_blkbits;
        assert_eq!(max_blocks, 1);
        match ext2_get_blocks(&sbi, inode, iblock, max_blocks as u64, create) {
            Ok(info) => {
                bindings::map_bh(bh_result, (*inode).i_sb, info.block_no);
                (*bh_result).b_size = (info.count as usize) << (*inode).i_blkbits;
                if info.new {
                    bindings::set_buffer_new(bh_result);
                }
                if info.boundary {
                    bindings::set_buffer_boundary(bh_result);
                }
            }
            Err(err) => {
                pr_err!("get_blocks error");
                return err.to_errno() as c_int;
            }
        }
    }
    0
}

unsafe extern "C" fn ext2_read_folio(
    _file: *mut bindings::file,
    folio: *mut bindings::folio,
) -> c_int {
    unsafe { bindings::mpage_read_folio(folio, Some(ext2_get_block)) }
}

unsafe extern "C" fn ext2_write_begin(
    _file: *mut bindings::file,
    mapping: *mut bindings::address_space,
    pos: bindings::loff_t,
    len: c_uint,
    pagep: *mut *mut bindings::page,
    _fsdata: *mut *mut c_void,
) -> c_int {
    unsafe { bindings::block_write_begin(mapping, pos, len, pagep, Some(ext2_get_block)) }
}

unsafe extern "C" fn ext2_write_end(
    file: *mut bindings::file,
    mapping: *mut bindings::address_space,
    pos: bindings::loff_t,
    len: c_uint,
    copied: c_uint,
    page: *mut bindings::page,
    fsdata: *mut c_void,
) -> c_int {
    unsafe { bindings::generic_write_end(file, mapping, pos, len, copied, page, fsdata) }
}

unsafe extern "C" fn ext2_bmap(mapping: *mut bindings::address_space, block: u64) -> u64 {
    unsafe { bindings::generic_block_bmap(mapping, block, Some(ext2_get_block)) }
}

unsafe extern "C" fn ext2_writepages(
    mapping: *mut bindings::address_space,
    wbc: *mut bindings::writeback_control,
) -> c_int {
    unsafe { bindings::mpage_writepages(mapping, wbc, Some(ext2_get_block)) }
}

pub(crate) const EXT2_AOPS: bindings::address_space_operations =
    bindings::address_space_operations {
        dirty_folio: Some(bindings::block_dirty_folio),
        invalidate_folio: Some(bindings::block_invalidate_folio),
        read_folio: Some(ext2_read_folio),
        write_begin: Some(ext2_write_begin),
        write_end: Some(ext2_write_end),
        bmap: Some(ext2_bmap),
        writepages: Some(ext2_writepages),
        migrate_folio: Some(bindings::buffer_migrate_folio),
        is_partially_uptodate: Some(bindings::block_is_partially_uptodate),
        ..unsafe {
            core::mem::MaybeUninit::<bindings::address_space_operations>::zeroed().assume_init()
        }
    };

fn ext2_set_inode_flags(inode: *mut bindings::inode) {
    let ei = unsafe { container_of!(inode, Ext2InodeInfo, vfs_inode) };

    unsafe {
        (*inode).i_flags &= !(bindings::S_SYNC
            | bindings::S_APPEND
            | bindings::S_IMMUTABLE
            | bindings::S_NOATIME
            | bindings::S_DIRSYNC
            | bindings::S_DAX);
        if (*inode).i_flags & bindings::EXT2_SYNC_FL as u32 != 0 {
            (*ei).i_flags |= bindings::EXT2_SYNC_FL as u32;
        }
        if (*inode).i_flags & bindings::EXT2_APPEND_FL as u32 != 0 {
            (*ei).i_flags |= bindings::EXT2_APPEND_FL as u32;
        }
        if (*inode).i_flags & bindings::EXT2_IMMUTABLE_FL as u32 != 0 {
            (*ei).i_flags |= bindings::EXT2_IMMUTABLE_FL as u32;
        }
        if (*inode).i_flags & bindings::EXT2_NOATIME_FL as u32 != 0 {
            (*ei).i_flags |= bindings::EXT2_NOATIME_FL as u32;
        }
        if (*inode).i_flags & bindings::EXT2_DIRSYNC_FL as u32 != 0 {
            (*ei).i_flags |= bindings::EXT2_DIRSYNC_FL as u32;
        }
    }
}

pub(crate) fn ext2_set_file_ops(inode: *mut bindings::inode) {
    unsafe {
        (*inode).i_op = &EXT2_FILE_INODE_OPERATIONS;
        (*inode).__bindgen_anon_3.i_fop = &EXT2_FILE_OPERATIONS;
        (*(*inode).i_mapping).a_ops = &EXT2_AOPS;
    }
}

pub(crate) fn ext2_iget(
    sb: *mut bindings::super_block,
    ino: c_ulong,
) -> Result<*mut bindings::inode> {
    let sbi = ext2_sb(sb);
    let inode = unsafe { bindings::iget_locked(sb, ino) };
    if inode.is_null() {
        pr_err!("failed to iget_locked()");
        return Err(kernel::error::code::ENOMEM);
    }

    let ei = unsafe { container_of!(inode, Ext2InodeInfo, vfs_inode) };

    let (raw_inode, bh) = ext2_get_inode(sb, ino)?;
    unsafe {
        (*inode).i_mode = u16::from_le((*raw_inode).i_mode);

        let mut i_uid = u16::from_le((*raw_inode).i_uid) as u32;
        let mut i_gid = u16::from_le((*raw_inode).i_gid) as u32;
        i_uid |= (u16::from_le((*raw_inode).osd2.linux2.l_i_uid_high) as u32) << 16;
        i_gid |= (u16::from_le((*raw_inode).osd2.linux2.l_i_gid_high) as u32) << 16;
        bindings::i_uid_write(inode, i_uid);
        bindings::i_gid_write(inode, i_gid);
        bindings::set_nlink(inode, u16::from_le((*raw_inode).i_links_count) as u32);
        (*inode).i_size = u32::from_le((*raw_inode).i_size) as i64;

        bindings::inode_set_atime(inode, u32::from_le((*raw_inode).i_atime).into(), 0);
        bindings::inode_set_ctime(inode, u32::from_le((*raw_inode).i_ctime).into(), 0);
        bindings::inode_set_mtime(inode, u32::from_le((*raw_inode).i_mtime).into(), 0);

        (*ei).i_dtime = u32::from_le((*raw_inode).i_dtime);
        (*inode).i_blocks = u32::from_le((*raw_inode).i_blocks) as u64;
        (*ei).i_flags = u32::from_le((*raw_inode).i_flags);
        ext2_set_inode_flags(inode);
        (*ei).i_faddr = u32::from_le((*raw_inode).i_faddr);
        (*ei).i_frag_no = (*raw_inode).osd2.linux2.l_i_frag;
        (*ei).i_frag_size = (*raw_inode).osd2.linux2.l_i_fsize;
        (*ei).i_file_acl = u32::from_le((*raw_inode).i_file_acl);
        (*ei).i_dir_acl = 0;

        if s_isreg(inode) {
            (*inode).i_size |= (u32::from_le((*raw_inode).i_dir_acl) as i64) << 32;
        } else {
            (*ei).i_dir_acl = u32::from_le((*raw_inode).i_dir_acl);
        }

        (*ei).i_dtime = 0;
        (*inode).i_generation = u32::from_le((*raw_inode).i_generation);
        (*ei).i_state = 0;
        (*ei).i_block_group = ((ino - 1) / sbi.s_inodes_per_group) as u32;

        for i in 0..bindings::EXT2_N_BLOCKS {
            (*ei).i_data[i as usize] = (*raw_inode).i_block[i as usize];
        }

        if s_isreg(inode) {
            ext2_set_file_ops(inode);
        } else if s_isdir(inode) {
            (*inode).i_op = &EXT2_DIR_INODE_OPERATIONS;
            (*inode).__bindgen_anon_3.i_fop = &EXT2_DIR_OPERATIONS;
            (*(*inode).i_mapping).a_ops = &EXT2_AOPS;
        } else {
            bindings::BUG();
        }

        bindings::brelse(bh);
        bindings::unlock_new_inode(inode);
    }

    Ok(inode)
}

fn ext2_setsize(inode: *mut bindings::inode, newsize: bindings::loff_t) -> c_int {
    if !s_isreg(inode) || s_isdir(inode) || s_islnk(inode) {
        return error::code::EINVAL.to_errno();
    }

    unsafe { bindings::inode_dio_wait(inode) };

    let ret =
        unsafe { bindings::block_truncate_page((*inode).i_mapping, newsize, Some(ext2_get_block)) };
    if ret != 0 {
        return ret;
    }

    unsafe {
        bindings::filemap_invalidate_lock((*inode).i_mapping);
        bindings::truncate_setsize(inode, newsize);
        // __ext2_truncate_blocks(inode, newsize);
        bindings::filemap_invalidate_unlock((*inode).i_mapping);

        bindings::inode_set_mtime_to_ts(inode, bindings::inode_set_ctime_current(inode));
        if bindings::inode_needs_sync(inode) != 0 {
            bindings::sync_mapping_buffers((*inode).i_mapping);
            bindings::sync_inode_metadata(inode, 1);
        } else {
            bindings::mark_inode_dirty(inode);
        }
    }

    0
}

fn ext2_get_inode(
    sb: *mut bindings::super_block,
    ino: c_ulong,
) -> Result<(*mut bindings::ext2_inode, *mut bindings::buffer_head)> {
    let sbi = ext2_sb(sb);
    if (ino != bindings::EXT2_ROOT_INO as c_ulong && ino < sbi.s_first_ino as c_ulong)
        || ino > u32::from_le(unsafe { (*sbi.s_es).s_inodes_count }) as c_ulong
    {
        pr_err!("invalid ino {} {}", ino, unsafe {
            (*sbi.s_es).s_inodes_count
        });
        return Err(kernel::error::code::EINVAL);
    }

    let block_group = (ino - 1) / sbi.s_inodes_per_group;
    let (gdp, _) = ext2_get_group_desc(sb, block_group as u32)?;

    let mut offset = ((ino - 1) % sbi.s_inodes_per_group) * sbi.s_inode_size as c_ulong;
    let block = unsafe {
        u32::from_le((*gdp).bg_inode_table) as c_ulong
            + (offset >> (*sb).s_blocksize_bits) as c_ulong
    };
    let bh = unsafe { bindings::sb_bread(sb, block) };
    if bh.is_null() {
        return Err(kernel::error::code::EIO);
    }

    offset &= unsafe { (*sb).s_blocksize - 1 };
    let inode = unsafe { (*bh).b_data.add(offset as usize) as *mut bindings::ext2_inode };
    Ok((inode, bh))
}

fn __ext2_write_inode(inode: *mut bindings::inode, do_sync: bool) -> c_int {
    let ei = unsafe { container_of!(inode, Ext2InodeInfo, vfs_inode) };
    let sb = unsafe { (*inode).i_sb };
    let sbi = ext2_sb(sb);
    let ino = unsafe { (*inode).i_ino };
    let uid = unsafe { bindings::i_uid_read(inode) };
    let gid = unsafe { bindings::i_gid_read(inode) };

    let (raw_inode, bh) = match ext2_get_inode(sb, ino) {
        Ok((raw_inode, bh)) => (raw_inode, bh),
        Err(err) => {
            return err.to_errno() as c_int;
        }
    };

    unsafe {
        if (*ei).i_state & bindings::I_NEW as u16 == 0 {
            let ptr = raw_inode as *mut u8;
            ptr.write_bytes(0, sbi.s_inode_size as usize);
        }

        (*raw_inode).i_mode = u16::to_le((*inode).i_mode);
        if true {
            (*raw_inode).i_uid = u16::to_le((uid & 0xffff) as u16);
            (*raw_inode).i_gid = u16::to_le((gid & 0xffff) as u16);
            (*raw_inode).osd2.linux2.l_i_uid_high = u16::to_le((uid >> 16) as u16);
            (*raw_inode).osd2.linux2.l_i_gid_high = u16::to_le((gid >> 16) as u16);
        }
        (*raw_inode).i_links_count = u16::to_le((*inode).__bindgen_anon_1.i_nlink as u16);
        (*raw_inode).i_size = u32::to_le((*inode).i_size as u32);
        (*raw_inode).i_atime = u32::to_le(bindings::inode_get_atime_sec(inode) as u32);
        (*raw_inode).i_ctime = u32::to_le(bindings::inode_get_ctime_sec(inode) as u32);
        (*raw_inode).i_mtime = u32::to_le(bindings::inode_get_mtime_sec(inode) as u32);

        (*raw_inode).i_blocks = u32::to_le((*inode).i_blocks as u32);
        (*raw_inode).i_dtime = u32::to_le((*ei).i_dtime);
        (*raw_inode).i_flags = u32::to_le((*ei).i_flags);
        (*raw_inode).i_faddr = u32::to_le((*ei).i_faddr);
        (*raw_inode).osd2.linux2.l_i_frag = (*ei).i_frag_no;
        (*raw_inode).osd2.linux2.l_i_fsize = (*ei).i_frag_size;
        (*raw_inode).i_file_acl = u32::to_le((*ei).i_file_acl);

        if !s_isreg(inode) {
            (*raw_inode).i_dir_acl = u32::to_le((*ei).i_dir_acl);
        } else {
            // (*raw_inode).i_size_high = u32::to_le(((*inode).i_size >> 32) as u32);
        }

        (*raw_inode).i_generation = u32::to_le((*inode).i_generation);
        for i in 0..bindings::EXT2_N_BLOCKS {
            (*raw_inode).i_block[i as usize] = (*ei).i_data[i as usize];
        }

        bindings::mark_buffer_dirty(bh);
        if do_sync {
            bindings::sync_dirty_buffer(bh);
        }
        (*ei).i_state &= !bindings::EXT2_STATE_NEW as u16;
        bindings::brelse(bh);
    }
    0
}

pub(crate) unsafe extern "C" fn ext2_write_inode(
    inode: *mut bindings::inode,
    wbc: *mut bindings::writeback_control,
) -> c_int {
    __ext2_write_inode(inode, unsafe {
        (*wbc).sync_mode == bindings::writeback_sync_modes_WB_SYNC_ALL
    })
}

pub(crate) unsafe extern "C" fn ext2_getattr(
    _idmap: *mut bindings::mnt_idmap,
    path: *const bindings::path,
    stat: *mut bindings::kstat,
    request_mask: u32,
    _query_flags: c_uint,
) -> c_int {
    unsafe {
        let inode = (*(*path).dentry).d_inode;
        bindings::generic_fillattr(
            &mut bindings::nop_mnt_idmap as *mut bindings::mnt_idmap,
            request_mask,
            inode,
            stat,
        );
    }
    0
}

pub(crate) unsafe extern "C" fn ext2_setattr(
    _idmap: *mut bindings::mnt_idmap,
    dentry: *mut bindings::dentry,
    iattr: *mut bindings::iattr,
) -> c_int {
    let inode = unsafe { bindings::d_inode(dentry) };
    unsafe {
        let ret = bindings::setattr_prepare(
            &mut bindings::nop_mnt_idmap as *mut bindings::mnt_idmap,
            dentry,
            iattr,
        );
        if ret != 0 {
            return ret;
        }
        if (*iattr).ia_valid & bindings::ATTR_SIZE != 0 && (*iattr).ia_size != (*inode).i_size {
            let ret = ext2_setsize(inode, (*iattr).ia_size);
            if ret != 0 {
                return ret;
            }
        }
        bindings::setattr_copy(
            &mut bindings::nop_mnt_idmap as *mut bindings::mnt_idmap,
            inode,
            iattr,
        );
        bindings::mark_inode_dirty(inode);
    }
    0
}

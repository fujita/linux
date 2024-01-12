// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2024 FUJITA Tomonori <fujita.tomonori@gmail.com>

use core::ffi::{c_int, c_long, c_uint, c_void};
use kernel::bindings;
use kernel::error;

use crate::{
    dir::ext2_add_link, dir::ext2_make_empty, ext2_iget, ext2_inode_by_name,
    ialloc::ext2_new_inode, inode::ext2_getattr, inode::ext2_set_file_ops,
};
use crate::{EXT2_AOPS, EXT2_DIR_OPERATIONS};

fn ext2_add_nodir(dentry: *mut bindings::dentry, inode: *mut bindings::inode) -> c_int {
    unsafe {
        match ext2_add_link(dentry, inode) {
            Ok(_) => {
                bindings::d_instantiate_new(dentry, inode);
                0
            }
            Err(err) => {
                bindings::inode_dec_link_count(inode);
                bindings::discard_new_inode(inode);
                err.to_errno()
            }
        }
    }
}

unsafe extern "C" fn ext2_lookup(
    dir: *mut bindings::inode,
    dentry: *mut bindings::dentry,
    _flags: c_uint,
) -> *mut bindings::dentry {
    unsafe {
        if (*dentry).d_name.__bindgen_anon_1.__bindgen_anon_1.len > bindings::EXT2_NAME_LEN {
            return bindings::ERR_PTR(-1 * bindings::ENAMETOOLONG as c_long)
                as *mut bindings::dentry;
        }
        let inode = match ext2_inode_by_name(dir, &(*dentry).d_name) {
            Ok(ino) => {
                let inode = ext2_iget((*dir).i_sb, ino);
                inode.unwrap()
            }
            Err(err) => {
                if err != error::code::ENOENT {
                    return bindings::ERR_PTR(err.to_errno() as i64) as *mut bindings::dentry;
                }
                core::ptr::null_mut() as *mut bindings::inode
            }
        };
        bindings::d_splice_alias(inode, dentry)
    }
}

unsafe extern "C" fn ext2_create(
    _idmap: *mut bindings::mnt_idmap,
    dir: *mut bindings::inode,
    dentry: *mut bindings::dentry,
    mode: bindings::umode_t,
    _excl: bool,
) -> c_int {
    unsafe {
        let inode = ext2_new_inode(dir, mode, &(*dentry).d_name as *const bindings::qstr);
        if bindings::IS_ERR(inode as *mut c_void) {
            return bindings::PTR_ERR(inode as *const c_void) as i32;
        }

        ext2_set_file_ops(inode);
        bindings::mark_inode_dirty(inode);
        return ext2_add_nodir(dentry, inode);
    }
}

unsafe extern "C" fn ext2_mkdir(
    _idmap: *mut bindings::mnt_idmap,
    dir: *mut bindings::inode,
    dentry: *mut bindings::dentry,
    mode: bindings::umode_t,
) -> c_int {
    unsafe {
        // let err = unsafe { bindings::dquot_initialize(dir) };
        // if err != 0 {
        //     return err;
        // }
        bindings::inode_inc_link_count(dir);

        let inode = ext2_new_inode(
            dir,
            bindings::S_IFDIR as bindings::umode_t | mode,
            &(*dentry).d_name as *const bindings::qstr,
        );
        if bindings::IS_ERR(inode as *mut c_void) {
            return bindings::PTR_ERR(inode as *const c_void) as i32;
        }
        (*inode).i_op = &EXT2_DIR_INODE_OPERATIONS;
        (*inode).__bindgen_anon_3.i_fop = &EXT2_DIR_OPERATIONS;
        (*(*inode).i_mapping).a_ops = &EXT2_AOPS;

        bindings::inode_inc_link_count(inode);

        ext2_make_empty(inode, dir);

        let _ = ext2_add_link(dentry, inode);

        bindings::d_instantiate_new(dentry, inode);
    }
    0
}

pub(crate) const EXT2_DIR_INODE_OPERATIONS: bindings::inode_operations =
    bindings::inode_operations {
        create: Some(ext2_create),
        lookup: Some(ext2_lookup),
        mkdir: Some(ext2_mkdir),
        getattr: Some(ext2_getattr),
        ..unsafe { core::mem::MaybeUninit::<bindings::inode_operations>::zeroed().assume_init() }
    };

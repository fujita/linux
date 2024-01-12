// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2024 FUJITA Tomonori <fujita.tomonori@gmail.com>

use core::ffi::c_int;
use kernel::bindings::{self, loff_t};
use kernel::error;
use kernel::prelude::*;

use crate::inode::{ext2_getattr, ext2_setattr};

unsafe extern "C" fn ext2_release_file(
    _inode: *mut bindings::inode,
    _filp: *mut bindings::file,
) -> c_int {
    0
}

unsafe extern "C" fn ext2_fsync(
    file: *mut bindings::file,
    start: loff_t,
    end: loff_t,
    datasync: c_int,
) -> c_int {
    let ret = unsafe { bindings::generic_buffers_fsync(file, start, end, datasync != 0) };
    if ret == error::code::EIO.to_errno() {
        pr_err!("ext2_fsync: IO error");
    }
    ret
}

pub(crate) const EXT2_FILE_OPERATIONS: bindings::file_operations = bindings::file_operations {
    llseek: Some(bindings::generic_file_llseek),
    read_iter: Some(bindings::generic_file_read_iter),
    write_iter: Some(bindings::generic_file_write_iter),
    mmap: Some(bindings::generic_file_mmap),
    open: Some(bindings::generic_file_open),
    release: Some(ext2_release_file),
    fsync: Some(ext2_fsync),
    ..unsafe { core::mem::MaybeUninit::<bindings::file_operations>::zeroed().assume_init() }
};

pub(crate) const EXT2_FILE_INODE_OPERATIONS: bindings::inode_operations =
    bindings::inode_operations {
        getattr: Some(ext2_getattr),
        setattr: Some(ext2_setattr),
        ..unsafe { core::mem::MaybeUninit::<bindings::inode_operations>::zeroed().assume_init() }
    };

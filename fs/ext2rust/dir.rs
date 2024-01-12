// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2024 FUJITA Tomonori <fujita.tomonori@gmail.com>

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use kernel::bindings;
use kernel::error;
use kernel::prelude::*;

use crate::{ext2_has_incompact_feature, ext2_sb, inode::ext2_get_block};

const PAGE_SIZE: c_ulong = 1 << bindings::PAGE_SHIFT;
const PAGE_MASK: c_ulong = !(PAGE_SIZE - 1);

fn ext2_rec_len_from_disk(dlen: u16) -> c_uint {
    let len = u16::from_le(dlen) as c_uint;

    if 1 << bindings::PAGE_SHIFT >= 65536 {
        if len == bindings::EXT2_MAX_REC_LEN {
            return 1 << 16;
        }
    }
    len
}

fn ext2_rec_len_to_disk(len: c_uint) -> u16 {
    if 1 << bindings::PAGE_SHIFT >= 65536 {
        if len == 1 << 16 {
            return u16::to_le(bindings::EXT2_MAX_REC_LEN as u16);
        } else {
            assert!(len > 1 << 16);
        }
    }
    u16::to_le(len as u16)
}

fn ext2_chunk_size(inode: *mut bindings::inode) -> c_uint {
    unsafe { (*(*inode).i_sb).s_blocksize as u32 }
}

const EXT2_DIR_ROUND: i32 = bindings::EXT2_DIR_ROUND as i32;

fn ext2_dir_rec_len(name_len: c_int) -> c_int {
    (name_len + 8 + EXT2_DIR_ROUND) & !EXT2_DIR_ROUND
}

fn ext2_last_byte(inode: *mut bindings::inode, page_nr: c_ulong) -> c_uint {
    unsafe {
        let mut last_byte = (*inode).i_size as c_ulong;

        last_byte -= page_nr << bindings::PAGE_SHIFT;
        if last_byte > PAGE_SIZE {
            last_byte = PAGE_SIZE;
        }
        last_byte as c_uint
    }
}

#[allow(dead_code)]
fn ext2_check_folio(folio: *mut bindings::folio, _quiet: c_int, kaddr: *mut c_void) -> bool {
    unsafe {
        let dir = (*(*folio).__bindgen_anon_1.__bindgen_anon_1.mapping).host;
        let mut limit = bindings::folio_size(folio) as c_ulong;
        let chunk_size = ext2_chunk_size(dir) as c_ulong;

        if (*dir).i_size < bindings::folio_pos(folio) + limit as c_long {
            limit = bindings::offset_in_folio(folio, (*dir).i_size as *mut c_void);
            if (limit & (chunk_size - 1)) != 0 {
                bindings::folio_set_error(folio);
                return false;
            }
            if limit == 0 {
                bindings::folio_test_checked(folio);
                return true;
            }
        }

        let mut offs = 0;
        while offs <= limit - ext2_dir_rec_len(1) as c_ulong {
            let p = kaddr.add(offs as usize) as *mut bindings::ext2_dir_entry_2;
            let rec_len = ext2_rec_len_from_disk((*p).rec_len);

            if rec_len < ext2_dir_rec_len(1) as u32 {
                bindings::folio_set_error(folio);
                return false;
            }
            if rec_len & 3 > 0 {
                bindings::folio_set_error(folio);
                return false;
            }
            if rec_len < ext2_dir_rec_len((*p).name_len as i32) as u32 {
                bindings::folio_set_error(folio);
                return false;
            }
            offs += rec_len as c_ulong;
        }

        if offs != limit {
            bindings::folio_set_error(folio);
            return false;
        }

        bindings::folio_test_checked(folio);
    }
    true
}

fn ext2_commit_chunk(folio: *mut bindings::folio, pos: bindings::loff_t, len: c_uint) {
    unsafe {
        let mapping = (*folio).__bindgen_anon_1.__bindgen_anon_1.mapping;
        let dir = (*mapping).host;
        bindings::inode_inc_iversion((*mapping).host);
        bindings::block_write_end(
            core::ptr::null_mut(),
            mapping,
            pos,
            len,
            len,
            &mut (*folio).__bindgen_anon_1.page as *mut bindings::page,
            core::ptr::null_mut(),
        );
        if pos + len as i64 > (*dir).i_size {
            bindings::i_size_write(dir, pos + len as i64);
            bindings::mark_inode_dirty(dir);
        }
        bindings::folio_unlock(folio);
    }
}

fn ext2_get_folio(
    dir: *mut bindings::inode,
    n: c_ulong,
    _quiet: c_int,
) -> Result<(*mut c_void, *mut bindings::folio)> {
    unsafe {
        let mapping = (*dir).i_mapping;
        let folio = bindings::read_mapping_folio(mapping, n, core::ptr::null_mut());
        if bindings::IS_ERR(folio as *const c_void) {
            pr_err!("failed map_folio");
            return Err(kernel::error::Error::from_errno(
                bindings::PTR_ERR(folio as *const c_void) as i32,
            ));
        }
        let kaddr = bindings::kmap_local_folio(folio, 0);
        // if !bindings::folio_test_checked(folio) {
        //     if !ext2_check_folio(folio, quiet, kaddr) {
        //         bindings::folio_release_kmap(folio, kaddr);
        //         pr_err!("failed check_folio");
        //         return Err(error::code::EIO);
        //     }
        // }
        Ok((kaddr, folio))
    }
}

fn ext2_match(len: c_int, name: *const c_char, de: *mut bindings::ext2_dir_entry_2) -> bool {
    unsafe {
        if (*de).name_len != len as u8 {
            return false;
        }
        if (*de).inode == 0 {
            return false;
        }
        if bindings::memcmp(
            name as *const c_void,
            (*de).name.as_ptr() as *const c_void,
            len as c_ulong,
        ) != 0
        {
            return false;
        }
    }
    true
}

fn ext2_next_entry(de: *mut bindings::ext2_dir_entry_2) -> *mut bindings::ext2_dir_entry_2 {
    unsafe {
        let rec_len = ext2_rec_len_from_disk((*de).rec_len);
        let p = de as *mut c_void;
        p.add(rec_len as usize) as *mut bindings::ext2_dir_entry_2
    }
}

fn ext2_validate_entry(base: *mut c_void, offset: c_uint, mask: c_uint) -> c_uint {
    unsafe {
        let de = base.add(offset as usize) as *mut bindings::ext2_dir_entry_2;
        let mut p =
            base.add((offset + (offset & mask)) as usize) as *mut bindings::ext2_dir_entry_2;
        while p < de {
            if (*p).rec_len == 0 {
                break;
            }
            p = ext2_next_entry(p);
        }
        ((p as c_ulong) & !PAGE_MASK) as c_uint
    }
}

pub(crate) fn ext2_inode_by_name(
    dir: *mut bindings::inode,
    child: *const bindings::qstr,
) -> Result<c_ulong> {
    let (de, folio) = ext2_find_entry(dir, child)?;
    let ino = unsafe { u32::from_le((*de).inode) };
    unsafe { bindings::folio_release_kmap(folio, de as *mut c_void) };
    Ok(ino as c_ulong)
}

unsafe extern "C" fn ext2_readdir(
    file: *mut bindings::file,
    ctx: *mut bindings::dir_context,
) -> c_int {
    unsafe {
        let pos = (*ctx).pos;
        let inode = (*file).f_inode;
        let mut offset = pos & !(PAGE_MASK as i64);
        let mut n = pos >> bindings::PAGE_SHIFT;
        let npages = bindings::dir_pages(inode) as i64;
        let mut need_revalidate = !bindings::inode_eq_iversion(inode, (*file).f_version);
        let chunk_mask = !(ext2_chunk_size(inode) - 1);

        let sbi = ext2_sb((*inode).i_sb);
        let has_filetype =
            ext2_has_incompact_feature(sbi.s_es, bindings::EXT2_FEATURE_INCOMPAT_FILETYPE);

        if pos > (*inode).i_size as i64 - ext2_dir_rec_len(1) as i64 {
            return 0;
        }

        for i in n..npages {
            let (kaddr, folio) = match ext2_get_folio(inode, i as u64, 0) {
                Ok((kaddr, folio)) => (kaddr, folio),
                Err(err) => {
                    pr_err!("failed get_folio");
                    return err.to_errno();
                }
            };
            if need_revalidate {
                if offset > 0 {
                    offset = ext2_validate_entry(kaddr, offset as u32, chunk_mask) as i64;
                    (*ctx).pos = (n << bindings::PAGE_SHIFT) + offset;
                }
                (*file).f_version = bindings::inode_query_iversion(inode);
                need_revalidate = false;
            }
            let mut de = kaddr.add(offset as usize) as *mut bindings::ext2_dir_entry_2;
            let limit =
                kaddr.add((ext2_last_byte(inode, i as u64) - ext2_dir_rec_len(1) as u32) as usize);

            while de as *mut c_void <= limit {
                if (*de).rec_len == 0 {
                    pr_err!("invalid entry rec_len = 0 {}", (*de).inode);
                    bindings::folio_release_kmap(folio, de as *mut c_void);
                    return -error::code::EIO.to_errno();
                }
                if (*de).inode > 0 {
                    let d_type = if has_filetype {
                        bindings::fs_ftype_to_dtype((*de).file_type as u32)
                    } else {
                        bindings::DT_UNKNOWN as u8
                    };

                    if !bindings::dir_emit(
                        ctx,
                        (*de).name.as_mut_ptr() as *const c_char,
                        (*de).name_len as i32,
                        u32::from_le((*de).inode) as u64,
                        d_type as u32,
                    ) {
                        bindings::folio_release_kmap(folio, de as *mut c_void);
                        return 0;
                    }
                } else {
                    pr_err!(
                        "invalid entry {}",
                        CStr::from_char_ptr((*de).name.as_mut_ptr())
                    );
                }
                (*ctx).pos += ext2_rec_len_from_disk((*de).rec_len) as i64;
                de = ext2_next_entry(de);
            }
            bindings::folio_release_kmap(folio, kaddr as *mut c_void);
            n += 1;
            offset = 0;
        }
    }
    0
}

fn ext2_find_entry(
    dir: *mut bindings::inode,
    child: *const bindings::qstr,
) -> Result<(*mut bindings::ext2_dir_entry_2, *mut bindings::folio)> {
    unsafe {
        let name = (*child).name;
        let namelen = (*child).__bindgen_anon_1.__bindgen_anon_1.len;
        let reclen = ext2_dir_rec_len(namelen as i32) as u32;
        let npages = bindings::dir_pages(dir);

        if npages == 0 {
            return Err(error::code::ENOENT);
        }

        let start = 0;

        let mut n = start;
        loop {
            let (mut kaddr, folio) = match ext2_get_folio(dir, n, 0) {
                Ok((kaddr, folio)) => (kaddr, folio),
                Err(err) => return Err(err),
            };
            let mut de = kaddr as *mut bindings::ext2_dir_entry_2;
            kaddr = kaddr.add((ext2_last_byte(dir, n) - reclen) as usize);
            while de as *mut c_void <= kaddr {
                if (*de).rec_len == 0 {
                    bindings::folio_release_kmap(folio, de as *mut c_void);
                    return Err(error::code::ENOENT);
                }
                if ext2_match(namelen as i32, name as *const i8, de) {
                    return Ok((de, folio));
                }
                de = ext2_next_entry(de);
            }
            bindings::folio_release_kmap(folio, kaddr as *mut c_void);

            n += 1;
            if n >= npages {
                n = 0;
            }
            if n > (*dir).i_blocks >> (bindings::PAGE_SHIFT - 9) {
                return Err(error::code::ENOENT);
            }
            if n == start {
                break;
            }
        }
    }
    return Err(error::code::ENOENT);
}

fn ext2_prepare_chunk(folio: *mut bindings::folio, pos: bindings::loff_t, len: u32) -> c_int {
    unsafe {
        bindings::__block_write_begin(
            &mut (*folio).__bindgen_anon_1.page as *mut bindings::page,
            pos,
            len,
            Some(ext2_get_block),
        )
    }
}

fn ext2_handle_dirsync(dir: *mut bindings::inode) -> c_int {
    unsafe {
        let mut err = bindings::filemap_write_and_wait_range((*dir).i_mapping, 0, i64::MAX);
        if err == 0 {
            err = bindings::sync_inode_metadata(dir, 1);
        }
        err
    }
}

pub(crate) fn ext2_add_link(
    dentry: *mut bindings::dentry,
    inode: *mut bindings::inode,
) -> Result<()> {
    unsafe {
        let dir = bindings::d_inode((*dentry).d_parent);
        let name = (*dentry).d_name.name;
        let namelen = (*dentry).d_name.__bindgen_anon_1.__bindgen_anon_1.len;
        let chunk_size = ext2_chunk_size(dir);
        let reclen = ext2_dir_rec_len(namelen as i32);
        let mut rec_len = 0;
        let mut name_len = 0;
        let mut folio = core::ptr::null_mut() as *mut bindings::folio;
        let mut de = core::ptr::null_mut() as *mut bindings::ext2_dir_entry_2;
        let npages = bindings::dir_pages(dir);
        //let mut kaddr = core::ptr::null_mut() as *mut c_void;

        'outer: for n in 0..npages + 1 {
            let (mut kaddr, f) = ext2_get_folio(dir, n, 0).unwrap();
            folio = f;

            bindings::folio_lock(folio);
            let dir_end = kaddr.add(ext2_last_byte(dir, n) as usize);
            de = kaddr as *mut bindings::ext2_dir_entry_2;
            kaddr = kaddr.add(bindings::folio_size(folio) - reclen as usize);
            while de as *mut c_void <= kaddr {
                if de as *mut c_void == dir_end {
                    name_len = 0;
                    rec_len = chunk_size;
                    (*de).rec_len = ext2_rec_len_to_disk(chunk_size);
                    (*de).inode = 0;
                    break 'outer;
                }
                if (*de).rec_len == 0 {
                    pr_err!("zero-length directory entry");
                    bindings::folio_unlock(folio);
                    bindings::folio_release_kmap(folio, de as *mut c_void);
                    return Err(error::code::EIO);
                }

                if ext2_match(namelen as i32, name as *const i8, de) {
                    bindings::folio_unlock(folio);
                    bindings::folio_release_kmap(folio, de as *mut c_void);
                    return Err(error::code::EEXIST);
                }

                name_len = ext2_dir_rec_len((*de).name_len.into());
                rec_len = ext2_rec_len_from_disk((*de).rec_len);
                if (*de).inode == 0 && rec_len >= reclen as u32 {
                    break 'outer;
                }
                if rec_len >= (name_len + reclen) as u32 {
                    break 'outer;
                }
                de = (de as *mut c_void).add(rec_len as usize) as *mut bindings::ext2_dir_entry_2;
            }
            bindings::folio_unlock(folio);
            bindings::folio_release_kmap(folio, kaddr as *mut c_void);
        }

        let pos =
            bindings::folio_pos(folio) + bindings::offset_in_folio(folio, de as *mut c_void) as i64;
        let _ = ext2_prepare_chunk(folio, pos, rec_len);
        if (*de).inode != 0 {
            let de1 = (de as *mut c_void).add(name_len as usize) as *mut bindings::ext2_dir_entry_2;
            (*de1).rec_len = ext2_rec_len_to_disk(rec_len - name_len as u32);
            (*de).rec_len = ext2_rec_len_to_disk(name_len as u32);
            de = de1;
        }
        (*de).name_len = namelen as u8;
        core::ptr::copy_nonoverlapping(name as *mut i8, (*de).name.as_mut_ptr(), namelen as usize);
        (*de).inode = u32::to_le((*inode).i_ino as u32);
        (*de).file_type = bindings::fs_umode_to_ftype((*inode).i_mode);
        ext2_commit_chunk(folio, pos, rec_len);
        bindings::inode_set_mtime_to_ts(dir, bindings::inode_set_ctime_current(dir));
        bindings::mark_inode_dirty(dir);
        ext2_handle_dirsync(dir);

        bindings::folio_release_kmap(folio, de as *mut c_void);
    }
    Ok(())
}

pub(crate) fn ext2_make_empty(inode: *mut bindings::inode, parent: *mut bindings::inode) -> c_int {
    unsafe {
        let folio = bindings::filemap_grab_folio((*inode).i_mapping, 0);
        let chunk_size = (*(*inode).i_sb).s_blocksize as u32;

        ext2_prepare_chunk(folio, 0, chunk_size);
        let kaddr = bindings::kmap_local_folio(folio, 0);
        core::ptr::write_bytes(kaddr, 0, chunk_size as usize);
        let mut de = kaddr as *mut bindings::ext2_dir_entry_2;
        (*de).name_len = 1;
        (*de).rec_len = ext2_rec_len_to_disk(ext2_dir_rec_len(1) as u32);
        core::ptr::write_bytes((*de).name.as_mut_ptr(), b'.', 1);
        (*de).inode = u32::to_le((*inode).i_ino as u32);
        (*de).file_type = bindings::fs_umode_to_ftype((*inode).i_mode);

        de = kaddr.add(ext2_dir_rec_len(1) as usize) as *mut bindings::ext2_dir_entry_2;
        (*de).name_len = 2;
        (*de).rec_len = ext2_rec_len_to_disk(chunk_size - ext2_dir_rec_len(1) as u32);
        core::ptr::write_bytes((*de).name.as_mut_ptr(), b'.', 2);
        (*de).inode = u32::to_le((*parent).i_ino as u32);
        (*de).file_type = bindings::fs_umode_to_ftype((*inode).i_mode);
        bindings::kunmap_local(kaddr);
        ext2_commit_chunk(folio, 0, chunk_size as u32);
        let err = ext2_handle_dirsync(inode);
        bindings::folio_put(folio);
        err
    }
}

pub(crate) const EXT2_DIR_OPERATIONS: bindings::file_operations = bindings::file_operations {
    llseek: Some(bindings::generic_file_llseek),
    read: Some(bindings::generic_read_dir),
    iterate_shared: Some(ext2_readdir),
    ..unsafe { core::mem::MaybeUninit::<bindings::file_operations>::zeroed().assume_init() }
};

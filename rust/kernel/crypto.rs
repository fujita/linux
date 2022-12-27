// SPDX-License-Identifier: GPL-2.0

//! Cryptography.
//!
//! C headers: [`include/crypto/hash.h`](../../../../include/crypto/hash.h),
//! [`include/crypto/skcipher.h`](../../../../include/crypto/skcipher.h).
//! [`include/crypto/aead.h`](../../../../include/crypto/aead.h).

use crate::{
    error::{code, from_kernel_err_ptr, to_result},
    str::CStr,
    Result,
};
use alloc::alloc::{alloc, dealloc};
use core::alloc::Layout;

///
pub struct Hash {
    ptr: *mut bindings::crypto_shash,
}

impl Drop for Hash {
    fn drop(&mut self) {
        unsafe { bindings::crypto_free_shash(self.ptr) }
    }
}

impl Hash {
    ///
    pub fn new(name: &'static CStr, t: u32, mask: u32) -> Result<Hash> {
        let ptr = unsafe {
            from_kernel_err_ptr(bindings::crypto_alloc_shash(name.as_char_ptr(), t, mask))
        }?;
        Ok(Hash { ptr })
    }

    ///
    pub fn setkey(&mut self, data: &[u8]) -> Result {
        to_result(unsafe {
            bindings::crypto_shash_setkey(self.ptr, data.as_ptr(), data.len() as u32)
        })
    }

    ///
    pub fn digestsize(&self) -> u32 {
        unsafe { bindings::crypto_shash_digestsize(self.ptr) }
    }
}

///
pub struct HashDesc {
    ptr: *mut bindings::shash_desc,
    size: usize,
}

impl Drop for HashDesc {
    fn drop(&mut self) {
        unsafe {
            dealloc(
                self.ptr as _,
                Layout::from_size_align(self.size, 2).unwrap(),
            );
        }
    }
}

impl HashDesc {
    ///
    pub fn new(hash: &Hash) -> Result<Self> {
        let size = core::mem::size_of::<bindings::shash_desc>()
            + unsafe { bindings::crypto_shash_descsize(hash.ptr) } as usize;
        let layout = Layout::from_size_align(size, 2)?;
        let ptr = unsafe { alloc(layout) } as *mut bindings::shash_desc;
        unsafe { (*ptr).tfm = hash.ptr };
        Ok(HashDesc { ptr, size })
    }

    ///
    pub fn init(&mut self) -> Result {
        to_result(unsafe { bindings::crypto_shash_init(self.ptr) })
    }

    ///
    pub fn update(&mut self, data: &[u8]) -> Result {
        to_result(unsafe {
            bindings::crypto_shash_update(self.ptr, data.as_ptr(), data.len() as u32)
        })
    }

    ///
    pub fn finalize(&mut self, output: &mut [u8]) -> Result {
        to_result(unsafe { bindings::crypto_shash_final(self.ptr, output.as_mut_ptr()) })
    }
}

///
pub struct Skcipher {
    ptr: *mut bindings::crypto_sync_skcipher,
}

impl Drop for Skcipher {
    fn drop(&mut self) {
        unsafe { bindings::crypto_free_sync_skcipher(self.ptr) }
    }
}

impl Skcipher {
    ///
    pub fn new(name: &'static CStr, t: u32, mask: u32) -> Result<Self> {
        let ptr = unsafe {
            from_kernel_err_ptr(bindings::crypto_alloc_sync_skcipher(
                name.as_char_ptr(),
                t,
                mask,
            ))
        }?;
        Ok(Skcipher { ptr })
    }

    ///
    pub fn setkey(&mut self, data: &[u8]) -> Result {
        to_result(unsafe {
            bindings::crypto_skcipher_setkey(
                &mut (*self.ptr).base,
                data.as_ptr(),
                data.len() as u32,
            )
        })
    }
}

///
pub struct SkcipherRequest {
    ///
    pub ptr: *mut bindings::skcipher_request,
}

impl SkcipherRequest {
    ///
    pub fn new(tfm: &Skcipher) -> Result<Self> {
        let ptr = unsafe {
            from_kernel_err_ptr(bindings::skcipher_request_alloc(
                &mut (*tfm.ptr).base,
                bindings::GFP_KERNEL,
            ))
        }?;
        unsafe {
            bindings::skcipher_request_set_tfm(ptr, &mut (*tfm.ptr).base);
            bindings::skcipher_request_set_callback(ptr, 0, None, core::ptr::null_mut());
        }
        Ok(SkcipherRequest { ptr })
    }

    ///
    pub fn encrypt(&mut self) -> Result {
        to_result(unsafe { bindings::crypto_skcipher_encrypt(self.ptr) })
    }
}

impl Drop for SkcipherRequest {
    fn drop(&mut self) {
        unsafe {
            bindings::skcipher_request_zero(self.ptr);
            bindings::skcipher_request_free(self.ptr);
        }
    }
}

///
pub struct Aead {
    ///
    pub ptr: *mut bindings::crypto_aead,
}

impl Aead {
    ///
    pub fn new(name: &'static CStr, t: u32, mask: u32) -> Result<Self> {
        let ptr = unsafe {
            from_kernel_err_ptr(bindings::crypto_alloc_aead(name.as_char_ptr(), t, mask))
        }?;
        Ok(Aead { ptr })
    }
}

impl Drop for Aead {
    fn drop(&mut self) {
        unsafe { bindings::crypto_free_aead(self.ptr) }
    }
}

///
pub struct Kpp {
    ///
    pub ptr: *mut bindings::crypto_kpp,
}

impl Kpp {
    ///
    pub fn new(name: &'static CStr, t: u32, mask: u32) -> Result<Self> {
        let ptr = unsafe {
            from_kernel_err_ptr(bindings::crypto_alloc_kpp(name.as_char_ptr(), t, mask))
        }?;
        Ok(Kpp { ptr })
    }
}

impl Drop for Kpp {
    fn drop(&mut self) {
        unsafe { bindings::crypto_free_kpp(self.ptr) }
    }
}

///
pub struct Akcipher {
    ///
    pub ptr: *mut bindings::crypto_akcipher,
}

impl Akcipher {
    ///
    pub fn new(name: &'static CStr, t: u32, mask: u32) -> Result<Self> {
        let ptr = unsafe {
            from_kernel_err_ptr(bindings::crypto_alloc_akcipher(name.as_char_ptr(), t, mask))
        }?;
        Ok(Akcipher { ptr })
    }
}

impl Drop for Akcipher {
    fn drop(&mut self) {
        unsafe { bindings::crypto_free_akcipher(self.ptr) }
    }
}

///
pub struct AkcipherRequest {
    ///
    pub ptr: *mut bindings::akcipher_request,
}

impl AkcipherRequest {
    ///
    pub fn new(tfm: &Akcipher) -> Result<Self> {
        let ptr = unsafe { bindings::akcipher_request_alloc(tfm.ptr, bindings::GFP_KERNEL) };
        if ptr.is_null() {
            Err(code::ENOMEM)
        } else {
            Ok(AkcipherRequest { ptr: ptr })
        }
    }
}

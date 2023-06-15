// SPDX-License-Identifier: GPL-2.0

//! Cryptographic Hash operations.
//!
//! C headers: [`include/crypto/hash.h`](../../../../include/crypto/hash.h)

use crate::{
    error::{
        code::{EINVAL, ENOMEM},
        from_err_ptr, to_result, Result,
    },
    str::CStr,
};
use alloc::alloc::{alloc, dealloc};
use core::alloc::Layout;

/// Corresponds to the kernel's `struct crypto_shash`.
///
/// # Invariants
///
/// The pointer is valid.
pub struct Shash(*mut bindings::crypto_shash);

impl Drop for Shash {
    fn drop(&mut self) {
        // SAFETY: The type invariant guarantees that the pointer is valid.
        unsafe { bindings::crypto_free_shash(self.0) }
    }
}

impl Shash {
    /// Creates a [`Shash`] object for a message digest handle.
    pub fn new(name: &CStr, t: u32, mask: u32) -> Result<Shash> {
        // SAFETY: FFI call.
        let ptr =
            unsafe { from_err_ptr(bindings::crypto_alloc_shash(name.as_char_ptr(), t, mask)) }?;
        // INVARIANT: `ptr` is valid and non-null since `crypto_alloc_shash`
        // returned a valid pointer which was null-checked.
        Ok(Self(ptr))
    }

    /// Sets optional key used by the hashing algorithm.
    pub fn setkey(&mut self, data: &[u8]) -> Result {
        // SAFETY: The type invariant guarantees that the pointer is valid.
        to_result(unsafe {
            bindings::crypto_shash_setkey(self.0, data.as_ptr(), data.len() as u32)
        })
    }

    /// Returns the size of the result of the transformation.
    pub fn digestsize(&self) -> u32 {
        // SAFETY: The type invariant guarantees that the pointer is valid.
        unsafe { bindings::crypto_shash_digestsize(self.0) }
    }
}

/// Corresponds to the kernel's `struct shash_desc`.
///
/// # Invariants
///
/// The field `ptr` is valid.
pub struct ShashDesc<'a> {
    ptr: *mut bindings::shash_desc,
    tfm: &'a Shash,
    size: usize,
}

impl Drop for ShashDesc<'_> {
    fn drop(&mut self) {
        // SAFETY: The type invariant guarantees that the pointer is valid.
        unsafe {
            dealloc(
                self.ptr.cast(),
                Layout::from_size_align(self.size, 2).unwrap(),
            );
        }
    }
}

impl<'a> ShashDesc<'a> {
    /// Creates a [`ShashDesc`] object for a request data structure for message digest.
    pub fn new(tfm: &'a Shash) -> Result<Self> {
        // SAFETY: The type invariant guarantees that `tfm.0` pointer is valid.
        let size = core::mem::size_of::<bindings::shash_desc>()
            + unsafe { bindings::crypto_shash_descsize(tfm.0) } as usize;
        let layout = Layout::from_size_align(size, 2)?;
        let ptr = unsafe { alloc(layout) } as *mut bindings::shash_desc;
        if ptr.is_null() {
            return Err(ENOMEM);
        }
        // INVARIANT: `ptr` is valid and non-null since `alloc`
        // returned a valid pointer which was null-checked.
        let mut desc = ShashDesc { ptr, tfm, size };
        // SAFETY: `desc.ptr` is valid and non-null since `alloc`
        // returned a valid pointer which was null-checked.
        // Additionally, The type invariant guarantees that `tfm.0` is valid.
        unsafe { (*desc.ptr).tfm = desc.tfm.0 };
        desc.reset()?;
        Ok(desc)
    }

    /// Re-initializes message digest.
    pub fn reset(&mut self) -> Result {
        // SAFETY: The type invariant guarantees that the pointer is valid.
        to_result(unsafe { bindings::crypto_shash_init(self.ptr) })
    }

    /// Adds data to message digest for processing.
    pub fn update(&mut self, data: &[u8]) -> Result {
        // SAFETY: The type invariant guarantees that the pointer is valid.
        to_result(unsafe {
            bindings::crypto_shash_update(self.ptr, data.as_ptr(), data.len() as u32)
        })
    }

    /// Calculates message digest.
    pub fn finalize(&mut self, output: &mut [u8]) -> Result {
        if self.tfm.digestsize() as usize > output.len() {
            return Err(EINVAL);
        }
        // SAFETY: The type invariant guarantees that the pointer is valid.
        to_result(unsafe { bindings::crypto_shash_final(self.ptr, output.as_mut_ptr()) })
    }
}

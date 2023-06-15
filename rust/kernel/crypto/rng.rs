// SPDX-License-Identifier: GPL-2.0

//! Random number generator.
//!
//! C headers: [`include/crypto/rng.h`](../../../../include/crypto/rng.h)

use crate::{
    error::{code::EINVAL, from_err_ptr, to_result, Result},
    str::CStr,
};

/// Type of Random number generator.
///
/// # Invariants
///
/// The pointer is valid.
enum RngType {
    /// Uses `crypto_default_rng`
    // We don't need to keep an pointer for the default but simpler.
    Default(*mut bindings::crypto_rng),

    /// Allocated via `crypto_alloc_rng.
    Allocated(*mut bindings::crypto_rng),
}

/// Corresponds to the kernel's `struct crypto_rng`.
pub struct Rng(RngType);

impl Drop for Rng {
    fn drop(&mut self) {
        match self.0 {
            RngType::Default(_) => {
                // SAFETY: it's safe because `crypto_get_default_rng()` was called during
                // the initialization.
                unsafe {
                    bindings::crypto_put_default_rng();
                }
            }
            RngType::Allocated(ptr) => {
                // SAFETY: The type invariants of `RngType` guarantees that the pointer is valid.
                unsafe { bindings::crypto_free_rng(ptr) };
            }
        }
    }
}

impl Rng {
    /// Creates a [`Rng`] instance.
    pub fn new(name: &CStr, t: u32, mask: u32) -> Result<Self> {
        // SAFETY: There are no safety requirements for this FFI call.
        let ptr = unsafe { from_err_ptr(bindings::crypto_alloc_rng(name.as_char_ptr(), t, mask)) }?;
        // INVARIANT: `ptr` is valid and non-null since `crypto_alloc_rng`
        // returned a valid pointer which was null-checked.
        Ok(Self(RngType::Allocated(ptr)))
    }

    /// Creates a [`Rng`] instance with a default algorithm.
    pub fn new_with_default() -> Result<Self> {
        // SAFETY: There are no safety requirements for this FFI call.
        to_result(unsafe { bindings::crypto_get_default_rng() })?;
        // INVARIANT: The C API guarantees that `crypto_default_rng` is valid until
        // `crypto_put_default_rng` is called.
        Ok(Self(RngType::Default(unsafe {
            bindings::crypto_default_rng
        })))
    }

    /// Get a random number.
    pub fn generate(&mut self, src: &[u8], dst: &mut [u8]) -> Result {
        if src.len() > u32::MAX as usize || dst.len() > u32::MAX as usize {
            return Err(EINVAL);
        }
        let ptr = match self.0 {
            RngType::Default(ptr) => ptr,
            RngType::Allocated(ptr) => ptr,
        };
        // SAFETY: The type invariants of `RngType' guarantees that the pointer is valid.
        to_result(unsafe {
            bindings::crypto_rng_generate(
                ptr,
                src.as_ptr(),
                src.len() as u32,
                dst.as_mut_ptr(),
                dst.len() as u32,
            )
        })
    }

    /// Re-initializes the [`Rng`] instance.
    pub fn reset(&mut self, seed: &[u8]) -> Result {
        if seed.len() > u32::MAX as usize {
            return Err(EINVAL);
        }
        let ptr = match self.0 {
            RngType::Default(ptr) => ptr,
            RngType::Allocated(ptr) => ptr,
        };
        // SAFETY: The type invariants of `RngType' guarantees that the pointer is valid.
        to_result(unsafe { bindings::crypto_rng_reset(ptr, seed.as_ptr(), seed.len() as u32) })
    }
}

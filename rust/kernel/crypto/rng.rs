// SPDX-License-Identifier: GPL-2.0

//! Random number generator.
//!
//! C headers: [`include/crypto/rng.h`](../../../../include/crypto/rng.h)

use crate::{
    error::{from_err_ptr, to_result, Result},
    str::CStr,
};

/// Corresponds to the kernel's `struct crypto_rng`.
///
/// # Invariants
///
/// The pointer is valid.
pub struct Rng(*mut bindings::crypto_rng);

impl Drop for Rng {
    fn drop(&mut self) {
        // SAFETY: The type invariant guarantees that `self.0` is valid.
        if unsafe { bindings::crypto_default_rng } == self.0 {
            // SAFETY: FFI call.
            unsafe {
                bindings::crypto_put_default_rng();
            }
        } else {
            // SAFETY: The type invariant guarantees that `self.0` is valid.
            unsafe { bindings::crypto_free_rng(self.0) };
        }
    }
}

impl Rng {
    /// Creates a [`Rng`] instance.
    pub fn new(name: &CStr, t: u32, mask: u32) -> Result<Self> {
        // SAFETY: FFI call.
        let ptr = unsafe { from_err_ptr(bindings::crypto_alloc_rng(name.as_char_ptr(), t, mask)) }?;
        // INVARIANT: `ptr` is valid and non-null since `crypto_alloc_rng`
        // returned a valid pointer which was null-checked.
        Ok(Self(ptr))
    }

    /// Creates a [`Rng`] instance with a default algorithm.
    pub fn new_with_default() -> Result<Self> {
        // SAFETY: FFI call.
        to_result(unsafe { bindings::crypto_get_default_rng() })?;
        // SAFETY: The C API guarantees that `crypto_default_rng` is valid until
        // `crypto_put_default_rng` is called.
        Ok(Self(unsafe { bindings::crypto_default_rng }))
    }

    /// Get a random number.
    pub fn generate(&mut self, src: &[u8], dst: &mut [u8]) -> Result {
        // SAFETY: The type invariant guarantees that the pointer is valid.
        to_result(unsafe {
            bindings::crypto_rng_generate(
                self.0,
                src.as_ptr(),
                src.len() as u32,
                dst.as_mut_ptr(),
                dst.len() as u32,
            )
        })
    }

    /// Re-initializes the [`Rng`] instance.
    pub fn reset(&mut self, seed: &[u8]) -> Result {
        // SAFETY: The type invariant guarantees that the pointer is valid.
        to_result(unsafe { bindings::crypto_rng_reset(self.0, seed.as_ptr(), seed.len() as u32) })
    }
}

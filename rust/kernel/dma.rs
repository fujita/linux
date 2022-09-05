// SPDX-License-Identifier: GPL-2.0

//! PCI devices and drivers.
//!
//! C header: [`include/linux/pci.h`](../../../../include/linux/dma.h)

#![allow(dead_code)]

use crate::{bindings, device, to_result, Result};
use core::ffi::c_void;
use core::ptr;

/// Set the DMA mask to inform the kernel about DMA addressing capabilities
pub fn set_mask(dev: &dyn device::RawDevice, mask: u64) -> Result {
    to_result(unsafe { bindings::dma_set_mask(dev.raw_device(), mask) })
}

/// Set the DMA coherent mask to inform the kernel about DMA addressing capabilities
pub fn set_coherent_mask(dev: &dyn device::RawDevice, mask: u64) -> Result {
    to_result(unsafe { bindings::dma_set_coherent_mask(dev.raw_device(), mask) })
}

/// alloc coherent memory
pub fn dma_alloc_coherent(
    dev: &dyn device::RawDevice,
    size: usize,
    handle: *mut u64,
    flag: bindings::gfp_t,
) -> Result<*mut c_void> {
    let ptr = unsafe { bindings::dma_alloc_attrs(dev.raw_device(), size, handle, flag, 0) };
    Ok(ptr)
}

/// map
pub fn dma_map_sg(
    dev: &device::Device,
    sg: *mut bindings::scatterlist,
    nents: core::ffi::c_int,
    dir: bindings::dma_data_direction,
) -> u32 {
    unsafe {
        bindings::dma_map_sg_attrs(dev.ptr, sg, nents, dir, bindings::DMA_ATTR_NO_WARN as u64)
    }
}

/// unmap
pub fn dma_unmap_sg(
    dev: &device::Device,
    sg: *mut bindings::scatterlist,
    nents: core::ffi::c_int,
    dir: bindings::dma_data_direction,
) {
    unsafe { bindings::dma_unmap_sg_attrs(dev.ptr, sg, nents, dir, 0) }
}

/// alloc dma memory
pub fn dma_alloc(
    dev: &device::Device,
    size: usize,
    dma_handle: *mut bindings::dma_addr_t,
    flag: bindings::gfp_t,
) -> *mut core::ffi::c_void {
    unsafe { bindings::dma_alloc_attrs(dev.ptr, size, dma_handle, flag, 0) }
}

/// move to blk
pub fn device_add_disk(dev: &dyn device::RawDevice, disk: *mut bindings::gendisk) -> i32 {
    unsafe { bindings::device_add_disk(dev.raw_device(), disk, ptr::null_mut()) }
}

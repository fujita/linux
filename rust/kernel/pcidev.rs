use crate::{
    bindings,
    device::{self, RawDevice},
    driver,
    error::{from_kernel_result, Result},
    str::CStr,
    to_result,
    types::PointerWrapper,
    ThisModule,
};
use alloc::boxed::Box;
use core::ffi::c_void;

pub struct Adapter<T: Driver>(T);

impl<T: Driver> driver::DriverOps for Adapter<T> {
    type RegType = bindings::pci_driver;

    unsafe fn register(
        reg: *mut bindings::pci_driver,
        name: &'static CStr,
        module: &'static ThisModule,
    ) -> Result {
        let pdrv: &mut bindings::pci_driver = unsafe { &mut *reg };

        pdrv.name = name.as_char_ptr();
        pdrv.probe = Some(Self::probe_callback);
        pdrv.remove = Some(Self::remove_callback);
        pdrv.id_table = T::PCI_ID_TABLE.as_ptr();
        to_result(unsafe { bindings::__pci_register_driver(reg, module.0, name.as_char_ptr()) })
    }

    unsafe fn unregister(reg: *mut bindings::pci_driver) {
        unsafe { bindings::pci_unregister_driver(reg) }
    }
}

impl<T: Driver> Adapter<T> {
    extern "C" fn probe_callback(
        pdev: *mut bindings::pci_dev,
        _id: *const bindings::pci_device_id,
    ) -> core::ffi::c_int {
        from_kernel_result! {
            let mut dev = unsafe { Device::from_ptr(pdev) };
            let data = T::probe(&mut dev).unwrap();
            unsafe {
                bindings::pci_set_drvdata(pdev, data.into_pointer() as _);
            }
            Ok(0)
        }
    }

    extern "C" fn remove_callback(_pdev: *mut bindings::pci_dev) {}
}

pub trait Driver {
    type Data: PointerWrapper + Send + Sync + driver::DeviceRemoval = ();

    const PCI_ID_TABLE: &'static [bindings::pci_device_id];

    fn probe(dev: &mut Device) -> Result<Self::Data>;

    fn remove(_data: &Self::Data) -> Result {
        Ok(())
    }
}

pub struct Device {
    pub ptr: *mut bindings::pci_dev,
}

impl Device {
    unsafe fn from_ptr(ptr: *mut bindings::pci_dev) -> Self {
        Self { ptr }
    }

    pub fn enable_device_mem(&mut self) -> Result {
        to_result(unsafe { bindings::pci_enable_device_mem(self.ptr) })
    }

    pub fn set_master(&mut self) {
        unsafe {
            bindings::pci_set_master(self.ptr);
        }
    }

    pub fn resource_start(&self, index: usize) -> u64 {
        unsafe {
            let pdev = *self.ptr;
            pdev.resource[index].start
        }
    }

    pub fn select_bars(&mut self, flags: u64) -> i32 {
        unsafe { bindings::pci_select_bars(self.ptr, flags) }
    }

    pub fn request_selected_regions(&mut self, bars: i32, res_name: &CStr) -> Result {
        to_result(unsafe {
            bindings::pci_request_selected_regions(self.ptr, bars, res_name.as_char_ptr())
        })
    }

    pub fn dma_set_mask(&mut self, mask: u64) -> Result {
        to_result(unsafe { bindings::dma_set_mask(self.raw_device(), mask) })
    }

    pub fn dma_set_coherent_mask(&mut self, mask: u64) -> Result {
        to_result(unsafe { bindings::dma_set_coherent_mask(self.raw_device(), mask) })
    }

    pub fn dma_alloc_coherent(
        &mut self,
        size: usize,
        handle: *mut u64,
        flag: bindings::gfp_t,
    ) -> Result<*mut c_void> {
        let ptr = unsafe { bindings::dma_alloc_attrs(self.raw_device(), size, handle, flag, 0) };
        Ok(ptr)
    }
}

unsafe impl device::RawDevice for Device {
    fn raw_device(&self) -> *mut bindings::device {
        // SAFETY: By the type invariants, we know that `self.ptr` is non-null and valid.
        unsafe { &mut (*self.ptr).dev }
    }
}

pub struct DmaPool {
    ptr: *mut bindings::dma_pool,
}

impl Drop for DmaPool {
    fn drop(&mut self) {
        unsafe {
            bindings::dma_pool_destroy(self.ptr);
        }
    }
}

unsafe impl Send for DmaPool {}

unsafe impl Sync for DmaPool {}

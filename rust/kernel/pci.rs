// SPDX-License-Identifier: GPL-2.0

//! PCI devices and drivers.
//!
//! C header: [`include/linux/pci.h`](../../../../include/linux/pci.h)

#![allow(dead_code)]

use crate::{
    bindings, device,
    device::RawDevice,
    driver,
    error::{
        code::{EINVAL, ENOMEM},
        from_kernel_result, Error, Result,
    },
    irq,
    str::CStr,
    to_result,
    types::PointerWrapper,
    ThisModule,
};
use core::fmt;

/// An adapter for the registration of PCI drivers.
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
        pdrv.id_table = T::ID_TABLE.as_ref();
        to_result(unsafe { bindings::__pci_register_driver(reg, module.0, name.as_char_ptr()) })
    }

    unsafe fn unregister(reg: *mut bindings::pci_driver) {
        unsafe { bindings::pci_unregister_driver(reg) }
    }
}

impl<T: Driver> Adapter<T> {
    extern "C" fn probe_callback(
        pdev: *mut bindings::pci_dev,
        id: *const bindings::pci_device_id,
    ) -> core::ffi::c_int {
        from_kernel_result! {
            let mut dev = unsafe { Device::from_ptr(pdev) };

            // SAFETY: `id` is a pointer within the static table, so it's always valid.
            let offset = unsafe {(*id).driver_data};
            // SAFETY: The offset comes from a previous call to `offset_from` in `IdArray::new`, which
            // guarantees that the resulting pointer is within the table.
            let info = {
                let ptr = unsafe {id.cast::<u8>().offset(offset as _).cast::<Option<T::IdInfo>>()};
                unsafe {(&*ptr).as_ref()}
            };
            let data = T::probe(&mut dev, info)?;
            unsafe { bindings::pci_set_drvdata(pdev, data.into_pointer() as _) };
            Ok(0)
        }
    }

    extern "C" fn remove_callback(pdev: *mut bindings::pci_dev) {
        let ptr = unsafe { bindings::pci_get_drvdata(pdev) };
        let data = unsafe { T::Data::from_pointer(ptr) };
        T::remove(&data);
        <T::Data as driver::DeviceRemoval>::device_remove(&data);
    }
}

/// Abstraction for bindings::pci_device_id.
#[derive(Clone, Copy)]
pub struct DeviceId {
    /// Vendor ID
    pub vendor: u32,
    /// Device ID
    pub device: u32,
    /// Subsystem vendor ID
    pub subvendor: u32,
    /// Subsystem device ID
    pub subdevice: u32,
    /// Device class and subclass
    pub class: u32,
    /// Limit which sub-fields of the class
    pub class_mask: u32,
}

impl DeviceId {
    const PCI_ANY_ID: u32 = !0;

    /// PCI_DEVICE macro.
    pub const fn new(vendor: u32, device: u32) -> Self {
        Self {
            vendor,
            device,
            subvendor: DeviceId::PCI_ANY_ID,
            subdevice: DeviceId::PCI_ANY_ID,
            class: 0,
            class_mask: 0,
        }
    }

    /// PCI_DEVICE_CLASS macro.
    pub const fn with_class(class: u32, class_mask: u32) -> Self {
        Self {
            vendor: DeviceId::PCI_ANY_ID,
            device: DeviceId::PCI_ANY_ID,
            subvendor: DeviceId::PCI_ANY_ID,
            subdevice: DeviceId::PCI_ANY_ID,
            class,
            class_mask,
        }
    }
}

// SAFETY: `ZERO` is all zeroed-out and `to_rawid` stores `offset` in `pci_device_id::driver_data`.
unsafe impl const driver::RawDeviceId for DeviceId {
    type RawType = bindings::pci_device_id;

    const ZERO: Self::RawType = bindings::pci_device_id {
        vendor: 0,
        device: 0,
        subvendor: 0,
        subdevice: 0,
        class: 0,
        class_mask: 0,
        driver_data: 0,
        override_only: 0,
    };

    fn to_rawid(&self, offset: isize) -> Self::RawType {
        bindings::pci_device_id {
            vendor: self.vendor,
            device: self.device,
            subvendor: self.subvendor,
            subdevice: self.subdevice,
            class: self.class,
            class_mask: self.class_mask,
            driver_data: offset as _,
            override_only: 0,
        }
    }
}

/// Define a const pci device id table
///
/// # Examples
///
/// ```ignore
/// # use kernel::{pci, define_pci_id_table};
/// #
/// struct MyDriver;
/// impl pci::Driver for MyDriver {
///     // [...]
/// #   fn probe(_dev: &mut pci::Device, _id_info: Option<&Self::IdInfo>) -> Result {
/// #       Ok(())
/// #   }
/// #   define_pci_id_table! {u32, [
/// #       (pci::DeviceId::new(0x010800, 0xffffff), None),
/// #       (pci::DeviceId::with_class(0x010802, 0xfffff), Some(0x10)),
/// #   ]}
/// }
/// ```
#[macro_export]
macro_rules! define_pci_id_table {
    ($data_type:ty, $($t:tt)*) => {
        type IdInfo = $data_type;
        const ID_TABLE: $crate::driver::IdTable<'static, $crate::pci::DeviceId, $data_type> = {
            $crate::define_id_array!(ARRAY, $crate::pci::DeviceId, $data_type, $($t)* );
            ARRAY.as_table()
        };
    };
}

/// A PCI driver
pub trait Driver {
    /// Data stored on device by driver.
    ///
    /// Corresponds to the data set or retrieved via the kernel's
    /// `pci_{set,get}_drvdata()` functions.
    ///
    /// Require that `Data` implements `PointerWrapper`. We guarantee to
    /// never move the underlying wrapped data structure.
    type Data: PointerWrapper + Send + Sync + driver::DeviceRemoval = ();

    /// The type holding information about each device id supported by the driver.
    type IdInfo: 'static = ();

    /// The table of device ids supported by the driver.
    const ID_TABLE: driver::IdTable<'static, DeviceId, Self::IdInfo>;

    /// PCI driver probe.
    ///
    /// Called when a new platform device is added or discovered.
    /// Implementers should attempt to initialize the device here.
    fn probe(dev: &mut Device, id: Option<&Self::IdInfo>) -> Result<Self::Data>;

    /// PCI driver remove.
    ///
    /// Called when a platform device is removed.
    /// Implementers should prepare the device for complete removal here.
    fn remove(_data: &Self::Data);
}

/// flags for IRQ allocation
pub mod irq_flags {
    /// Allow legacy interrupts
    pub const LEGACY: u32 = bindings::PCI_IRQ_LEGACY;
    /// Allow MSI interrupts
    pub const MSI: u32 = bindings::PCI_IRQ_MSI;
    /// Allow MSI-X interrupts
    pub const MSIX: u32 = bindings::PCI_IRQ_MSIX;
    /// Allow all types of interrupts
    pub const ALL_TYPES: u32 =
        bindings::PCI_IRQ_LEGACY | bindings::PCI_IRQ_MSI | bindings::PCI_IRQ_MSIX;
    /// Auto-assign affinity
    pub const AFFINITY: u32 = bindings::PCI_IRQ_AFFINITY;
}

/// A PCI device.
///
/// # Invariants
///
/// The field `ptr` is non-null and valid for the lifetime of the object.
pub struct Device {
    ptr: *mut bindings::pci_dev,
    enabled: bool,
    bars: i32,
}

impl Device {
    unsafe fn from_ptr(ptr: *mut bindings::pci_dev) -> Self {
        Self {
            ptr,
            enabled: false,
            bars: 0,
        }
    }

    /// enables bus-mastering for device
    pub fn set_master(&self) {
        unsafe { bindings::pci_set_master(self.ptr) };
    }

    /// Initialize device
    pub fn enable_device(&mut self) -> Result {
        let ret = unsafe { bindings::pci_enable_device(self.ptr) };
        if ret != 0 {
            Err(Error::from_kernel_errno(ret))
        } else {
            self.enabled = true;
            Ok(())
        }
    }

    /// Return BAR mask from the type of resource
    pub fn select_bars(&self, flags: core::ffi::c_ulong) -> i32 {
        unsafe { bindings::pci_select_bars(self.ptr, flags) }
    }

    /// Reserve selected PCI I/O and memory resources
    pub fn request_selected_regions(&mut self, bars: i32, name: &'static CStr) -> Result {
        let ret =
            unsafe { bindings::pci_request_selected_regions(self.ptr, bars, name.as_char_ptr()) };
        if ret != 0 {
            Err(Error::from_kernel_errno(ret))
        } else {
            self.bars |= bars;
            Ok(())
        }
    }

    /// Get address for accessing the device
    pub fn map_resource(&self, index: usize, len: usize) -> Result<MappedResource> {
        let pdev = unsafe { &*self.ptr };

        if index >= pdev.resource.len() {
            return Err(EINVAL);
        }

        if pdev.resource[index].start > pdev.resource[index].end
            || len > (pdev.resource[index].end - pdev.resource[index].start).try_into()?
        {
            return Err(EINVAL);
        }

        MappedResource::try_new(pdev.resource[index].start, len)
    }

    /// allocate multiple IRQs for a device
    pub fn alloc_irq_vectors(
        &mut self,
        min_vecs: u32,
        max_vecs: u32,
        flags: u32,
    ) -> Result<IrqVec> {
        IrqVec::new(self, min_vecs, max_vecs, flags)
    }
}

unsafe impl device::RawDevice for Device {
    fn raw_device(&self) -> *mut bindings::device {
        // SAFETY: By the type invariants, we know that `self.ptr` is non-null and valid.
        unsafe { &mut (*self.ptr).dev }
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        unsafe {
            // safe even if pci_set_master() wasn't executed.
            bindings::pci_clear_master(self.ptr);
            if self.enabled {
                bindings::pci_disable_device(self.ptr);
            }
            bindings::pci_release_selected_regions(self.ptr, self.bars);
        }
    }
}

/// allocated IRQs
pub struct IrqVec {
    ptr: *mut bindings::pci_dev,
}

impl IrqVec {
    fn new(dev: &Device, min_vecs: u32, max_vecs: u32, flags: u32) -> Result<Self> {
        let ret = unsafe {
            bindings::pci_alloc_irq_vectors_affinity(
                dev.ptr,
                min_vecs,
                max_vecs,
                flags,
                core::ptr::null_mut(),
            )
        };
        if ret < 0 {
            return Err(Error::from_kernel_errno(ret));
        }
        unsafe {
            bindings::get_device(dev.raw_device());
        }
        Ok(IrqVec { ptr: dev.ptr })
    }

    /// allocate an interrupt line for a PCI device
    pub fn request_irq<T: irq::Handler>(
        &self,
        index: u32,
        data: T::Data,
        name_args: fmt::Arguments<'_>,
    ) -> Result<irq::Registration<T>> {
        let ret = unsafe { bindings::pci_irq_vector(self.ptr, index) };
        if ret < 0 {
            return Err(Error::from_kernel_errno(ret));
        }
        irq::Registration::try_new(ret as _, data, irq::flags::SHARED, name_args)
    }
}

impl Drop for IrqVec {
    fn drop(&mut self) {
        unsafe {
            bindings::pci_free_irq_vectors(self.ptr);
            bindings::put_device(Device::from_ptr(self.ptr).raw_device());
        }
    }
}

unsafe impl Send for IrqVec {}
unsafe impl Sync for IrqVec {}

/// Address for accessing the device
/// io_mem.rs requires const size but some drivers have to handle
/// non const size with ioremap().
pub struct MappedResource {
    ptr: usize,
    len: usize,
}

macro_rules! define_read {
    ($(#[$attr:meta])* $name:ident, $type_name:ty) => {
        /// Reads IO data from the given offset
        $(#[$attr])*
        #[inline]
        pub fn $name(&self, offset: usize) -> Result<$type_name> {
            if offset + core::mem::size_of::<$type_name>() > self.len {
                return Err(EINVAL);
            }
            let ptr = self.ptr.wrapping_add(offset);
            Ok(unsafe { bindings::$name(ptr as _) })
        }
    };
}

macro_rules! define_write {
    ($(#[$attr:meta])* $name:ident, $type_name:ty) => {
        /// Writes IO data to the given offset
        $(#[$attr])*
        #[inline]
        pub fn $name(&self, value: $type_name, offset: usize) -> Result {
            if offset + core::mem::size_of::<$type_name>() > self.len {
                return Err(EINVAL);
            }
            let ptr = self.ptr.wrapping_add(offset);
            unsafe { bindings::$name(value, ptr as _) };
            Ok(())
        }
   };
}

impl MappedResource {
    fn try_new(offset: bindings::resource_size_t, len: usize) -> Result<Self> {
        let addr = unsafe { bindings::ioremap(offset, len as _) };
        if addr.is_null() {
            Err(ENOMEM)
        } else {
            Ok(Self {
                ptr: addr as usize,
                len,
            })
        }
    }

    define_read!(readb, u8);
    define_read!(readb_relaxed, u8);
    define_read!(readw, u16);
    define_read!(readw_relaxed, u16);
    define_read!(readl, u32);
    define_read!(readl_relaxed, u32);
    define_read!(
        #[cfg(CONFIG_64BIT)]
        readq,
        u64
    );
    define_read!(
        #[cfg(CONFIG_64BIT)]
        readq_relaxed,
        u64
    );

    define_write!(writeb, u8);
    define_write!(writeb_relaxed, u8);
    define_write!(writew, u16);
    define_write!(writew_relaxed, u16);
    define_write!(writel, u32);
    define_write!(writel_relaxed, u32);
    define_write!(
        #[cfg(CONFIG_64BIT)]
        writeq,
        u64
    );
    define_write!(
        #[cfg(CONFIG_64BIT)]
        writeq_relaxed,
        u64
    );
}

impl Drop for MappedResource {
    fn drop(&mut self) {
        unsafe {
            bindings::iounmap(self.ptr as _);
        }
    }
}

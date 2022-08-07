// SPDX-License-Identifier: GPL-2.0

//! PCI devices and drivers.
//!
//! C header: [`include/linux/pci.h`](../../../../include/linux/pci.h)

#![allow(dead_code)]

use crate::{
    bindings, device, driver,
    error::{from_kernel_result, Result},
    str::CStr,
    to_result,
    types::PointerWrapper,
    ThisModule,
};

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
        pdrv.id_table = T::ID_TABLE.as_ptr();
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
            let id: bindings::pci_device_id = unsafe {*id};
            let data = T::probe(&mut dev, DeviceId::from(id))?;
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
    /// Data private to the driver
    pub driver_data: u64,
    /// Match only when dev->driver_override is this driver
    pub override_only: u32,
}

impl DeviceId {
    const PCI_ANY_ID: u32 = !0;

    /// zeroed().
    pub const ZERO: DeviceId = DeviceId {
        vendor: 0,
        device: 0,
        subvendor: 0,
        subdevice: 0,
        class: 0,
        class_mask: 0,
        driver_data: 0,
        override_only: 0,
    };

    const BINDINGS_ZERO: bindings::pci_device_id = bindings::pci_device_id {
        vendor: 0,
        device: 0,
        subvendor: 0,
        subdevice: 0,
        class: 0,
        class_mask: 0,
        driver_data: 0,
        override_only: 0,
    };

    /// PCI_DEVICE macro.
    pub const fn new(vendor: u32, device: u32) -> Self {
        Self {
            vendor,
            device,
            subvendor: DeviceId::PCI_ANY_ID,
            subdevice: DeviceId::PCI_ANY_ID,
            class: 0,
            class_mask: 0,
            driver_data: 0,
            override_only: 0,
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
            driver_data: 0,
            override_only: 0,
        }
    }
}

impl From<bindings::pci_device_id> for DeviceId {
    fn from(id: bindings::pci_device_id) -> Self {
        DeviceId {
            vendor: id.vendor,
            device: id.device,
            subvendor: id.subvendor,
            subdevice: id.subdevice,
            class: id.class,
            class_mask: id.class_mask,
            driver_data: id.driver_data,
            override_only: id.override_only,
        }
    }
}

/// A zero-terminated PCI device id array
pub struct IdArray<const N: usize> {
    /// array of bindings::pci_device_id
    pub id_info: [bindings::pci_device_id; N],
}

impl<const N: usize> IdArray<N> {
    /// used by define_pci_id_table macro.
    pub const fn new(ids: [DeviceId; N]) -> Self {
        let mut array = Self {
            id_info: [DeviceId::BINDINGS_ZERO; N],
        };
        let mut i = 0;
        while i < N {
            let d = &ids[i];
            array.id_info[i] = bindings::pci_device_id {
                vendor: d.vendor,
                device: d.device,
                subvendor: d.subvendor,
                subdevice: d.subdevice,
                class: d.class,
                class_mask: d.class_mask,
                driver_data: d.driver_data,
                override_only: d.override_only,
            };
            i += 1;
        }
        array
    }
}

/// count entries.
#[macro_export]
macro_rules! count_exprs {
    () => {0usize};
    ($head:expr, $($tail:expr,)*) => {1usize + $crate::count_exprs!($($tail,)*)};
}

/// Defines PCI device id table.
#[macro_export]
macro_rules! define_pci_id_table {
    ($($e:expr),*) => {
        const ID_TABLE: &'static [bindings::pci_device_id] = {
            const ARRAY: IdArray<{ $crate::count_exprs!($($e,)*)+1}> = IdArray::new([$($e),*, DeviceId::ZERO]);
            &ARRAY.id_info
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
    /// never move the underlying wrapped data structure. This allows
    type Data: PointerWrapper + Send + Sync + driver::DeviceRemoval = ();

    /// The table of device ids supported by the driver.
    const ID_TABLE: &'static [bindings::pci_device_id];

    /// PCI driver probe.
    ///
    /// Called when a new platform device is added or discovered.
    /// Implementers should attempt to initialize the device here.
    fn probe(dev: &mut Device, id: DeviceId) -> Result<Self::Data>;

    /// PCI driver remove.
    ///
    /// Called when a platform device is removed.
    /// Implementers should prepare the device for complete removal here.
    fn remove(_data: &Self::Data);
}

/// A PCI device.
///
/// # Invariants
///
/// The field `ptr` is non-null and valid for the lifetime of the object.
pub struct Device {
    ptr: *mut bindings::pci_dev,
}

impl Device {
    unsafe fn from_ptr(ptr: *mut bindings::pci_dev) -> Self {
        Self { ptr }
    }
}

unsafe impl device::RawDevice for Device {
    fn raw_device(&self) -> *mut bindings::device {
        // SAFETY: By the type invariants, we know that `self.ptr` is non-null and valid.
        unsafe { &mut (*self.ptr).dev }
    }
}

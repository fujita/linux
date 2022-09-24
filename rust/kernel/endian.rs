// SPDX-License-Identifier: GPL-2.0

//! Endian integer types

macro_rules! define_le_integer {
    ($name:ident, $native_type:ty) => {
        /// little-endian integer
        #[allow(non_camel_case_types)]
        #[derive(Default, Clone, Copy)]
        #[repr(transparent)]
        pub struct $name($native_type);

        impl From<$native_type> for $name {
            #[cfg(target_endian = "little")]
            fn from(v: $native_type) -> Self {
                Self(v)
            }
            #[cfg(target_endian = "big")]
            fn from(v: $native_type) -> Self {
                Self(<$native_type>::from_le(v))
            }
        }

        impl From<$name> for $native_type {
            #[cfg(target_endian = "little")]
            fn from(v: $name) -> Self {
                v.0
            }
            #[cfg(target_endian = "big")]
            fn from(v: $name) -> Self {
                <$native_type>::from_le(v.0)
            }
        }
    };
}

macro_rules! define_be_integer {
    ($name:ident, $native_type:ty) => {
        /// big-endian integer
        #[allow(non_camel_case_types)]
        #[derive(Default, Clone, Copy)]
        #[repr(transparent)]
        pub struct $name($native_type);

        impl From<$native_type> for $name {
            #[cfg(target_endian = "little")]
            fn from(v: $native_type) -> Self {
                Self(<$native_type>::from_be(v))
            }
            #[cfg(target_endian = "big")]
            fn from(v: $native_type) -> Self {
                Self(v)
            }
        }

        impl From<$name> for $native_type {
            #[cfg(target_endian = "little")]
            fn from(v: $name) -> Self {
                <$native_type>::from_be(v.0)
            }
            #[cfg(target_endian = "big")]
            fn from(v: $name) -> Self {
                v.0
            }
        }
    };
}

define_le_integer!(le64, u64);
define_le_integer!(le32, u32);
define_le_integer!(le16, u16);

define_be_integer!(be64, u64);
define_be_integer!(be32, u32);
define_be_integer!(be16, u16);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_size() {
        assert_eq!(core::mem::size_of::<be16>(), core::mem::size_of::<u16>());
        assert_eq!(core::mem::size_of::<be32>(), core::mem::size_of::<u32>());
        assert_eq!(core::mem::size_of::<be64>(), core::mem::size_of::<u64>());
        assert_eq!(core::mem::size_of::<le16>(), core::mem::size_of::<u16>());
        assert_eq!(core::mem::size_of::<le32>(), core::mem::size_of::<u32>());
        assert_eq!(core::mem::size_of::<le64>(), core::mem::size_of::<u64>());
    }

    #[test]
    fn test_le16() {
        let n = 0x1Au16;
        if cfg!(target_endian = "big") {
            assert_eq!(le16::from(n).0, n.swap_bytes());
            assert_eq!(u16::from(le16::from(n)), n);
        } else {
            assert_eq!(le16::from(n).0, n);
            assert_eq!(u16::from(le16::from(n)), n);
        }
    }

    #[test]
    fn test_le32() {
        let n = 0x1Au32;
        if cfg!(target_endian = "big") {
            assert_eq!(le32::from(n).0, n.swap_bytes());
            assert_eq!(u32::from(le32::from(n)), n);
        } else {
            assert_eq!(le32::from(n).0, n);
            assert_eq!(u32::from(le32::from(n)), n);
        }
    }

    #[test]
    fn test_le64() {
        let n = 0x1Au64;
        if cfg!(target_endian = "big") {
            assert_eq!(le64::from(n).0, n.swap_bytes());
            assert_eq!(u64::from(le64::from(n)), n);
        } else {
            assert_eq!(le64::from(n).0, n);
            assert_eq!(u64::from(le64::from(n)), n);
        }
    }

    #[test]
    fn test_be16() {
        let n = 0x1Au16;
        if cfg!(target_endian = "big") {
            assert_eq!(be16::from(n).0, n);
            assert_eq!(u16::from(be16::from(n)), n);
        } else {
            assert_eq!(be16::from(n).0, n.swap_bytes());
            assert_eq!(u16::from(be16::from(n)), n);
        }
    }

    #[test]
    fn test_be32() {
        let n = 0x1Au32;
        if cfg!(target_endian = "big") {
            assert_eq!(be32::from(n).0, n);
            assert_eq!(u32::from(be32::from(n)), n);
        } else {
            assert_eq!(be32::from(n).0, n.swap_bytes());
            assert_eq!(u32::from(be32::from(n)), n);
        }
    }

    #[test]
    fn test_be64() {
        let n = 0x1Au64;
        if cfg!(target_endian = "big") {
            assert_eq!(be64::from(n).0, n);
            assert_eq!(u64::from(be64::from(n)), n);
        } else {
            assert_eq!(be64::from(n).0, n.swap_bytes());
            assert_eq!(u64::from(be64::from(n)), n);
        }
    }
}

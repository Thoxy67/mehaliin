use std::slice;

/// This trait provides an ability to for reading a value from memory at a given
/// address.
///
/// # Examples
///
/// ```
/// fn main() {
///     let addr = 0x1000;
///
///     // This read an u16 value in the 0x1000 internal memory address
///     let val: u16 = ReadFromMemory::read::<u16>(addr);
///     println!("Value: {}", val);
///
///     // This read an String value with a size of 5 in the 0x1000 internal memory address
///     let str_val = ReadFromMemory::read_sized::<String>(addr, 5);
///     println!("String: \"{}\"", str_val);
/// }
/// ```
pub unsafe trait ReadFromMemory {
    /// Reads a single value of the implementing type from the provided memory
    /// address.
    fn read_from_memory(address: usize) -> Self;
    /// Reads multiple values of the implementing type from the provided memory
    /// address with the specified size.
    fn read_from_memory_sized(address: usize, size: usize) -> Self;
}

unsafe impl ReadFromMemory for u8 {
    fn read_from_memory(address: usize) -> Self {
        (unsafe { *((address) as *const Self) }) as Self
    }

    fn read_from_memory_sized(address: usize, _size: usize) -> Self {
        return Self::read_from_memory(address);
    }
}

unsafe impl ReadFromMemory for u16 {
    fn read_from_memory(address: usize) -> Self {
        (unsafe { *((address) as *const Self) }) as Self
    }

    fn read_from_memory_sized(address: usize, _size: usize) -> Self {
        return Self::read_from_memory(address);
    }
}

unsafe impl ReadFromMemory for u32 {
    fn read_from_memory(address: usize) -> Self {
        (unsafe { *((address) as *const Self) }) as Self
    }

    fn read_from_memory_sized(address: usize, _size: usize) -> Self {
        return Self::read_from_memory(address);
    }
}

unsafe impl ReadFromMemory for u64 {
    fn read_from_memory(address: usize) -> Self {
        (unsafe { *((address) as *const Self) }) as Self
    }

    fn read_from_memory_sized(address: usize, _size: usize) -> Self {
        return Self::read_from_memory(address);
    }
}

unsafe impl ReadFromMemory for i8 {
    fn read_from_memory(address: usize) -> Self {
        (unsafe { *((address) as *const Self) }) as Self
    }

    fn read_from_memory_sized(address: usize, _size: usize) -> Self {
        return Self::read_from_memory(address);
    }
}

unsafe impl ReadFromMemory for i16 {
    fn read_from_memory(address: usize) -> Self {
        (unsafe { *((address) as *const Self) }) as Self
    }

    fn read_from_memory_sized(address: usize, _size: usize) -> Self {
        return Self::read_from_memory(address);
    }
}

unsafe impl ReadFromMemory for i32 {
    fn read_from_memory(address: usize) -> Self {
        (unsafe { *((address) as *const Self) }) as Self
    }

    fn read_from_memory_sized(address: usize, _size: usize) -> Self {
        return Self::read_from_memory(address);
    }
}

unsafe impl ReadFromMemory for i64 {
    fn read_from_memory(address: usize) -> Self {
        (unsafe { *((address) as *const Self) }) as Self
    }

    fn read_from_memory_sized(address: usize, _size: usize) -> Self {
        return Self::read_from_memory(address);
    }
}

unsafe impl ReadFromMemory for f32 {
    fn read_from_memory(address: usize) -> Self {
        (unsafe { *((address) as *const Self) }) as Self
    }

    fn read_from_memory_sized(address: usize, _size: usize) -> Self {
        return Self::read_from_memory(address);
    }
}

unsafe impl ReadFromMemory for f64 {
    fn read_from_memory(address: usize) -> Self {
        (unsafe { *((address) as *const Self) }) as Self
    }

    fn read_from_memory_sized(address: usize, _size: usize) -> Self {
        return Self::read_from_memory(address);
    }
}

unsafe impl ReadFromMemory for isize {
    fn read_from_memory(address: usize) -> Self {
        (unsafe { *((address) as *const Self) }) as Self
    }

    fn read_from_memory_sized(address: usize, _size: usize) -> Self {
        return Self::read_from_memory(address);
    }
}

unsafe impl ReadFromMemory for usize {
    fn read_from_memory(address: usize) -> Self {
        (unsafe { *((address) as *const Self) }) as Self
    }

    fn read_from_memory_sized(address: usize, _size: usize) -> Self {
        return Self::read_from_memory(address);
    }
}

// Implementation for slices of bytes (&[u8])
unsafe impl ReadFromMemory for &[u8] {
    fn read_from_memory_sized(address: usize, size: usize) -> Self {
        unsafe { slice::from_raw_parts(address as *const u8, size) }
    }

    fn read_from_memory(_address: usize) -> Self {
        panic!("read_from_memory need to bee sized for &[u8] use read_from_memory_sized instead");
    }
}

// Implementation for String using byte-slice implementation
unsafe impl ReadFromMemory for String {
    fn read_from_memory_sized(address: usize, size: usize) -> Self {
        String::from_utf8_lossy(unsafe { slice::from_raw_parts(address as *const u8, size) })
            .to_string()
    }

    fn read_from_memory(_address: usize) -> Self {
        panic!("read_from_memory need to bee sized for String use read_from_memory_sized instead");
    }
}

/// Function that reads an instance of any type implementing `ReadFromMemory` by
/// calling its `read_from_memory` method.
///
/// # Arguments
///
/// * `address` : The starting point from where the value should be read from
///   memory.
///
/// # Returns
///
/// An instance of generic type T which implements `ReadFromMemory`.
pub fn read<T: ReadFromMemory>(address: usize) -> T {
    // assert!(address % T::SIZE == 0, "Address must be aligned");
    T::read_from_memory(address)
}

/// Function that reads an instance of any type implementing `ReadFromMemory` by
/// calling its `read_from_memory_sized` method.
///
/// # Arguments
///
/// * `address` : The starting point from where the sequence of values should be
///   read from memory.
/// * `size` : Number of instances of the type to read from memory.
///
/// # Returns
///
/// A sequence containing 'size' number of instances of generic type T which
/// implements `ReadFromMemory`.
pub fn read_sized<T: ReadFromMemory>(address: usize, size: usize) -> T {
    // assert!(address % T::SIZE == 0, "Address must be aligned");
    T::read_from_memory_sized(address, size)
}

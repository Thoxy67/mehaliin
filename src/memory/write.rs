use std::ptr;

/// This trait provides an ability to write a value of type `Self` into memory
/// at the given address.
///
/// # Examples
///
/// To use it simply call it with :
///
/// ```
/// fn main() {
///     // This write a u16 of value 10 in the 0x1000 internal memory address
///     ReadFromMemory::write(0x1000, 10u16);
/// }
/// ```
pub unsafe trait WriteToMemory {
    /// Writes the `value` into memory at the specified `address`.
    /// # Arguments
    /// * `address` - The destination address in memory to write to.
    /// * `value` - The value to write to memory.
    fn write_to_memory(address: usize, value: Self)
    where
        Self: Sized;
}

unsafe impl WriteToMemory for u8 {
    fn write_to_memory(address: usize, value: Self) {
        unsafe { ptr::from_exposed_addr_mut::<Self>(address).write(value) };
    }
}

unsafe impl WriteToMemory for u16 {
    fn write_to_memory(address: usize, value: Self) {
        unsafe { ptr::from_exposed_addr_mut::<Self>(address).write(value) };
    }
}

unsafe impl WriteToMemory for u32 {
    fn write_to_memory(address: usize, value: Self) {
        unsafe { ptr::from_exposed_addr_mut::<Self>(address).write(value) };
    }
}

unsafe impl WriteToMemory for u64 {
    fn write_to_memory(address: usize, value: Self) {
        unsafe { ptr::from_exposed_addr_mut::<Self>(address).write(value) };
    }
}

unsafe impl WriteToMemory for i8 {
    fn write_to_memory(address: usize, value: Self) {
        unsafe { ptr::from_exposed_addr_mut::<Self>(address).write(value) };
    }
}

unsafe impl WriteToMemory for i16 {
    fn write_to_memory(address: usize, value: Self) {
        unsafe { ptr::from_exposed_addr_mut::<Self>(address).write(value) };
    }
}

unsafe impl WriteToMemory for i32 {
    fn write_to_memory(address: usize, value: Self) {
        unsafe { ptr::from_exposed_addr_mut::<Self>(address).write(value) };
    }
}

unsafe impl WriteToMemory for i64 {
    fn write_to_memory(address: usize, value: Self) {
        unsafe { ptr::from_exposed_addr_mut::<Self>(address).write(value) };
    }
}

unsafe impl WriteToMemory for f32 {
    fn write_to_memory(address: usize, value: Self) {
        unsafe { ptr::from_exposed_addr_mut::<Self>(address).write(value) };
    }
}

unsafe impl WriteToMemory for f64 {
    fn write_to_memory(address: usize, value: Self) {
        unsafe { ptr::from_exposed_addr_mut::<Self>(address).write(value) };
    }
}

/// Caution: This code assumes the use of ASCII characters only. ⚠️
///
/// To handle strings with a different character encoding, first convert the
/// string to a byte array using the WriteToMemory::<&[u8]>() method, and then
/// convert it to your desired string format.
unsafe impl WriteToMemory for String {
    fn write_to_memory(address: usize, value: Self) {
        let b: &[u8] = value.as_bytes();

        for i in 0..value.len() - 1 {
            unsafe { std::ptr::from_exposed_addr_mut::<u8>(address + i).write_bytes(b[i], 1) };
        }
    }
}

unsafe impl WriteToMemory for &[u8] {
    fn write_to_memory(address: usize, value: Self) {
        for i in 0..value.len() - 1 {
            unsafe { std::ptr::from_exposed_addr_mut::<u8>(address + i).write_bytes(value[i], 1) };
        }
    }
}

/// Writes a value of any type implementing the `WriteToMemory` trait into
/// memory at the given address. # Arguments
/// * `address` - The destination address in memory to write to.
/// * `value` - The value to write to memory.
pub fn write<T: WriteToMemory>(address: usize, value: T) {
    // assert!(address % T::SIZE == 0, "Address must be aligned");
    T::write_to_memory(address, value);
}

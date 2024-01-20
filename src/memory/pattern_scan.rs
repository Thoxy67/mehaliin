use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::ptr::null;

use super::utils::{get_current_base_address, get_module_base_address};

extern "C" {
    #[link_name = "pattern_scan"]
    fn u_pattern_scan(signature: *const c_char, module_name: *const c_char) -> *const c_int;
}

/// Performs a pattern scan using the provided signature and optional module
/// name.
///
/// The pattern scan searches through memory for a sequence of bytes matching
/// the specified signature. If a module name is provided, the search will be
/// limited to the memory region corresponding to that module. Otherwise, the
/// entire address space of the process will be searched.
///
/// # Arguments
///
/// * `pattern`: A reference to a string representing the byte sequence to
///   search for in hexadecimal format using IDA format, with possible wildcard
///   characters '?'. For example, "48 8B 05 ? ? C0 ?" would represent any 6
///   bytes where the first one is 0x48, the second is 0x8B, the third can be
///   anything, etc.
/// * `module_name`: An optional reference to a string specifying the name of
///   the module to limit the search to. If left as `None`, the entire address
///   space of the process will be searched.
///
/// # Returns
///
/// A pointer to the starting address of the first occurrence of the pattern
/// within the specified module or the entire address space of the process,
/// converted to a `usize`. Returns `0` if no occurrences are found.
///
/// # Examples
///
/// ```
/// fn main() {
///     // Make a pattern scan on the Main module
///     let val: usize = memory::pattern_scan("48 8B 05 ? ? C0 ?", None);
///     println!("Address: 0x{}", val); // print the address found
///
///     // Make a pattern scan on the "my_module.dll"
///     let val: usize = memory::pattern_scan("48 8B 05 ? ? C0 ?", "my_module.dll");
///     println!("Address: 0x{}", val); // print the address found
/// }
/// ```
///
/// # Safety
///
/// This function uses raw pointers and calls external FFI functions which may
/// have undefined behavior if used incorrectly. Users should ensure they
/// understand the risks associated with these operations before calling this
/// function. Additionally, the returned values must not be used after the
/// current process has been terminated or modified in ways that affect
/// memory layout.
pub fn pattern_scan(pattern: &str, module_name: Option<&str>) -> usize {
    let pattern = CString::new(pattern).expect("CString::new failed");
    match module_name {
        Some(module) => {
            let name = CString::new(module).expect("CString::new failed");
            return unsafe {
                u_pattern_scan(
                    pattern.as_ptr() as *const c_char,
                    name.as_ptr() as *const c_char,
                )
            } as usize;
        }
        None => {
            return unsafe {
                u_pattern_scan(
                    pattern.as_ptr() as *const ::std::os::raw::c_char,
                    null() as *const ::std::os::raw::c_char,
                )
            } as usize
        }
    }
}

/// Searches for an instruction pointer (IP) within the specified module or
/// the entire address space of the process that matches the given pattern.
///
/// This function performs a pattern scan similar to the `pattern_scan`
/// function but returns additional information about the matched IP, such
/// as its offset relative to the base address of the module and the name
/// of the module itself.
///
/// # Arguments
///
/// * `pattern`: A reference to a string representing the byte sequence to
///   search for in hexadecimal format, with possible wildcard characters '?'.
/// * `module_name`: An optional reference to a string specifying the name of
///   the module to limit the search to. If left as `None`, the search will be
///   performed across the entire address space of the process.
///
/// # Returns
///
/// An option containing a tuple of four elements:
/// 1. The virtual address of the matched IP, represented as a `usize`.
/// 2. The offset of the matched IP from the base address of the module, also
///    represented as a `usize`.
/// 3. The base address of the module, represented as a `usize`.
/// 4. The name of the module as a `String`.
///
/// If no matches are found, this function returns `None`.
///
/// # Examples
///
/// ```
/// fn main() {
///     // Make a pattern scan on the Main module
///     match memory::pattern_pointer_scan("48 8B 05 ? ? C0 ?", None) {
///         Some(found) => {
///             println!(
///                 "Final Address: 0x{}, Offset: 0x{}, BaseAddress: 0x{}, Module: {} ",
///                 found.0, found.1, found.2, found.3
///             );
///         },
///         None => {
///             println!("not found");
///         },
///     }
/// }
/// ```
///
/// # Safety
///
/// This function uses raw pointers and calls external FFI functions which may
/// have undefined behavior if used incorrectly. Users should ensure they
/// understand the risks associated with these operations before calling this
/// function. Additionally, the returned values must not be used after the
/// current process has been terminated or modified in ways that affect
/// memory layout.
pub fn pattern_pointer_scan(
    pattern: &str,
    module_name: Option<&str>,
) -> Option<(usize, usize, usize, String)> {
    let (base_address, _, name) = if let Some(module_name) = module_name {
        match get_module_base_address(module_name) {
            Ok(addr) => addr,
            Err(_) => return None,
        }
    } else {
        match get_current_base_address() {
            Ok(addr) => addr,
            Err(_) => return None,
        }
    };

    let pattern = CString::new(pattern).expect("CString::new failed");
    match module_name {
        Some(n) => {
            let final_address = unsafe {
                u_pattern_scan(
                    pattern.as_ptr() as *const c_char,
                    n.as_ptr() as *const c_char,
                )
            };
            return Some((
                final_address as usize,
                final_address as usize - base_address as usize,
                base_address as usize,
                name,
            ));
        }
        None => {
            let final_address = unsafe {
                u_pattern_scan(pattern.as_ptr() as *const c_char, null() as *const c_char)
            };
            return Some((
                final_address as usize,
                final_address as usize - base_address as usize,
                base_address as usize,
                name,
            ));
        }
    }
}

use windows::core::PCSTR;
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetModuleHandleW};

#[cfg(feature = "CPP_PATERN_SCAN")]
extern "C" {
    #[link_name = "pattern_scan"]
    fn u_pattern_scan(
        signature: *const std::os::raw::c_char,
        module_name: *const std::os::raw::c_char,
    ) -> *const std::os::raw::c_int;
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
#[cfg(feature = "CPP_PATERN_SCAN")]
pub fn pattern_scan(pattern: &str, module_name: Option<&str>) -> usize {
    let pattern = std::ffi::CString::new(pattern).expect("CString::new failed");
    match module_name {
        Some(module) => {
            let name = std::ffi::CString::new(module).expect("CString::new failed");
            return unsafe {
                u_pattern_scan(
                    pattern.as_ptr() as *const std::os::raw::c_char,
                    name.as_ptr() as *const std::os::raw::c_char,
                )
            } as usize;
        }
        None => {
            return unsafe {
                u_pattern_scan(
                    pattern.as_ptr() as *const ::std::os::raw::c_char,
                    std::ptr::null() as *const ::std::os::raw::c_char,
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
#[cfg(feature = "CPP_PATERN_SCAN")]
pub fn pattern_pointer_scan(
    pattern: &str,
    module_name: Option<&str>,
) -> Option<(usize, usize, usize, String)> {
    let (base_address, _, name) = if let Some(module_name) = module_name {
        match super::utils::get_module_base_address(module_name) {
            Ok(addr) => addr,
            Err(_) => return None,
        }
    } else {
        match super::utils::get_current_base_address() {
            Ok(addr) => addr,
            Err(_) => return None,
        }
    };

    let final_address = pattern_scan(pattern, module_name);
    return Some((
        final_address as usize,
        final_address as usize - base_address as usize,
        base_address as usize,
        name,
    ));
}

/// Retrieves a handle to the loaded module with the specified name or returns the handle of the currently executing image.
///
/// This function accepts either a null-terminated UTF-8 encoded wide string (when providing a module name) or a null pointer (when searching for the current executable image).
/// When passing a module name, the function looks up the base address of the DLL or EXE file in the application's address space. In case of success, it returns an opaque handle to the module.
/// On the other hand, when passing a null pointer, the function retrieves the base address of the running program itself.
///
/// # Arguments
///
/// * module_name: Optional parameter indicating the name of the desired module. Use None to retrieve the handle of the current executing image.
///
/// # Return Value
///
/// Returns an opaque handle to the requested module (HMODULE type alias) wrapped inside an Option enum.
/// In case of errors like an invalid module name or failure during lookup, the result contains a None variant.
/// Successful lookups yield an Some wrapper around the actual handle.
pub fn get_hmodule(module_name: Option<&str>) -> HMODULE {
    match module_name {
        Some(name) => unsafe {
            GetModuleHandleA(PCSTR::from_raw(name.as_ptr() as *mut u8)).unwrap()
        },
        None => unsafe { GetModuleHandleW(None).unwrap() },
    }
}

/// Converts a given pattern represented as a string into a vector of i32.
///
/// The input string should contain hexadecimal digits separated by spaces,
/// with optional question marks ("?") acting as wildcards for unknown bytes.
/// Each pair of hexadecimal digits represents an individual byte, while
/// consecutive pairs may be combined into a single byte preceded by "a2-".
///
/// For example, the following inputs are valid patterns:
///
/// 1. "48 8b 05 ?? ?? c0 ?"
/// 2. "7e e8 18 00 00 66 68"
/// 3. "5428?3257??88"
///
/// Note that each group of two hexadecimal digits should always include exactly
/// two digits, except when using the "a2-" prefix to indicate combining them
/// into a single byte.
///
/// # Example
///
/// Here's how you might use this function:
///
/// ```
///  use my_crate::utils;
///  let pattern = "48 8b 05 ?? ?? c0 ?";
///  let bytes = utils::pattern_to_bytes(pattern);
///  assert!(matches!([48, 8b, 05, -1, -1, 0xc0, ?], bytes));
pub fn pattern_to_bytes(pattern: &str) -> Vec<i32> {
    let mut bytes = Vec::new();
    let mut a2dig = false;

    for (i, c) in pattern.char_indices() {
        match c {
            ' ' => {} // skip whitespace characters
            '?' => {
                if pattern.chars().nth(i + 1).map(|x| x == '?') == Some(true) {
                    continue;
                }
                bytes.push(-1);
            }
            _ => {
                if a2dig {
                    a2dig = false;
                    continue;
                }
                let next_c = pattern.chars().nth(i + 1).unwrap();
                let value = u8::from_str_radix(&format!("{}{}", c, next_c), 16).unwrap();
                bytes.push(value as i32);
                a2dig = true;
            }
        }
    }

    bytes
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
/// This function uses raw pointers which may
/// have undefined behavior if used incorrectly. Users should ensure they
/// understand the risks associated with these operations before calling this
/// function. Additionally, the returned values must not be used after the
/// current process has been terminated or modified in ways that affect
/// memory layout.
#[cfg(not(feature = "CPP_PATERN_SCAN"))]
pub fn pattern_scan(pattern: &str, module_name: Option<&str>) -> usize {
    let hmodule = get_hmodule(module_name);
    let mut modulei = windows::Win32::System::ProcessStatus::MODULEINFO::default();

    match unsafe {
        windows::Win32::System::ProcessStatus::GetModuleInformation(
            windows::Win32::System::Threading::GetCurrentProcess(),
            hmodule,
            &mut modulei,
            std::mem::size_of::<windows::Win32::System::ProcessStatus::MODULEINFO>()
                .try_into()
                .unwrap(),
        )
    } {
        Ok(_) => {
            let size_of_image = modulei.SizeOfImage as usize;
            let pattern_bytes = pattern_to_bytes(pattern);

            let scan_bytes: *const u8 = modulei.lpBaseOfDll as *const u8;

            for i in 0..size_of_image - pattern_bytes.len() {
                let mut found = true;

                for j in 0..pattern_bytes.len() {
                    if (unsafe { *((scan_bytes.add(i + j)) as *const u8) as i32 })
                        != pattern_bytes[j]
                        && pattern_bytes[j] != -1
                    {
                        found = false;
                        break;
                    }
                }
                if found {
                    return unsafe { (scan_bytes.add(i)) as usize };
                }
            }
        }
        Err(_) => {
            return 0;
        }
    };
    return 0;
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
/// This function uses raw pointers which may
/// have undefined behavior if used incorrectly. Users should ensure they
/// understand the risks associated with these operations before calling this
/// function. Additionally, the returned values must not be used after the
/// current process has been terminated or modified in ways that affect
/// memory layout.
#[cfg(not(feature = "CPP_PATERN_SCAN"))]
pub fn pattern_pointer_scan(
    pattern: &str,
    module_name: Option<&str>,
) -> Option<(usize, usize, usize, String)> {
    let (base_address, _, name) = if let Some(module_name) = module_name {
        match super::utils::get_module_base_address(module_name) {
            Ok(addr) => addr,
            Err(_) => return None,
        }
    } else {
        match super::utils::get_current_base_address() {
            Ok(addr) => addr,
            Err(_) => return None,
        }
    };
    let final_address = pattern_scan(pattern, module_name);
    return Some((
        final_address as usize,
        final_address as usize - base_address as usize,
        base_address as usize,
        name,
    ));
}

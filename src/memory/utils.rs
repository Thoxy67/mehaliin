use std::ffi::c_void;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32First, Module32Next, MODULEENTRY32, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

/// Obtains the base address of the currently running process along with the
/// module size and name.
///
/// This function retrieves the details of the primary module of the current
/// process.
///
/// # Returns
///
/// A Result containing the requested base address represented as a raw pointer
/// to constant c_void, the size of the module as u32, and the module name as
/// String, on success. Fails otherwise, returning an informative string
/// detailing the issue.
pub fn get_current_base_address() -> Result<(*const c_void, u32, String), String> {
    let a = unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, std::process::id())
    }
    .unwrap();
    let mut b: MODULEENTRY32 = MODULEENTRY32::default();
    b.dwSize = std::mem::size_of::<MODULEENTRY32>() as u32;
    match unsafe { Module32First(a, &mut b) } {
        Ok(_) => {
            let base_address: *const c_void = b.modBaseAddr.cast();
            let base_size = b.modBaseSize;
            let base_name = String::from_utf8_lossy(&b.szModule).to_string();
            b.dwSize;
            return Ok((base_address, base_size, base_name));
        },
        Err(_) => {
            return Err(
                format!("Error failed to enum process modules {}", std::process::id()).to_string()
            );
        },
    };
}

/// Retrieves the base address of the specified module by name along with the
/// module size and name.
///
/// This function searches for the module within the process modules and returns
/// its details upon finding.
///
/// # Arguments
///
/// * module : The lowercased module name to search base address.
///
/// # Returns
///
/// A Result containing the requested base address represented as a raw pointer
/// to constant c_void, the size of the module as u32, and the module name as
/// String, on success. Fails otherwise, returning an informative string
/// detailing the issue.
pub fn get_module_base_address(module: &str) -> Result<(*const c_void, u32, String), String> {
    let module_name = module.to_lowercase();
    let a = unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, std::process::id())
    }
    .unwrap();
    let mut b: MODULEENTRY32 = MODULEENTRY32::default();
    b.dwSize = std::mem::size_of::<MODULEENTRY32>() as u32;
    match unsafe { Module32First(a, &mut b) } {
        Ok(_) => {
            if String::from_utf8_lossy(&b.szModule).to_lowercase().contains(&module_name) {
                let base_address: *const c_void = b.modBaseAddr.cast();
                let base_size = b.modBaseSize;
                let base_name = String::from_utf8_lossy(&b.szModule).to_string();
                b.dwSize;
                return Ok((base_address, base_size, base_name));
            } else {
                loop {
                    match unsafe { Module32Next(a, &mut b) } {
                        Ok(_) => {
                            if String::from_utf8_lossy(&b.szModule)
                                .to_lowercase()
                                .contains(&module_name)
                            {
                                let base_address: *const c_void = b.modBaseAddr.cast();
                                let base_size = b.modBaseSize;
                                let base_name = String::from_utf8_lossy(&b.szModule).to_string();
                                b.dwSize;
                                return Ok((base_address, base_size, base_name));
                            }
                        },
                        Err(_) => break,
                    };
                }

                return Err(format!("Error failed to find module base address : {}", module_name)
                    .to_string());
            }
        },
        Err(_) => {
            return Err(
                format!("Error failed to enum process modules {}", std::process::id()).to_string()
            );
        },
    };
}

/// Calculates the final effective address of a target object given its base
/// address, relative address, and optional sequence of offsets.
///
/// This function is useful when working with tools like Cheat Engine. It takes
/// a base address, a relative address, and an optional list of additional
/// offsets to calculate the ultimate destination address by applying each
/// offset sequentially.
///
/// # Arguments
/// * `base_address`: A `usize` integer specifying the starting address where
///   the search begins.
/// * `relative_address`: Another `usize` integer indicating the displacement of
///   the target object relative to the base address.
/// * `offsets`: An optional vector of `usize` integers, specifying additional
///   offsets to apply sequentially to reach the ultimate destination address.
///
/// # Returns
/// A single `usize` integer representing the calculated absolute address of
/// the target object.
///
/// # Safety
/// This function performs multiple unchecked arithmetic operations and type
/// conversions on raw pointers, potentially involving misalignment corrections.
/// Make sure the input parameters accurately correspond to valid memory
/// locations accessible through your program. Improper usage might result in
/// undefined behavior, such as segmentation faults or erroneous calculations.
pub fn get_pointer_address(base_address: usize, address: usize, offsets: Vec<usize>) -> usize {
    let mut addr =
        unsafe { *((base_address as usize + address) as *const usize) + offsets[0] } as *mut c_void; // BINGO
    for i in 1..offsets.len() {
        addr = unsafe { *((addr) as *const usize) + offsets[i] } as *mut c_void;
    }
    return addr as usize;
}

/// Tries to acquire a handle to the current process with complete access
/// rights.
///
/// On success, returns a [`Result`] containing the acquired [`HANDLE`]. In case
/// of failure, any encountered errors are forwarded via
/// [`windows::core::Error`].
///
/// # Returns
/// A [`Result`] containing either the [`HANDLE`] to the current process or an
/// error.
///
/// # Safety
/// This function requires proper handling of Windows API calls and the correct
/// import statements. Refer to the examples above and make necessary
/// adjustments depending on your project setup. Using this function improperly
/// might cause unexpected behaviors or crashes.
#[allow(dead_code)]
pub fn get_handle() -> Result<HANDLE, windows::core::Error> {
    unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, std::process::id()).map(|h| h) }
}

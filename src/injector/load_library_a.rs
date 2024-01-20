use std::{ffi::CString, path::PathBuf};

use windows::Win32::{
    Foundation::CloseHandle,
    System::{
        Diagnostics::Debug::WriteProcessMemory,
        LibraryLoader::{GetModuleHandleA, GetProcAddress},
        Memory::{VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE},
        Threading::{
            CreateRemoteThread, OpenProcess, WaitForSingleObject, INFINITE, PROCESS_ALL_ACCESS,
        },
    },
};

/// Injects a dynamic link library (DLL) into another running process.
///
/// # Arguments
///
/// * `pid` - Process Identifier (PID) of the targeted process.
/// * `dll_path` - Absolute path of the DLL file to inject.
///
/// # Return Value
///
/// On success, returns `Ok(()). On failure, returns `Err(String)`.
///
/// # Error Handling
///
/// Possible errors include failing to access the target process, allocating memory inside it, writing data to its memory, creating remote threads, resuming those threads, closing handles, releasing allocated memory, or obtaining required API addresses.
///
/// # Examples
///
/// To inject `notepad.exe`, make sure you have placed a test DLL named `test.dll` alongside your compiled binary. Then execute the following code snippet in debug mode.
///
/// ```noexample
/// use std::path::PathBuf;
/// let exe_location = std::env::current_exe().unwrap();
/// let parent_directory = exe_location.parent().unwrap().to_owned();
/// let dll_path = PathBuf::from(parent_directory.join("test.dll"));
/// inject_dll(utils::get_process_id_by_name("notepad.exe").unwrap(), dll_path).unwrap();
/// ```
pub fn inject_dll(pid: u32, dll_path: PathBuf) -> Result<(), String> {
    let process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid) };
    if process.is_err() {
        return Err("Failed to open the target process.".to_string());
    }
    match process {
        Ok(p) => {
            let addr = unsafe {
                VirtualAllocEx(
                    p,
                    None,
                    dll_path.as_path().to_string_lossy().len(),
                    MEM_COMMIT,
                    PAGE_READWRITE,
                )
            };
            if addr.is_null() {
                return Err("Failed to allocate memory in the target process.".to_string());
            }
            match unsafe {
                WriteProcessMemory(
                    p,
                    addr,
                    dll_path.as_path().to_string_lossy().as_ptr() as *const std::ffi::c_void,
                    dll_path.as_path().to_string_lossy().len(),
                    None,
                )
            } {
                Ok(()) => {
                    let kernel32 = CString::new("kernel32.dll").expect("CString::new failed");
                    match unsafe {
                        GetModuleHandleA(windows::core::PCSTR::from_raw(
                            kernel32.as_ptr() as *const u8
                        ))
                    } {
                        Ok(hmodule) => {
                            let loadlibrarya =
                                CString::new("LoadLibraryA").expect("CString::new failed");
                            let h_loadlibrarya = unsafe {
                                GetProcAddress(
                                    hmodule,
                                    windows::core::PCSTR::from_raw(
                                        loadlibrarya.as_ptr() as *const u8
                                    ),
                                )
                            };
                            match unsafe {
                                CreateRemoteThread(
                                    p,
                                    None,
                                    0,
                                    Some(std::mem::transmute(h_loadlibrarya)),
                                    Some(addr as *const std::ffi::c_void),
                                    0,
                                    None,
                                )
                            } {
                                Ok(thread) => unsafe {
                                    WaitForSingleObject(thread, INFINITE);
                                    let _ = CloseHandle(thread);
                                    let _ = CloseHandle(p);
                                    let _ = VirtualFreeEx(p, addr, 0, MEM_RELEASE);
                                },
                                Err(_) => {
                                    return Err("Can't close Handle".to_string());
                                }
                            };
                        }
                        Err(_) => {
                            return Err("Failed to get module kernel32.dll".to_string());
                        }
                    }
                }
                Err(_) => {
                    return Err("Failed to write into the target process memory.".to_string());
                }
            }
        }
        Err(_) => {
            return Err("Failed to open the target process.".to_string());
        }
    }
    Ok(())
}

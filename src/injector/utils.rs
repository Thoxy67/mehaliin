use std::{
    env, fs,
    path::{Path, PathBuf},
};

use windows::Win32::{
    Foundation::CloseHandle,
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32First, Module32Next, MODULEENTRY32, TH32CS_SNAPMODULE,
        TH32CS_SNAPMODULE32,
    },
};

// Gets the base module address of a specified process and module name.
///
/// # Arguments
///
/// * `pid` - The process ID to look up.
/// * `module` - The name of the module to find within the process's memory space. Case-insensitive matching is used.
///
/// # Returns
///
/// A `Result` containing either the base address of the requested module or an error string explaining why it could not be retrieved.
///
/// # Examples
///
/// Basic example using hard-coded PID and module name values:
/// ```noexample
/// use std::result;
/// let opt_res = get_base_module_address(0x1234, "kernel32.dll");
/// if let Ok(val) = opt_res { println!("Found kernel32 at address {:#X}", val); }
/// else { println!("Couldn't retrieve kernel32 address: {}", opt_res.err().unwrap()); }
/// ```
/// Example looking up a specific process by name then finding its main executable module:
/// ```noexample
/// use std::result;
/// match get_process_id_by_name("powershell.exe") {
///     Ok(pid) => {
///         let opt_res = super::get_base_module_address(pid, "");
///         if let Ok(val) = opt_res { println!("PowerShell located at address {:#X}", val); }
///         else { println!("Couldn't retrieve PowerShell address: {}", opt_res.err().unwrap()); }
///     },
///     Err(e) => println!("Unable to locate powershell.exe: {}", e),
/// }
/// ```
pub fn get_base_module_address(pid: u32, module: &str) -> Result<*const u8, String> {
    let a =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) }.unwrap();
    let mut b: MODULEENTRY32 = MODULEENTRY32::default();
    b.dwSize = std::mem::size_of::<MODULEENTRY32>() as u32;
    match unsafe { Module32First(a, &mut b) } {
        Ok(_) => {
            let addr = b.modBaseAddr;
            loop {
                if String::from_utf8_lossy(&b.szModule)
                    .to_lowercase()
                    .starts_with(module)
                {
                    let _ = unsafe { CloseHandle(a) };
                    break;
                }
                match unsafe { Module32Next(a, &mut b) } {
                    Ok(_) => {
                        continue;
                    }
                    Err(_) => {
                        let _ = unsafe { CloseHandle(a) };
                        break;
                    }
                }
            }
            let _ = unsafe { CloseHandle(a) };
            return Ok(addr);
        }
        Err(_) => {
            return Err(format!(
                "Error failed to enum process modules {}",
                std::process::id()
            )
            .to_string());
        }
    };
}

// Finds the process identifier associated with a provided name.
///
/// # Arguments
///
/// * `process_name` - The display name of the desired process to locate.
///
/// # Returns
/// A `Result` containing either the process identifier (PID) as a `u32` value or an error message describing what went wrong during lookup.
///
/// # Examples
///
/// Lookup Chrome browser processes and terminate them all after printing their respective PIDs:
/// ```noexample
/// use std::result;
/// let chrome_procs = vec!["chrome.exe", "googlechrome.exe"];
/// for proc in chrome_procs {
///     match super::get_process_id_by_name(proc) {
///         Ok(pid) => {
///             println!("Process found on pid : {}", pid);
///         },
///         Err(e) => println!("Failed to locate process '{}': {}", proc, e),
///     }
/// }
/// ```
pub fn get_process_id_by_name(process_name: &str) -> Result<u32, String> {
    let sys = sysinfo::System::new_all();
    for (p, process) in sys.processes() {
        if process.name() == process_name {
            return Ok(p.as_u32());
        }
    }
    return Err(format!("{} process not found", process_name).to_string());
}

// Searches recursively from the application directory for any DLL files that can be loaded into memory.
///
/// # Arguments
///
/// * `p` - Optional predefined path string. If present, will start searching there instead of the app dir.
///
/// # Returns
///
/// A `Result` holding the first encountered file path ending with ".dll" extension or an error message detailing failure information.
///
/// # Examples
///
/// Demonstrating how you might call this method directly before loading a library via `load_library` helper:
/// ```noexample
/// use std::result;
/// match super::get_dll_path(Some("C:\Windows\system32".into())) {
///     Ok(file_path) => { println!("Loading dll..."); load_library(file_path.clone()).expect("Load Failed!");},
///     Err(e) => panic!("Failed to locate dll: {}", e),
/// }
/// ```
pub fn get_dll_path(p: Option<String>) -> Result<PathBuf, String> {
    match p {
        Some(pa) => {
            let pat = Path::new(&pa).to_path_buf();
            if pat.exists() {
                return Ok(pat);
            }
        }
        None => {}
    }

    let current_exe = env::current_exe().unwrap();
    let current_dir = current_exe.parent().unwrap().to_owned();

    match fs::read_dir(current_dir) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(entry) => {
                        if entry
                            .path()
                            .as_mut_os_string()
                            .to_string_lossy()
                            .ends_with(".dll")
                        {
                            return Ok(entry.path().to_path_buf());
                        }
                    }
                    Err(e) => return Err(format!("Error: {}", e).to_string()),
                }
            }
        }
        Err(e) => return Err(format!("Error: {}", e).to_string()),
    }

    return Err(format!("DLL not found").to_string());
}

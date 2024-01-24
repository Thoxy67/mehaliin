use std::env;
use std::path::Path;

fn main() {
    let root_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let target = env::var("TARGET").unwrap();

    let parts = target.splitn(4, '-').collect::<Vec<_>>();
    let sys = parts[2];

    if sys != "windows" {
        panic!("Platform '{sys}' not supported.");
    }

    if cfg!(FFI_PATERN_SCAN) {
        let memc = Path::new(&root_dir).join("include");

        cc::Build::new()
            .cpp(true)
            .opt_level_str("z")
            .file(memc.join("pattern_scanner.cpp"))
            .compile("pattern_scanner.a");

        println!("cargo:rerun-if-changed=include");
        println!(
            "cargo:rustc-link-search=native={}",
            env::var("OUT_DIR").unwrap()
        );
    }
}

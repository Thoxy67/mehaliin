#![feature(exposed_provenance)]
#![feature(ptr_metadata)]

#[cfg(feature = "Memory")]
pub mod memory;

#[cfg(feature = "Injector")]
pub mod injector;

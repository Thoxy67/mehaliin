# MeHaLiIn: Internal Memory Hacking Library for Rust

Welcome to MeHaLiIn, an acronym derived from "Me" for Memory, "Ha" for Hacking, "Li" for Library, and "In" for Internal. 

I chose this name over InMeHaLi for its smoother pronunciation.

## Overview

MeHaLiIn is a Rust library designed for internal memory manipulation, offering functionalities such as internal memory reading, 
pattern scanning, and writing. 

This library is particularly useful for developing internal cheats for games.

## Usage Guide

To get started with MeHaLiIn, add it as a dependency in your `Cargo.toml` file:

### Importing to your project

```toml
[dependencies]
mehaliin = { version = "*" = features = []}
```

### Features Flags :

```toml

Memory = ["Memory_Utils", "Memory_Read", "Memory_Write", "Memory_Pattern_Scan"] # Every Memory functions
Injector = ["Injector_Utils", "Injector_LoadLibraryA"] # Every Injector functions

Memory_Utils = [] # Only Memory Utils functions
Memory_Read = [] # Only Memory Reat functions
Memory_Write = [] # Only Memory Write functions
Memory_Pattern_Scan = [] # Only Memory Patter_Scan functions

Injector_Utils = [] # Only Injector Utils functions
Injector_LoadLibraryA = [] # Only Injector LoadLibraryA functions

CPP_PATTERN_SCAN = [] # Replace the Rust pattern Scan with c++ ffi one (faster)
```

Now you can use it in you project.

## Platform Compatibility

MeHaLiIn is specifically tailored for the Windows operating system.

## Safety Considerations

Please note that MeHalIn uses unsafe Rust code 💀 to provide low-level memory interaction capabilities. 

When working with unsafe code, always prioritize safety and understand potential risks associated with each function call. 

Additionally, familiarize yourself with Rust's ownership model and borrow checker rules before diving deep into this library.

## License

This project is licensed under the [MIT License](LICENSE).

## Contributions

Contributions to this project are welcome. 

If you find any issues or want to
enhance the functionality, feel free to open a pull request.
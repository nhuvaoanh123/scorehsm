// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

use std::{env, fs, path::PathBuf};

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Select linker script: Secure alias when TrustZone enabled, NS alias otherwise
    let memory_file = if env::var("CARGO_FEATURE_TRUSTZONE").is_ok() {
        "memory-tz.x"
    } else {
        "memory.x"
    };

    fs::copy(memory_file, out.join("memory.x")).unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=memory-tz.x");
    println!("cargo:rerun-if-changed=build.rs");
}

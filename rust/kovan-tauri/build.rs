use std::{env, fs, path::PathBuf};

fn main() {
    let preload_path = "../../app/desktop/preload.js";
    println!("cargo:rerun-if-changed={preload_path}");
    println!("cargo:rerun-if-changed=src/bridge.js");

    // Read the Electron contract without evaluating its code.
    let preload = fs::read_to_string(preload_path).expect("Electron preload");
    let (_, methods) = preload
        .split_once("exposeInMainWorld('statscanHost', Object.freeze({")
        .expect("statscanHost declaration");
    let (methods, _) = methods.split_once("\n}));").expect("statscanHost end");
    let names: Vec<_> = methods
        .lines()
        .filter_map(|line| {
            let (name, definition) = line.trim().split_once(':')?;
            (definition.contains("=>")
                && name.starts_with(|c: char| c.is_ascii_alphabetic())
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
            .then_some(name)
        })
        .collect();
    assert!(names.contains(&"settingsGet") && names.contains(&"accessStatus"));

    let bridge = fs::read_to_string("src/bridge.js").expect("Tauri bridge");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    fs::write(out.join("bridge.js"), format!("({bridge})({names:?});"))
        .expect("write initialization script");
    tauri_build::build();
}

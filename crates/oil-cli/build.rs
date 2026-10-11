fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.contains("windows") {
        let mut res = winres::WindowsResource::new();
        res.set_icon("oil.ico");
        res.compile().expect("Failed to compile resource");

        // When targeting Windows GNU (MinGW / windres), the object file must be linked explicitly.
        // On MSVC, rc.exe generates resource.lib/.res which winres links automatically.
        if target.contains("gnu") {
            if let Ok(out_dir) = std::env::var("OUT_DIR") {
                let res_o = format!("{}/resource.o", out_dir.replace('\\', "/"));
                if std::path::Path::new(&res_o).exists() {
                    println!("cargo:rustc-link-arg={}", res_o);
                }
            }
        }
    }
}

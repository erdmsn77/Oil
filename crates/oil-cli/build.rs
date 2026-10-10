fn main() {
    if std::env::var("TARGET").map(|t| t.contains("windows")).unwrap_or(false) {
        let mut res = winres::WindowsResource::new();
        res.set_icon("oil.ico");
        res.compile().expect("Failed to compile resource");
        let out_dir = std::env::var("OUT_DIR").unwrap();
        println!("cargo:rustc-link-arg={}/resource.o", out_dir.replace('\\', "/"));
    }
}

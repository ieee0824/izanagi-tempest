fn main() {
    println!("cargo:rerun-if-changed=abi_check.c");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux")
        || std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64")
    {
        return;
    }
    assert_eq!(
        std::env::var("HOST").unwrap(),
        std::env::var("TARGET").unwrap(),
        "KVM ABI verification supports native Linux/x86_64 builds only"
    );
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("abi_check.o");
    let result = std::process::Command::new("cc")
        .args(["-std=c11", "-Wall", "-Werror", "-c", "abi_check.c", "-o"])
        .arg(output)
        .status()
        .expect("C compiler required for KVM ABI checks");
    assert!(result.success(), "Linux KVM header ABI mismatch");
}

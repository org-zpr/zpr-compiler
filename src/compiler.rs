pub fn get_compiler_version() -> (u32, u32, u32) {
    let version = env!("CARGO_PKG_VERSION");
    let version_parts: Vec<&str> = version.split('.').collect();
    let major = version_parts
        .get(0)
        .unwrap_or(&"0")
        .parse::<u32>()
        .unwrap_or(0);
    let minor = version_parts
        .get(1)
        .unwrap_or(&"0")
        .parse::<u32>()
        .unwrap_or(0);
    let patch = version_parts
        .get(2)
        .unwrap_or(&"0")
        .parse::<u32>()
        .unwrap_or(0);
    (major, minor, patch)
}

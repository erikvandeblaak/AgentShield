//! Embeds a Windows VERSIONINFO resource in `agentshield.exe`.
//!
//! Code signing (SignPath) requires every signed binary to carry product name and version
//! metadata, and the values must match the desktop app (Tauri sets them from `tauri.conf.json`).
//! Unsigned binaries without metadata are also more likely to be flagged by antivirus heuristics.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    #[cfg(windows)]
    {
        let version = std::env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION");
        let mut res = winresource::WindowsResource::new();
        res.set("ProductName", "Erik\u{2019}s AgentShield")
            .set(
                "FileDescription",
                "Erik\u{2019}s AgentShield CLI, hook and daemon",
            )
            .set("CompanyName", "Erik van de Blaak")
            .set(
                "LegalCopyright",
                "\u{a9} 2026 Erik van de Blaak \u{2014} Apache-2.0",
            )
            .set("OriginalFilename", "agentshield.exe")
            .set("InternalName", "agentshield")
            .set("ProductVersion", &version)
            .set("FileVersion", &version);
        res.compile()
            .expect("embedding the Windows version resource failed");
    }
}

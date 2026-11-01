//! Builds the C++ bridge and links it with the static libmodsecurity of a prefix that
//! `scripts/build-modsecurity.sh` made. The prefix is the absolute path in the environment
//! variable `TUKUYOMI_MODSECURITY_PREFIX`. Its `include-src` directory holds the header files of the library's
//! own `src/`, which the bridge reads for the classes that the installed headers leave out.
//!
//! The inspector says which toolchain built it and the hash of the source of the engine in its HELLO. Both are
//! fixed here and compiled in: the toolchain as `rustc <release>`, from the `release:` line of `rustc -vV` of the
//! compiler that builds the crate, and the hash as the line of the file `archive.sha256` that the script of the
//! prefix wrote. A prefix without that file is refused.
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

const PREFIX_VAR: &str = "TUKUYOMI_MODSECURITY_PREFIX";
const SHA256_FILE: &str = "archive.sha256";
/// The longest toolchain string of a HELLO is 64 bytes; `rustc ` takes 6 of them.
const MAX_RELEASE: usize = 58;

fn stop(why: &str) -> ! {
    eprintln!("{why}");
    process::exit(1);
}

/// The directory of a static library that the C++ compiler finds on its own search path: rustc looks
/// for a static library only in the directories it is given.
fn directory_of(compiler: &Path, file: &str, package: &str) -> PathBuf {
    let output = Command::new(compiler)
        .arg(format!("-print-file-name={file}"))
        .output()
        .unwrap_or_else(|e| stop(&format!("cannot run the C++ compiler: {e}")));
    let found = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    match found.parent() {
        Some(dir) if found.is_absolute() && found.is_file() => dir.to_path_buf(),
        _ => stop(&format!(
            "{file} was not found by the C++ compiler (install {package})"
        )),
    }
}

/// The sha256 of the archive of the library: the one line of `file`, 64 lowercase hexadecimal digits.
fn archive_sha256(file: &Path) -> String {
    let text = fs::read_to_string(file).unwrap_or_else(|e| {
        stop(&format!(
            "cannot read {SHA256_FILE} of the prefix ({e}); build the prefix again with scripts/build-modsecurity.sh"
        ))
    });
    let line = text.strip_suffix('\n').unwrap_or(&text);
    if line.len() == 64 && line.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        line.to_owned()
    } else {
        stop(&format!(
            "{SHA256_FILE} of the prefix is not one line of 64 lowercase hexadecimal digits"
        ))
    }
}

/// `rustc <release>` for the compiler that cargo builds with, from the `release:` line of `rustc -vV`.
fn toolchain() -> String {
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| stop("RUSTC is not set"));
    let output = Command::new(rustc)
        .arg("-vV")
        .output()
        .unwrap_or_else(|e| stop(&format!("cannot run rustc -vV: {e}")));
    if !output.status.success() {
        stop("rustc -vV failed");
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let release = text
        .lines()
        .find_map(|line| line.strip_prefix("release: "))
        .unwrap_or_else(|| stop("rustc -vV has no release line"));
    let plain = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+');
    if release.is_empty() || release.len() > MAX_RELEASE || !release.chars().all(plain) {
        stop("the release of rustc is not a plain version string");
    }
    format!("rustc {release}")
}

fn main() {
    println!("cargo:rerun-if-changed=src/bridge.cc");
    println!("cargo:rerun-if-env-changed={PREFIX_VAR}");
    let prefix = match env::var(PREFIX_VAR) {
        Ok(p) if Path::new(&p).is_absolute() => p,
        Ok(_) => stop(&format!("{PREFIX_VAR} must be an absolute path")),
        Err(_) => stop(&format!(
            "{PREFIX_VAR} must be set to the absolute path of a libmodsecurity prefix (see scripts/build-modsecurity.sh)"
        )),
    };
    let include = Path::new(&prefix).join("include");
    let private = Path::new(&prefix).join("include-src");
    let lib = Path::new(&prefix).join("lib");
    let archive = lib.join("libmodsecurity.a");
    if !include.join("modsecurity/modsecurity.h").is_file()
        || !private.join("src/variables/variable.h").is_file()
        || !archive.is_file()
    {
        stop(&format!(
            "{PREFIX_VAR} has no include/modsecurity/modsecurity.h, include-src/src/variables/variable.h and lib/libmodsecurity.a (see scripts/build-modsecurity.sh)"
        ));
    }
    println!("cargo:rerun-if-changed={}", archive.display());
    println!("cargo:rerun-if-changed={}", private.display());
    let sha256_file = Path::new(&prefix).join(SHA256_FILE);
    println!("cargo:rerun-if-changed={}", sha256_file.display());
    println!("cargo:rustc-env=TKV_BUILD_TOOLCHAIN={}", toolchain());
    println!(
        "cargo:rustc-env=TKV_BUILD_ENGINE_SOURCE={}",
        archive_sha256(&sha256_file)
    );

    // The headers of libmodsecurity, and those of its `src/`, are read as system headers, so that their
    // warnings do not show; the warnings of the bridge itself stay on.
    let mut build = cc::Build::new();
    build
        .cpp(true)
        .cpp_link_stdlib(None)
        .std("c++17")
        .warnings(true)
        .extra_warnings(true)
        .flag("-isystem")
        .flag(&include)
        .flag("-isystem")
        .flag(&private)
        .file("src/bridge.cc");
    let compiler = build.get_compiler();
    let pcre2 = directory_of(compiler.path(), "libpcre2-8.a", "libpcre2-dev");
    let yajl = directory_of(compiler.path(), "libyajl_s.a", "libyajl-dev");
    build.compile("tkv_bridge");

    // The bridge comes before the libraries it uses. libstdc++ is the one dynamic library.
    println!("cargo:rustc-link-search=native={}", lib.display());
    println!("cargo:rustc-link-search=native={}", pcre2.display());
    println!("cargo:rustc-link-search=native={}", yajl.display());
    println!("cargo:rustc-link-lib=static=modsecurity");
    println!("cargo:rustc-link-lib=static=pcre2-8");
    println!("cargo:rustc-link-lib=static=yajl_s");
    println!("cargo:rustc-link-lib=dylib=stdc++");
}

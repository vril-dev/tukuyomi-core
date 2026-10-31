//! Builds the C++ bridge and links it with the static libmodsecurity of a prefix that
//! `scripts/build-modsecurity.sh` made. The prefix is the absolute path in the environment
//! variable `TUKUYOMI_MODSECURITY_PREFIX`. Its `include-src` directory holds the header files of the library's
//! own `src/`, which the bridge reads for the classes that the installed headers leave out.
use std::env;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

const PREFIX_VAR: &str = "TUKUYOMI_MODSECURITY_PREFIX";

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

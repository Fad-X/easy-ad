//! NetExec (nxc) detection, automatic installation, and module invocation.
//!
//! easy-ad prefers native Rust protocol clients; nxc is invoked only for
//! checks where a native implementation is not yet feasible (Kerberos
//! ticket acquisition, coercion triggers, gMSA blob decryption, full share
//! ACL enumeration with hash auth).

use anyhow::{Context, Result, bail};
use std::path::PathBuf;
use tokio::process::Command;

/// Handle to a located (or installed) nxc binary.
#[derive(Debug, Clone)]
pub struct NxcHandle {
    pub binary: PathBuf,
}

impl NxcHandle {
    /// Run an nxc subcommand, returning (stdout, stderr, success).
    pub async fn run(&self, args: &[&str]) -> Result<(String, String, bool)> {
        tracing::debug!(?args, "nxc invocation");
        let out = Command::new(&self.binary)
            .args(args)
            .output()
            .await
            .context("failed to spawn nxc")?;
        Ok((
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
            out.status.success(),
        ))
    }
}

/// Locate `nxc` / `nxc.exe` on PATH.
pub fn find_nxc() -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    let mut candidates: Vec<PathBuf> = Vec::new();
    let names: &[&str] = if cfg!(windows) { &["nxc.exe", "nxc"] } else { &["nxc"] };
    for dir in std::env::split_paths(&path_var) {
        for name in names {
            candidates.push(dir.join(name));
        }
    }
    candidates.into_iter().find(|c| c.is_file())
}

/// Check whether a command exists on PATH.
fn which(cmd: &str) -> bool {
    let names: &[&str] = if cfg!(windows) && !cmd.ends_with(".exe") {
        &[cmd, &format!("{}.exe", cmd)]
    } else {
        &[cmd]
    };
    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            for name in names {
                if dir.join(name).is_file() {
                    return true;
                }
            }
        }
    }
    false
}

/// Ensure nxc is available; if missing, attempt installation
/// (pipx -> pip3 -> git clone) unless the user disabled it.
pub async fn ensure_nxc(auto_install: bool) -> Result<Option<NxcHandle>> {
    if let Some(binary) = find_nxc() {
        tracing::info!(?binary, "found nxc");
        return Ok(Some(NxcHandle { binary }));
    }

    if !auto_install {
        eprintln!(
            "[!] nxc not found and auto-install disabled (--no-nxc-install).\n    \
             Install it manually: pipx install netexec\n    \
             Checks requiring nxc will be skipped."
        );
        return Ok(None);
    }

    eprintln!("[*] nxc not found on PATH - attempting automatic installation...");
    if which("pipx") {
        eprintln!("    -> pipx install netexec");
        let st = Command::new("pipx")
            .args(["install", "netexec"])
            .status()
            .await
            .context("failed to spawn pipx")?;
        if st.success() && find_nxc().is_some() {
            return Ok(Some(NxcHandle { binary: find_nxc().unwrap() }));
        }
    }
    if which("pip3") {
        eprintln!("    -> pip3 install netexec");
        let st = Command::new("pip3")
            .args(["install", "netexec"])
            .status()
            .await
            .context("failed to spawn pip3")?;
        if st.success() && find_nxc().is_some() {
            return Ok(Some(NxcHandle { binary: find_nxc().unwrap() }));
        }
    }
    if which("git") {
        eprintln!("    -> git clone https://github.com/Pennyw0rth/NetExec");
        let st = Command::new("git")
            .args([
                "clone",
                "--depth",
                "1",
                "https://github.com/Pennyw0rth/NetExec",
            ])
            .status()
            .await
            .context("failed to spawn git")?;
        if st.success() && find_nxc().is_none() {
            // The clone provides source, not an executable on PATH; still useful
            // to the user, but nxc remains unavailable.
            eprintln!("    NetExec source cloned into ./NetExec - install with: cd NetExec && pipx install .");
        }
    }

    if let Some(binary) = find_nxc() {
        // Verify the installation works.
        let handle = NxcHandle { binary };
        match handle.run(&["--version"]).await {
            Ok((stdout, _, true)) => {
                tracing::info!(%stdout, "nxc installed and verified");
                return Ok(Some(handle));
            }
            _ => bail!("nxc installed but `nxc --version` failed"),
        }
    }

    eprintln!(
        "[!] Automatic nxc installation failed.\n    \
         Manual options:\n      \
         pipx install netexec\n      \
         pip3 install netexec\n      \
         git clone https://github.com/Pennyw0rth/NetExec && cd NetExec && pipx install .\n    \
         easy-ad will continue with native checks only."
    );
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_nxc_only_when_present() {
        // The test environment either has nxc or not; just assert no panic.
        let _ = find_nxc();
    }

    #[test]
    fn which_detects_self_via_path() {
        // `git` ships with the dev environment.
        assert!(which("git"));
    }
}

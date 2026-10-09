//! ZIP packaging of BloodHound JSON files for BH CE import.

use anyhow::{Context, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

/// Package every `.json` file in `src_dir` into a single ZIP archive at
/// `dest_zip`, as expected by BloodHound Community Edition's "Upload Data".
pub fn package(src_dir: &Path, dest_zip: &Path) -> Result<PathBuf> {
    let file = File::create(dest_zip).context("cannot create bloodhound zip")?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o644);

    let mut entries: Vec<PathBuf> = std::fs::read_dir(src_dir)
        .context("cannot read bloodhound output dir")?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    entries.sort();

    for path in entries {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .context("bad file name in bloodhound dir")?;
        zip.start_file(name, options)?;
        let mut f = File::open(&path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        zip.write_all(&buf)?;
    }
    zip.finish().context("zip finalization failed")?;
    Ok(dest_zip.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packages_json_files() {
        let tmp = std::env::temp_dir().join("easy-ad-test-bh");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("users.json"), "{}").unwrap();
        std::fs::write(tmp.join("groups.json"), "{}").unwrap();
        std::fs::write(tmp.join("notes.txt"), "ignored").unwrap();

        let zip_path = tmp.join("export.zip");
        package(&tmp, &zip_path).unwrap();
        assert!(zip_path.exists());

        let f = File::open(&zip_path).unwrap();
        let mut archive = zip::ZipArchive::new(f).unwrap();
        let names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_string())
            .collect();
        assert!(names.contains(&"users.json".to_string()));
        assert!(names.contains(&"groups.json".to_string()));
        assert!(!names.contains(&"notes.txt".to_string()));

        let _ = std::fs::remove_dir_all(&tmp);
    }
}

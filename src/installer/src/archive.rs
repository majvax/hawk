//! Unpacks a release artifact: a .zip on Windows, a .tar.gz elsewhere.
//! Entries are checked to stay inside the destination.

use std::fs::{self, File};
use std::path::{Component, Path, PathBuf};

pub fn extract(archive: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination).map_err(|error| error.to_string())?;
    let name = archive.file_name().and_then(|name| name.to_str()).unwrap_or_default();
    if name.ends_with(".zip") {
        extract_zip(archive, destination)
    } else if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        extract_tar_gz(archive, destination)
    } else {
        Err(format!("don't know how to unpack {name}"))
    }
}

/// `entry` under `destination`, or None for an absolute path or one that
/// climbs out with `..`.
fn inside(destination: &Path, entry: &Path) -> Option<PathBuf> {
    let mut path = destination.to_path_buf();
    for component in entry.components() {
        match component {
            Component::Normal(part) => path.push(part),
            Component::CurDir => {}
            _ => return None,
        }
    }
    Some(path)
}

fn extract_zip(archive: &Path, destination: &Path) -> Result<(), String> {
    let file = File::open(archive).map_err(|error| error.to_string())?;
    let mut zip = zip::ZipArchive::new(file).map_err(|error| format!("{}: {error}", archive.display()))?;
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index).map_err(|error| error.to_string())?;
        let Some(target) = entry.enclosed_name().and_then(|name| inside(destination, &name)) else {
            return Err(format!("{} has an entry outside its folder", archive.display()));
        };
        if entry.is_dir() {
            fs::create_dir_all(&target).map_err(|error| error.to_string())?;
            continue;
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let mut out = File::create(&target).map_err(|error| format!("{}: {error}", target.display()))?;
        std::io::copy(&mut entry, &mut out).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn extract_tar_gz(archive: &Path, destination: &Path) -> Result<(), String> {
    let file = File::open(archive).map_err(|error| error.to_string())?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(file));
    tar.set_preserve_permissions(true);
    for entry in tar.entries().map_err(|error| error.to_string())? {
        let mut entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path().map_err(|error| error.to_string())?.into_owned();
        if inside(destination, &path).is_none() {
            return Err(format!("{} has an entry outside its folder", archive.display()));
        }
        let kind = entry.header().entry_type();
        if kind.is_symlink() || kind.is_hard_link() {
            return Err(format!("{} has a link in it, which a release never does", archive.display()));
        }
        entry.unpack_in(destination).map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_entries_inside() {
        let destination = Path::new("/opt/hawk");
        assert_eq!(inside(destination, Path::new("bin/hawk")), Some(PathBuf::from("/opt/hawk/bin/hawk")));
        assert_eq!(inside(destination, Path::new("./hawk")), Some(PathBuf::from("/opt/hawk/hawk")));
        assert_eq!(inside(destination, Path::new("../etc/passwd")), None);
        assert_eq!(inside(destination, Path::new("/etc/passwd")), None);
    }
}

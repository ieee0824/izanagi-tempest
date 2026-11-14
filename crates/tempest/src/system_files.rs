//! Host system file access. Only unit-test builds can redirect paths to fixtures.
use std::{io, path::Path};

#[derive(Clone, Debug, Default)]
pub(crate) struct SystemFiles {
    #[cfg(test)]
    paths: Option<std::collections::BTreeMap<std::path::PathBuf, std::path::PathBuf>>,
}

impl SystemFiles {
    pub(crate) fn path<'a>(&'a self, path: &'a Path) -> &'a Path {
        #[cfg(test)]
        if let Some(paths) = &self.paths {
            // A synthetic fixture must describe every system path it accesses.
            // Do not silently fall back to the developer's host.
            return paths.get(path).expect("unlisted fixture system path");
        }
        path
    }

    pub(crate) fn digest(&self, path: &Path) -> io::Result<String> {
        crate::host_io::digest(self.path(path))
    }

    #[cfg(test)]
    pub(crate) fn fixture(root: &Path) -> Self {
        let paths = crate::capability_proof::reviewed_codex_system_paths()
            .unwrap()
            .into_iter()
            .chain(crate::capability_proof::reviewed_claude_system_paths().unwrap())
            .map(|(path, _)| {
                let target = root
                    .join("system-files")
                    .join(path.strip_prefix("/").unwrap());
                (path, target)
            })
            .collect();
        Self { paths: Some(paths) }
    }

    #[cfg(test)]
    pub(crate) fn create_fixture(root: &Path) -> Self {
        let files = Self::fixture(root);
        for (logical, target) in files.paths.as_ref().unwrap() {
            if matches!(
                logical.to_str().unwrap(),
                "/usr/bin/sandbox-exec"
                    | "/System/Library/Sandbox/Profiles/system.sb"
                    | "/System/Library/Sandbox/Profiles/dyld-support.sb"
            ) {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(target.parent().unwrap())
                    .unwrap();
                crate::host_io::write_new(target, logical.as_os_str().as_encoded_bytes()).unwrap();
            }
        }
        files
    }
}

//! Every skeleton must pin, inside this daemon's map space, every map it
//! declares as pinned by name.
//!
//! `LIBBPF_PIN_BY_NAME` without a path means libbpf pins the map at the bpffs
//! root (`/sys/fs/bpf/<name>`) instead of inside the map space. That is not a
//! cosmetic difference, and it produced two separate live failures:
//!
//!   * the WAN firewall never loaded at all. The rate-limit map's key gained a
//!     traffic class; the old root pin still had the 4-byte key; libbpf refuses to
//!     reuse it, and the whole skeleton load returned `EINVAL`. The service logged
//!     one line, the program was simply never attached, and every inbound
//!     authorization the firewall enforces was inert;
//!   * the XDP firewall read its global switches and inbound authorizations from a
//!     root-pinned map while the daemon wrote the managed one - two maps with one
//!     name, so a configured value could be applied and have no effect.
//!
//! Both are silent. The check below is per *loader function*, not per file and not
//! per name: for each skeleton's map list, every map declared pinned by name must
//! be pinned inside the function that loads that skeleton. Coarser scopes miss the
//! real cases - the TC and XDP firewalls live in one file, so "some loader names
//! it" passes even when the XDP loader leaves it to the root.
//!
//! It reads sources only - no BPF, no root - so it runs in the ordinary suite.

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};

    fn src_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    fn rust_sources() -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![src_root()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read src dir").flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if path.file_name().and_then(|n| n.to_str()) == Some("bpf_rs") {
                        continue;
                    }
                    stack.push(path);
                } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                    out.push(path);
                }
            }
        }
        out
    }

    /// Map names declared with `LIBBPF_PIN_BY_NAME` anywhere under `src/bpf`.
    fn pinned_map_names() -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        let mut stack = vec![src_root().join("bpf")];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read bpf dir").flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let is_source =
                    matches!(path.extension().and_then(|e| e.to_str()), Some("h" | "c"));
                if !is_source {
                    continue;
                }
                let text = read(&path);
                // `struct { ... } name SEC(".maps");` - the name is what sits
                // between the struct's closing brace and the SEC attribute.
                for (offset, _) in text.match_indices("SEC(\".maps\")") {
                    let before = &text[..offset];
                    let Some(start) = before.rfind("struct {") else { continue };
                    let block = &before[start..];
                    if !block.contains("LIBBPF_PIN_BY_NAME") {
                        continue;
                    }
                    let Some(close) = block.rfind('}') else { continue };
                    let name = block[close + 1..].trim();
                    if !name.is_empty()
                        && !name.contains(|c: char| !c.is_alphanumeric() && c != '_')
                    {
                        names.insert(name.to_string());
                    }
                }
            }
        }
        names
    }

    /// The maps each generated skeleton declares, from its own map list.
    fn skeleton_maps() -> BTreeMap<String, (String, BTreeSet<String>)> {
        let mut out = BTreeMap::new();
        let dir = src_root().join("bpf_rs");
        for entry in std::fs::read_dir(&dir).expect("read bpf_rs dir").flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
            if !name.ends_with(".skel.rs") {
                continue;
            }
            // Test skeletons are loaded by test harnesses that own a throwaway
            // bpffs directory; their name-based pinning is out of scope here.
            // (It is worth knowing they pin at the root when they run, but they
            // are not what ships.)
            if name.starts_with("test_") {
                continue;
            }
            let text = read(&path);
            let mut maps = BTreeSet::new();
            for (offset, _) in text.match_indices(".map(\"") {
                let rest = &text[offset + ".map(\"".len()..];
                let map: String =
                    rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                if !map.is_empty() {
                    maps.insert(map);
                }
            }
            // The builder type is how a loader is identified. Both firewall
            // skeletons are loaded from one file, so file scope is too coarse.
            let builder = text
                .match_indices("pub struct ")
                .map(|(offset, _)| &text[offset + "pub struct ".len()..])
                .find_map(|rest| {
                    let name: String =
                        rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                    name.ends_with("SkelBuilder").then_some(name)
                })
                .unwrap_or_default();
            out.insert(name, (builder, maps));
        }
        out
    }

    /// The body of the innermost `fn` containing `at`, and the file it is in.
    fn enclosing_function(text: &str, at: usize) -> Option<&str> {
        let before = &text[..at];
        let fn_at = before.rfind("fn ")?;
        let open = text[fn_at..].find('{')? + fn_at;
        let mut depth = 0usize;
        for (offset, ch) in text[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&text[open..open + offset + 1]);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// The maps a Rust source pins, by name.
    fn pinned_by(text: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for (offset, _) in text.match_indices("pin_and_reuse_map") {
            let window = &text[offset..];
            let Some(maps_at) = window.find(".maps.") else { continue };
            let window = &window[maps_at + ".maps.".len()..];
            let name: String =
                window.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
            if !name.is_empty() {
                out.insert(name);
            }
        }
        out
    }

    #[test]
    fn every_name_pinned_map_of_a_skeleton_is_pinned_by_its_loader() {
        let pinned = pinned_map_names();
        assert!(
            pinned.len() > 10,
            "the C parser found too few pinned maps to be meaningful: {pinned:?}"
        );

        let sources: Vec<(PathBuf, String)> =
            rust_sources().into_iter().map(|p| (p.clone(), read(&p))).collect();
        let skeletons = skeleton_maps();
        assert!(skeletons.len() > 10, "found too few skeletons");

        let mut problems: Vec<String> = Vec::new();
        for (skel, (builder, maps)) in &skeletons {
            let declared_pinned: Vec<&String> =
                maps.iter().filter(|name| pinned.contains(*name)).collect();
            if declared_pinned.is_empty() || builder.is_empty() {
                continue;
            }
            // A loader is a function that names this skeleton's builder type.
            let mut loader_bodies: Vec<(&PathBuf, &str)> = Vec::new();
            for (path, text) in &sources {
                for (offset, _) in text.match_indices(builder.as_str()) {
                    if let Some(body) = enclosing_function(text, offset) {
                        loader_bodies.push((path, body));
                    }
                }
            }
            if loader_bodies.is_empty() {
                continue;
            }
            let union: BTreeSet<String> =
                loader_bodies.iter().flat_map(|(_, body)| pinned_by(body)).collect();
            for name in declared_pinned {
                if !union.contains(name) {
                    let where_ = loader_bodies
                        .iter()
                        .map(|(p, _)| {
                            p.file_name().unwrap_or_default().to_string_lossy().to_string()
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    problems.push(format!(
                        "{skel} declares `{name}` (pinned by name) but the loader function(s) in \
                         [{where_}] never give it a pin path, so libbpf pins it at the bpffs root"
                    ));
                }
            }
        }

        assert!(
            problems.is_empty(),
            "maps that would be pinned outside the map space:\n  {}",
            problems.join("\n  ")
        );
    }
}

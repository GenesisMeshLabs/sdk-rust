//! The crate's layers (docs/architecture.md), checked from the source.
//!
//! Every `crate::` reference in a module's production code (its
//! `#[cfg(test)]` items aside) points to a module of its own layer or a
//! layer below, and the modules form no import cycle. The offline layers
//! build without the `client` feature; every module above them is behind
//! it. A new module must be placed in a layer here.
//!
//! `ALLOWED` is a ratchet: an edge listed there may break the rules, but the
//! test fails when an edge breaks them without being listed, and when a
//! listed edge no longer exists or no longer breaks them (remove it from the
//! list). The list only shrinks.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// The layers, lowest first: a module may use its own layer and those below.
const LAYERS: &[(&str, &[&str])] = &[
    // Typed errors, strict JSON input, the shared value rules and the
    // outboxes' entries: they import nothing above this layer.
    (
        "foundation",
        &["errors", "outbox_entry", "rules", "strict_json"],
    ),
    // Signing and digests, the field registry, canonical forms, and the
    // structural checks of signed JSON.
    ("canonical", &["auth", "canonical", "shape", "strict"]),
    // Building, signing and checking records offline, and the outboxes.
    (
        "records",
        &[
            "execution",
            "grants",
            "node_auth",
            "out_of_band",
            "outbox",
            "remediation",
        ],
    ),
    // Offline verification.
    (
        "verification",
        &["audit_pack", "key_history", "verify", "vouching"],
    ),
    // From here on: the `client` feature.
    ("transport", &["transport"]),
    (
        "sub-clients",
        &[
            "agreement",
            "attestation",
            "boundary",
            "consensus",
            "data_usage",
            "disclosure",
            "evidence",
            "evidence_store",
            "grant_client",
            "health",
            "node",
            "policy",
        ],
    ),
    ("client", &["client"]),
    ("orchestration", &["governance", "grant_holder"]),
];

/// The layers that build without the `client` feature.
const OFFLINE_LAYERS: usize = 4;

/// Edges that break the rules today, as (from, to). Only shrinks.
const ALLOWED: &[(&str, &str)] = &[];

#[test]
fn modules_use_only_their_layer_and_the_layers_below() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let graph = module_graph(&root);
    let layer = layer_of();

    let files: BTreeSet<&str> = graph.keys().map(String::as_str).collect();
    let placed: BTreeSet<&str> = layer.keys().copied().collect();
    let unplaced: Vec<_> = files.difference(&placed).collect();
    let gone: Vec<_> = placed.difference(&files).collect();
    assert!(
        unplaced.is_empty(),
        "place these modules in a layer in tests/architecture.rs and docs/architecture.md: {unplaced:?}"
    );
    assert!(gone.is_empty(), "these modules no longer exist: {gone:?}");

    let allowed: BTreeSet<(String, String)> = ALLOWED
        .iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
    // The direction: never up a layer.
    let mut upward = BTreeSet::new();
    for (from, tos) in &graph {
        for to in tos {
            if layer[to.as_str()] > layer[from.as_str()] {
                upward.insert((from.clone(), to.clone()));
            }
        }
    }
    // No cycle among the edges that are not allowed.
    let mut kept = graph.clone();
    for (a, b) in &allowed {
        if let Some(tos) = kept.get_mut(a) {
            tos.remove(b);
        }
    }
    let cycle = find_cycle(&kept);
    let in_cycle = cycle_edges(&graph);

    let broken: BTreeSet<_> = upward.union(&in_cycle).cloned().collect();
    let new: Vec<_> = broken.difference(&allowed).collect();
    let stale: Vec<_> = allowed.difference(&broken).collect();
    assert!(
        new.is_empty() && cycle.is_none(),
        "these imports break the layer table (docs/architecture.md): {new:?}; cycle: {cycle:?}. \
         Move the shared code to a lower module instead of importing upward."
    );
    assert!(
        stale.is_empty(),
        "these allowed edges no longer break the rules: remove them from ALLOWED: {stale:?}"
    );
}

#[test]
fn the_offline_layers_build_without_the_client_feature() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    // Comments out, strings kept: the attribute names its feature.
    let lib: String = std::fs::read_to_string(root.join("lib.rs"))
        .unwrap()
        .lines()
        .map(|line| line.split("//").next().unwrap())
        .collect::<Vec<_>>()
        .join(
            "
",
        );
    let gated = client_gated_modules(&lib);
    for (i, (name, modules)) in LAYERS.iter().enumerate() {
        for module in *modules {
            assert_eq!(
                gated.contains(*module),
                i >= OFFLINE_LAYERS,
                "{module} (layer {name}) must {}be behind #[cfg(feature = \"client\")] in lib.rs",
                if i >= OFFLINE_LAYERS { "" } else { "not " }
            );
        }
    }
}

/// The reader finds what an import names, and ignores comments, strings and
/// test modules.
#[test]
fn the_reader_finds_crate_references() {
    let source = r##"
        //! [`thing`](crate::docs_only)
        use crate::{alpha::A, beta, Root, gamma::{x, y}};
        use crate::delta::D;
        fn f() -> crate::epsilon::E { let _ = "crate::in_a_string"; let _ = r#"crate::raw"#; let _ = 'c'; }
        fn g<'a>(x: &'a str) -> &'a str { crate::zeta::z(x) }
        /* crate::block_comment */
        #[cfg(test)]
        mod tests { use crate::only_in_tests::T; }
        #[cfg(test)]
        use crate::test_import;
    "##;
    let roots = BTreeMap::from([("Root".to_owned(), "root_module".to_owned())]);
    let modules: BTreeSet<String> = [
        "alpha",
        "beta",
        "root_module",
        "gamma",
        "delta",
        "epsilon",
        "zeta",
        "docs_only",
        "in_a_string",
        "raw",
        "block_comment",
        "only_in_tests",
        "test_import",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let found = references(&production(&strip(source)), &roots, &modules);
    let expected: BTreeSet<String> = [
        "alpha",
        "beta",
        "root_module",
        "gamma",
        "delta",
        "epsilon",
        "zeta",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(found, expected);
}

fn layer_of() -> BTreeMap<&'static str, usize> {
    let mut out = BTreeMap::new();
    for (i, (_, modules)) in LAYERS.iter().enumerate() {
        for module in *modules {
            assert!(
                out.insert(*module, i).is_none(),
                "{module} is in two layers"
            );
        }
    }
    out
}

/// module -> the crate's modules it references (production code only).
fn module_graph(src: &Path) -> BTreeMap<String, BTreeSet<String>> {
    let mut sources = BTreeMap::new();
    for entry in std::fs::read_dir(src).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap();
        if let Some(module) = name.strip_suffix(".rs") {
            if module != "lib" {
                sources.insert(module.to_owned(), std::fs::read_to_string(&path).unwrap());
            }
        }
    }
    let modules: BTreeSet<String> = sources.keys().cloned().collect();
    let lib = strip(&std::fs::read_to_string(src.join("lib.rs")).unwrap());
    let roots = root_exports(&lib, &modules);
    sources
        .iter()
        .map(|(module, text)| {
            let mut refs = references(&production(&strip(text)), &roots, &modules);
            refs.remove(module);
            (module.clone(), refs)
        })
        .collect()
}

/// The names lib.rs re-exports at the crate root, and the module each comes
/// from (`pub use errors::{GenesisMeshError, Result}` -> Result: errors).
fn root_exports(lib: &str, modules: &BTreeSet<String>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for statement in lib.split(';') {
        let Some(at) = statement.find("pub use ") else {
            continue;
        };
        let path = statement[at + "pub use ".len()..].trim();
        let Some((module, rest)) = path.split_once("::") else {
            continue;
        };
        if !modules.contains(module.trim()) {
            continue;
        }
        for name in idents(rest) {
            out.entry(name).or_insert_with(|| module.trim().to_owned());
        }
    }
    out
}

/// The modules lib.rs declares behind `#[cfg(feature = "client")]`.
fn client_gated_modules(lib: &str) -> BTreeSet<String> {
    let compact: String = lib.split_whitespace().collect::<Vec<_>>().join(" ");
    let marker = "#[cfg(feature = \"client\")] ";
    let mut out = BTreeSet::new();
    let mut rest = compact.as_str();
    while let Some(at) = rest.find(marker) {
        rest = &rest[at + marker.len()..];
        let item = rest.strip_prefix("pub ").unwrap_or(rest);
        if let Some(name) = item.strip_prefix("mod ") {
            out.insert(name.split(';').next().unwrap().trim().to_owned());
        }
    }
    out
}

/// The modules a source references through `crate::`.
fn references(
    code: &str,
    roots: &BTreeMap<String, String>,
    modules: &BTreeSet<String>,
) -> BTreeSet<String> {
    let resolve = |name: &str, out: &mut BTreeSet<String>| {
        if modules.contains(name) {
            out.insert(name.to_owned());
        } else if let Some(module) = roots.get(name) {
            out.insert(module.clone());
        }
    };
    let mut out = BTreeSet::new();
    let bytes = code.as_bytes();
    let mut i = 0;
    while let Some(at) = code[i..].find("crate") {
        let start = i + at;
        i = start + "crate".len();
        if start > 0 && is_ident(bytes[start - 1]) || bytes.get(i).is_some_and(|b| is_ident(*b)) {
            continue;
        }
        let rest = code[i..].trim_start();
        let Some(rest) = rest.strip_prefix("::") else {
            continue;
        };
        let rest = rest.trim_start();
        if let Some(group) = rest.strip_prefix('{') {
            // The group's top-level items: `a::B`, `c`, `d::{e, f}`.
            let mut depth = 0;
            let mut item = String::new();
            for c in group.chars() {
                match c {
                    '{' => depth += 1,
                    '}' if depth == 0 => break,
                    '}' => depth -= 1,
                    ',' if depth == 0 => {
                        if let Some(first) = idents(&item).into_iter().next() {
                            resolve(&first, &mut out);
                        }
                        item.clear();
                        continue;
                    }
                    _ => {}
                }
                item.push(c);
            }
            if let Some(first) = idents(&item).into_iter().next() {
                resolve(&first, &mut out);
            }
        } else if let Some(first) = idents(rest).into_iter().next() {
            resolve(&first, &mut out);
        }
    }
    out
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn idents(text: &str) -> Vec<String> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty() && !w.starts_with(|c: char| c.is_ascii_digit()))
        .map(str::to_owned)
        .collect()
}

/// Code without comments, string and character literals (newlines kept).
fn strip(code: &str) -> String {
    let c: Vec<char> = code.chars().collect();
    let mut out = String::with_capacity(code.len());
    let mut i = 0;
    let prev_ident = |i: usize| i > 0 && (c[i - 1].is_alphanumeric() || c[i - 1] == '_');
    while i < c.len() {
        if c[i] == '/' && c.get(i + 1) == Some(&'/') {
            while i < c.len() && c[i] != '\n' {
                i += 1;
            }
        } else if c[i] == '/' && c.get(i + 1) == Some(&'*') {
            let mut depth = 0;
            while i < c.len() {
                if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    if c[i] == '\n' {
                        out.push('\n');
                    }
                    i += 1;
                }
            }
        } else if c[i] == 'r' && !prev_ident(i) && {
            let mut j = i + 1;
            while c.get(j) == Some(&'#') {
                j += 1;
            }
            c.get(j) == Some(&'"')
        } {
            let mut hashes = 0;
            i += 1;
            while c[i] == '#' {
                hashes += 1;
                i += 1;
            }
            i += 1;
            loop {
                if i >= c.len() {
                    break;
                }
                if c[i] == '"' && (1..=hashes).all(|k| c.get(i + k) == Some(&'#')) {
                    i += 1 + hashes;
                    break;
                }
                if c[i] == '\n' {
                    out.push('\n');
                }
                i += 1;
            }
            out.push_str("\"\"");
        } else if c[i] == '"' {
            i += 1;
            while i < c.len() && c[i] != '"' {
                if c[i] == '\\' {
                    i += 1;
                }
                if c.get(i) == Some(&'\n') {
                    out.push('\n');
                }
                i += 1;
            }
            i += 1;
            out.push_str("\"\"");
        } else if c[i] == '\'' {
            if c.get(i + 1) == Some(&'\\') {
                i += 2;
                while i < c.len() && c[i] != '\'' {
                    i += 1;
                }
                i += 1;
                out.push_str("' '");
            } else if c.get(i + 2) == Some(&'\'') {
                i += 3;
                out.push_str("' '");
            } else {
                out.push('\'');
                i += 1;
            }
        } else {
            out.push(c[i]);
            i += 1;
        }
    }
    out
}

/// Stripped code without its `#[cfg(test)]` items.
fn production(code: &str) -> String {
    let marker = "#[cfg(test)]";
    let mut out = String::new();
    let mut rest = code;
    while let Some(at) = rest.find(marker) {
        out.push_str(&rest[..at]);
        let item = &rest[at + marker.len()..];
        // The item ends at its first `;` outside braces, or at the brace
        // that closes its body.
        let mut depth = 0;
        let mut end = item.len();
        for (k, ch) in item.char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = k + 1;
                        break;
                    }
                }
                ';' if depth == 0 => {
                    end = k + 1;
                    break;
                }
                _ => {}
            }
        }
        rest = &item[end..];
    }
    out.push_str(rest);
    out
}

/// A cycle in the graph, as its modules in order, if there is one.
fn find_cycle(graph: &BTreeMap<String, BTreeSet<String>>) -> Option<Vec<String>> {
    fn visit(
        node: &str,
        graph: &BTreeMap<String, BTreeSet<String>>,
        state: &mut BTreeMap<String, u8>,
        path: &mut Vec<String>,
    ) -> Option<Vec<String>> {
        state.insert(node.to_owned(), 1);
        path.push(node.to_owned());
        for next in graph.get(node).into_iter().flatten() {
            match state.get(next.as_str()) {
                Some(1) => {
                    let from = path.iter().position(|n| n == next).unwrap();
                    let mut cycle = path[from..].to_vec();
                    cycle.push(next.clone());
                    return Some(cycle);
                }
                Some(_) => {}
                None => {
                    if let Some(cycle) = visit(next, graph, state, path) {
                        return Some(cycle);
                    }
                }
            }
        }
        path.pop();
        state.insert(node.to_owned(), 2);
        None
    }
    let mut state = BTreeMap::new();
    for node in graph.keys() {
        if !state.contains_key(node) {
            if let Some(cycle) = visit(node, graph, &mut state, &mut Vec::new()) {
                return Some(cycle);
            }
        }
    }
    None
}

/// The edges that lie on a cycle: `a -> b` where `b` reaches `a`.
fn cycle_edges(graph: &BTreeMap<String, BTreeSet<String>>) -> BTreeSet<(String, String)> {
    let reaches = |from: &str, to: &str| {
        let mut seen = BTreeSet::new();
        let mut stack = vec![from.to_owned()];
        while let Some(node) = stack.pop() {
            if node == to {
                return true;
            }
            if seen.insert(node.clone()) {
                stack.extend(graph.get(&node).into_iter().flatten().cloned());
            }
        }
        false
    };
    let mut out = BTreeSet::new();
    for (a, tos) in graph {
        for b in tos {
            if reaches(b, a) {
                out.insert((a.clone(), b.clone()));
            }
        }
    }
    out
}

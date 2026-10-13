//! The command line: `genesis-mesh-verify [--json] <command> ...`.

use std::path::PathBuf;

use genesis_mesh_sdk::verify::RECORD_KINDS;

use crate::Stop;

pub const USAGE: &str = "\
genesis-mesh-verify: verify Genesis Mesh records, evidence exports and audit
packs offline.

It never contacts a network and never needs a private key. Every key is a
base64 Ed25519 public key, given inline or as a file ('#' lines ignored).

Usage:
  genesis-mesh-verify record <kind> <file> [options]
  genesis-mesh-verify export <file> [options]
  genesis-mesh-verify pack <dir> --anchor <root key> [options]
  genesis-mesh-verify key-history <file> --root-key <key>
  genesis-mesh-verify --help | --version

record: verify one signed record (a JSON file) as an export verifies it.
  <kind>                    decision, justification, execution, checkpoint,
                            observation, break-glass, judgement, quarantine,
                            registry, remediation, review, key-succession,
                            archive, policy, attestation
  --na-key <key>            an NA public key, valid at every time (repeatable)
  --key-history <file>      the NA's key history (GET /na/key-history): each
                            NA key valid at its own times; needs --root-key
  --root-key <key>          the root public key you hold, for --key-history
  --executor-keys <file>    JSON from GET /admin/evidence/executor-keys
  --at <time>               judge a decision at this RFC 3339 time
                            (default: as of the decision's own time)
  --freshness-key <key>     a decision's freshness proof issuer (repeatable)
  --expect-policy <file>    a decision must bind this policy (repeatable)
  --expect-attestation <file>
                            a decision must bind this attestation

export: verify a gm.evidence.event JSON Lines export.
  --na-key, --key-history, --root-key, --executor-keys
                            as for record
  --known-anchors <path>    anchors you hold: a directory from 'genesis-mesh
                            evidence anchors fetch', or a JSON file
  --checkpoint <file>       the retention checkpoint the export continues from
                            (default: the one the export holds, if any)
  --partial                 the export is a deliberate slice: its ends are not
                            checked against the anchors
  --from-anchor             the export continues from a held anchor
  --cited <file>            entries before the export that its records rest
                            on (a pack's cited.jsonl): the export is then
                            verified as a pack's range

pack: verify an audit pack directory, as 'genesis-mesh audit verify' does.
  --anchor <key>            the root public key you hold (required)
  --known-anchors <path>    anchors you hold; without them the pack proves
                            its integrity, not that nothing was removed
                            (warning no_held_anchors)
  --require-anchors         fail when --known-anchors is not given
  --prior <dir>             a pack verified before (repeatable): the entries
                            this pack cites must equal the ones it holds
  --prior-entries <file>    the same as JSON: each store position and the
                            entry digest a prior pack holds there
  --period <from> <until>   two RFC 3339 times: fail when the pack does not
                            cover this period
  --report <file>           write the report this verification renders
  --executor-keys <file>    executor keys you hold, for a store without
                            registry records
  --changes <file>          changes from a log outside Genesis Mesh (CSV, or
                            JSON) to match against the pack
  --tolerance-seconds <n>   how far apart a change and its record may be
                            (default 300)

key-history: verify a key history ({\"genesis\", \"successions\"}) from the
root key you hold, and list each NA key's validity.

Global options:
  --json                    print the result as JSON
  -h, --help                print this help
  -V, --version             print the version

Exit codes: 0 verified, 1 not verified, 2 usage error, 3 an input could not
be read, 4 not available in this version.
";

/// What to run.
#[derive(Debug)]
pub enum Command {
    Help,
    Version,
    Record(RecordArgs),
    Export(ExportArgs),
    Pack(PackArgs),
    KeyHistory(KeyHistoryArgs),
}

/// The command and the output form.
#[derive(Debug)]
pub struct Cli {
    pub json: bool,
    pub command: Command,
}

#[derive(Debug)]
pub struct RecordArgs {
    pub kind: String,
    pub file: PathBuf,
    pub na_keys: Vec<String>,
    pub executor_keys: Option<PathBuf>,
    pub at: Option<String>,
    pub freshness_keys: Vec<String>,
    pub expect_policies: Vec<PathBuf>,
    pub expect_attestation: Option<PathBuf>,
    pub key_history: Option<PathBuf>,
    pub root_key: Option<String>,
}

#[derive(Debug)]
pub struct ExportArgs {
    pub file: PathBuf,
    pub na_keys: Vec<String>,
    pub executor_keys: Option<PathBuf>,
    pub known_anchors: Option<PathBuf>,
    pub checkpoint: Option<PathBuf>,
    pub partial: bool,
    pub from_anchor: bool,
    pub key_history: Option<PathBuf>,
    pub root_key: Option<String>,
    pub cited: Option<PathBuf>,
}

#[derive(Debug)]
pub struct PackArgs {
    pub dir: PathBuf,
    pub root_key: String,
    pub known_anchors: Option<PathBuf>,
    pub require_anchors: bool,
    pub prior: Vec<PathBuf>,
    pub prior_entries: Option<PathBuf>,
    pub period: Option<(String, String)>,
    pub report: Option<PathBuf>,
    pub executor_keys: Option<PathBuf>,
    pub changes: Option<PathBuf>,
    pub tolerance_seconds: i64,
}

#[derive(Debug)]
pub struct KeyHistoryArgs {
    pub file: PathBuf,
    pub root_key: Option<String>,
}

/// Options of one command: the positionals, then each option's values in
/// order, then the flags given.
struct Parsed {
    positionals: Vec<String>,
    values: Vec<(&'static str, String)>,
    flags: Vec<&'static str>,
}

impl Parsed {
    fn all(&self, name: &str) -> Vec<String> {
        self.values
            .iter()
            .filter(|(n, _)| *n == name)
            .map(|(_, v)| v.clone())
            .collect()
    }

    fn one(&self, name: &str) -> Result<Option<String>, Stop> {
        let mut all = self.all(name);
        if all.len() > 1 {
            return Err(Stop::Usage(format!("--{name} is given more than once")));
        }
        Ok(all.pop())
    }

    fn flag(&self, name: &str) -> bool {
        self.flags.contains(&name)
    }
}

/// Split a command's arguments into positionals, options with a value
/// (`--name value` or `--name=value`) and flags; `--` ends the options.
fn split(
    tokens: &[String],
    with_value: &[&'static str],
    flags: &[&'static str],
) -> Result<Parsed, Stop> {
    let mut parsed = Parsed {
        positionals: Vec::new(),
        values: Vec::new(),
        flags: Vec::new(),
    };
    let mut rest = tokens.iter();
    let mut options_ended = false;
    while let Some(token) = rest.next() {
        if options_ended || !token.starts_with("--") || token == "-" {
            parsed.positionals.push(token.clone());
            continue;
        }
        if token == "--" {
            options_ended = true;
            continue;
        }
        let (name, inline) = match token[2..].split_once('=') {
            Some((name, value)) => (name, Some(value.to_owned())),
            None => (&token[2..], None),
        };
        if let Some(known) = with_value.iter().find(|n| **n == name) {
            let value = match inline {
                Some(value) => value,
                None => rest
                    .next()
                    .cloned()
                    .ok_or_else(|| Stop::Usage(format!("--{name} needs a value")))?,
            };
            parsed.values.push((known, value));
        } else if let Some(known) = flags.iter().find(|n| **n == name) {
            if inline.is_some() {
                return Err(Stop::Usage(format!("--{name} takes no value")));
            }
            parsed.flags.push(known);
        } else {
            return Err(Stop::Usage(format!("unknown option --{name}")));
        }
    }
    Ok(parsed)
}

fn positionals<const N: usize>(parsed: &Parsed, usage: &str) -> Result<[String; N], Stop> {
    <[String; N]>::try_from(parsed.positionals.clone())
        .map_err(|_| Stop::Usage(format!("usage: genesis-mesh-verify {usage}")))
}

/// A record kind as the SDK names it: `checkpoint` is a retention
/// checkpoint, and a hyphen reads as an underscore.
pub fn record_kind(kind: &str) -> Result<String, Stop> {
    let kind = kind.to_ascii_lowercase().replace('-', "_");
    let kind = match kind.as_str() {
        "checkpoint" => "retention_checkpoint".to_owned(),
        _ => kind,
    };
    if RECORD_KINDS.contains(&kind.as_str()) {
        Ok(kind)
    } else {
        Err(Stop::Usage(format!(
            "unknown record kind {kind:?}; one of: {}",
            RECORD_KINDS.join(", ")
        )))
    }
}

/// Parse the command line (without the program name).
pub fn parse(argv: &[String]) -> Result<Cli, Stop> {
    let json = argv.iter().any(|a| a == "--json");
    let tokens: Vec<String> = argv.iter().filter(|a| *a != "--json").cloned().collect();
    let first = tokens.first().map(String::as_str);
    let command = match first {
        None | Some("-h" | "--help" | "help") => Command::Help,
        Some("-V" | "--version") => Command::Version,
        Some(_) if tokens.iter().any(|a| a == "-h" || a == "--help") => Command::Help,
        Some("record") => {
            let parsed = split(
                &tokens[1..],
                &[
                    "na-key",
                    "executor-keys",
                    "at",
                    "freshness-key",
                    "expect-policy",
                    "expect-attestation",
                    "key-history",
                    "root-key",
                ],
                &[],
            )?;
            let [kind, file] = positionals::<2>(&parsed, "record <kind> <file> [options]")?;
            Command::Record(RecordArgs {
                kind: record_kind(&kind)?,
                file: file.into(),
                na_keys: parsed.all("na-key"),
                executor_keys: parsed.one("executor-keys")?.map(PathBuf::from),
                at: parsed.one("at")?,
                freshness_keys: parsed.all("freshness-key"),
                expect_policies: parsed
                    .all("expect-policy")
                    .into_iter()
                    .map(PathBuf::from)
                    .collect(),
                expect_attestation: parsed.one("expect-attestation")?.map(PathBuf::from),
                key_history: parsed.one("key-history")?.map(PathBuf::from),
                root_key: parsed.one("root-key")?,
            })
        }
        Some("export") => {
            let parsed = split(
                &tokens[1..],
                &[
                    "na-key",
                    "executor-keys",
                    "known-anchors",
                    "checkpoint",
                    "key-history",
                    "root-key",
                    "cited",
                ],
                &["partial", "from-anchor"],
            )?;
            let [file] = positionals::<1>(&parsed, "export <file> [options]")?;
            Command::Export(ExportArgs {
                file: file.into(),
                na_keys: parsed.all("na-key"),
                executor_keys: parsed.one("executor-keys")?.map(PathBuf::from),
                known_anchors: parsed.one("known-anchors")?.map(PathBuf::from),
                checkpoint: parsed.one("checkpoint")?.map(PathBuf::from),
                partial: parsed.flag("partial"),
                from_anchor: parsed.flag("from-anchor"),
                key_history: parsed.one("key-history")?.map(PathBuf::from),
                root_key: parsed.one("root-key")?,
                cited: parsed.one("cited")?.map(PathBuf::from),
            })
        }
        Some("pack") => {
            // `--period` takes two values.
            let mut rest: Vec<String> = Vec::new();
            let mut period = None;
            let mut tokens_left = tokens[1..].iter();
            while let Some(token) = tokens_left.next() {
                if token == "--period" {
                    let (Some(from), Some(until)) = (tokens_left.next(), tokens_left.next()) else {
                        return Err(Stop::Usage("--period needs two times: FROM UNTIL".into()));
                    };
                    if period.replace((from.clone(), until.clone())).is_some() {
                        return Err(Stop::Usage("--period is given more than once".into()));
                    }
                } else {
                    rest.push(token.clone());
                }
            }
            let parsed = split(
                &rest,
                &[
                    "anchor",
                    "known-anchors",
                    "prior",
                    "prior-entries",
                    "report",
                    "executor-keys",
                    "changes",
                    "tolerance-seconds",
                ],
                &["require-anchors"],
            )?;
            let usage = "pack <dir> --anchor <root key> [options]";
            let [dir] = positionals::<1>(&parsed, usage)?;
            let root_key = parsed.one("anchor")?.ok_or_else(|| {
                Stop::Usage(
                    "pack needs --anchor <root key>: the pack's keys prove nothing alone".into(),
                )
            })?;
            let tolerance_seconds = match parsed.one("tolerance-seconds")? {
                None => 300,
                Some(n) => n
                    .parse::<i64>()
                    .ok()
                    .filter(|n| (0..=86_400).contains(n))
                    .ok_or_else(|| {
                        Stop::Usage(format!("--tolerance-seconds {n:?} is not 0 to 86400"))
                    })?,
            };
            Command::Pack(PackArgs {
                dir: dir.into(),
                root_key,
                known_anchors: parsed.one("known-anchors")?.map(PathBuf::from),
                require_anchors: parsed.flag("require-anchors"),
                prior: parsed.all("prior").into_iter().map(PathBuf::from).collect(),
                prior_entries: parsed.one("prior-entries")?.map(PathBuf::from),
                period,
                report: parsed.one("report")?.map(PathBuf::from),
                executor_keys: parsed.one("executor-keys")?.map(PathBuf::from),
                changes: parsed.one("changes")?.map(PathBuf::from),
                tolerance_seconds,
            })
        }
        Some("key-history") => {
            let parsed = split(&tokens[1..], &["root-key"], &[])?;
            let [file] = positionals::<1>(&parsed, "key-history <file> --root-key <key>")?;
            Command::KeyHistory(KeyHistoryArgs {
                file: file.into(),
                root_key: parsed.one("root-key")?,
            })
        }
        Some(other) => {
            return Err(Stop::Usage(format!(
                "unknown command {other:?}; one of: record, export, pack, key-history"
            )))
        }
    };
    Ok(Cli { json, command })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn reads_options_in_either_form_and_in_any_position() {
        let cli = parse(&argv(
            "record --na-key=a execution r.json --json --na-key b --at 2026-01-01T00:00:00Z",
        ))
        .unwrap();
        assert!(cli.json);
        let Command::Record(args) = cli.command else {
            panic!("not a record command");
        };
        assert_eq!(args.kind, "execution");
        assert_eq!(args.file, PathBuf::from("r.json"));
        assert_eq!(args.na_keys, ["a", "b"]);
        assert_eq!(args.at.as_deref(), Some("2026-01-01T00:00:00Z"));
    }

    #[test]
    fn names_kinds_as_the_sdk_does() {
        assert_eq!(record_kind("checkpoint").unwrap(), "retention_checkpoint");
        assert_eq!(record_kind("Break-Glass").unwrap(), "break_glass");
        assert_eq!(record_kind("key-succession").unwrap(), "key_succession");
        assert!(matches!(record_kind("anchor"), Err(Stop::Usage(_))));
    }

    #[test]
    fn refuses_what_it_does_not_know() {
        for line in [
            "record execution",
            "record execution a.json b.json",
            "export e.jsonl --nope",
            "export e.jsonl --partial=yes",
            "export e.jsonl --checkpoint",
            "export e.jsonl --checkpoint a --checkpoint b",
            "verify e.jsonl",
            "pack dir",
            "pack dir --anchor k --tolerance-seconds -1",
            "pack dir --anchor k --tolerance-seconds 90000",
            "pack dir --anchor k --period 2026-01-01T00:00:00Z",
        ] {
            assert!(matches!(parse(&argv(line)), Err(Stop::Usage(_))), "{line}");
        }
    }

    #[test]
    fn a_double_dash_ends_the_options() {
        let Command::Export(args) = parse(&argv("export -- --odd-name")).unwrap().command else {
            panic!("not an export command");
        };
        assert_eq!(args.file, PathBuf::from("--odd-name"));
    }

    #[test]
    fn help_and_version_win() {
        assert!(matches!(parse(&[]).unwrap().command, Command::Help));
        assert!(matches!(
            parse(&argv("export --help")).unwrap().command,
            Command::Help
        ));
        assert!(matches!(
            parse(&argv("--version")).unwrap().command,
            Command::Version
        ));
    }
}

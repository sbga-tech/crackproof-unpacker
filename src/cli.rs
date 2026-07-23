use std::env;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
#[cfg(test)]
use std::process;

#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, ensure};
use crackproof_unpacker::{analyze, unpack};

#[cfg(test)]
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const MAX_PACKED_INPUT_SIZE: u64 = 512 << 20;

fn usage() -> &'static str {
    "usage: crackproof-unpacker <packed.exe> [unpacked.exe]\n       crackproof-unpacker --analyze-json <packed.exe>"
}

fn default_output_path(packed: &Path) -> Result<PathBuf> {
    let stem = packed
        .file_stem()
        .context("packed input path has no file name")?;
    let mut name = OsString::from(stem);
    name.push("_unpacked");
    if let Some(extension) = packed.extension().filter(|extension| !extension.is_empty()) {
        name.push(".");
        name.push(extension);
    }
    Ok(packed.with_file_name(name))
}

#[derive(Debug, Eq, PartialEq)]
enum Command {
    Unpack { packed: PathBuf, output: PathBuf },
    AnalyzeJson { packed: PathBuf },
}

fn positional_paths(mut args: impl Iterator<Item = OsString>) -> Result<(PathBuf, PathBuf)> {
    let packed = PathBuf::from(args.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
    let output = match args.next() {
        Some(output) => PathBuf::from(output),
        None => default_output_path(&packed)?,
    };
    ensure!(args.next().is_none(), "{}", usage());
    Ok((packed, output))
}

fn parse_command(mut args: impl Iterator<Item = OsString>) -> Result<Command> {
    let first = args.next().ok_or_else(|| anyhow::anyhow!(usage()))?;
    if first == "--analyze-json" {
        let packed = args.next().ok_or_else(|| anyhow::anyhow!(usage()))?;
        ensure!(args.next().is_none(), "{}", usage());
        return Ok(Command::AnalyzeJson {
            packed: PathBuf::from(packed),
        });
    }
    let (packed, output) = positional_paths(std::iter::once(first).chain(args))?;
    Ok(Command::Unpack { packed, output })
}

fn lexical_absolute(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .context("reading current directory")?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(
                    normalized.components().next_back(),
                    Some(Component::Normal(_))
                ) {
                    normalized.pop();
                }
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    Ok(normalized)
}

fn resolved_destination(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .context("reading current directory")?
            .join(path)
    };
    let name = absolute
        .file_name()
        .context("destination path has no file name")?;
    let parent = absolute
        .parent()
        .context("destination path has no parent")?;
    let resolved_parent = fs::canonicalize(parent)
        .with_context(|| format!("resolving destination parent {}", parent.display()))?;
    Ok(resolved_parent.join(name))
}

fn ensure_distinct_input_output(input_path: &Path, output_path: &Path) -> Result<()> {
    let input_lexical = lexical_absolute(input_path)?;
    let output_lexical = lexical_absolute(output_path)?;
    ensure!(
        input_lexical != output_lexical,
        "input and output paths normalize to the same destination: {}",
        input_lexical.display()
    );
    let input_resolved = resolved_destination(input_path)?;
    let output_resolved = resolved_destination(output_path)?;
    ensure!(
        input_resolved != output_resolved,
        "input and output paths resolve to the same destination: {}",
        input_resolved.display()
    );

    if let (Ok(input_existing), Ok(output_existing)) =
        (fs::canonicalize(input_path), fs::canonicalize(output_path))
    {
        ensure!(
            input_existing != output_existing,
            "input and output paths resolve to the same existing file"
        );
    }
    Ok(())
}

fn write_output(path: &Path, data: &[u8]) -> Result<()> {
    let mut file =
        File::create(path).with_context(|| format!("creating output {}", path.display()))?;
    file.write_all(data)
        .with_context(|| format!("writing output {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing output {}", path.display()))
}

fn read_with_limit(reader: impl Read, limit: u64) -> Result<Vec<u8>> {
    let read_limit = limit
        .checked_add(1)
        .context("packed input size cap overflows")?;
    let mut bounded = reader.take(read_limit);
    let mut packed = Vec::new();
    bounded
        .read_to_end(&mut packed)
        .context("reading bounded packed input")?;
    ensure!(
        u64::try_from(packed.len()).context("packed input length does not fit u64")? <= limit,
        "packed input exceeds the {limit}-byte size cap"
    );
    Ok(packed)
}

fn read_packed_path(packed_path: &Path) -> Result<Vec<u8>> {
    let packed_file = File::open(packed_path)
        .with_context(|| format!("opening packed input {}", packed_path.display()))?;
    read_with_limit(packed_file, MAX_PACKED_INPUT_SIZE)
        .with_context(|| format!("reading packed input {}", packed_path.display()))
}

fn run_paths(packed_path: &Path, output_path: &Path) -> Result<()> {
    ensure_distinct_input_output(packed_path, output_path)?;
    let packed = read_packed_path(packed_path)?;
    let output = unpack(&packed)?;
    ensure_distinct_input_output(packed_path, output_path)?;
    write_output(output_path, &output)?;
    Ok(())
}

fn analyze_path(packed_path: &Path) -> Result<crackproof_unpacker::AnalysisReport> {
    let packed = read_packed_path(packed_path)?;
    Ok(analyze(&packed))
}

pub(super) fn run() -> Result<()> {
    match parse_command(env::args_os().skip(1))? {
        Command::Unpack { packed, output } => run_paths(&packed, &output),
        Command::AnalyzeJson { packed } => {
            let report = analyze_path(&packed)?;
            let stdout = std::io::stdout();
            let mut locked = stdout.lock();
            serde_json::to_writer_pretty(&mut locked, &report)
                .context("serializing CrackProof analysis report")?;
            writeln!(locked).context("writing CrackProof analysis report")
        }
    }
}

pub(super) fn failure_line(error: &anyhow::Error) -> String {
    let top_level = error.to_string();
    let root_cause = error.root_cause().to_string();
    if top_level == root_cause {
        format!("error: {top_level}")
    } else {
        format!("error: {top_level}: {root_cause}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_test_directory(label: &str) -> PathBuf {
        let root = env::temp_dir().join(format!(
            "crackproof-unpacker-{label}-{}-{}",
            process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));

        fs::create_dir(&root).unwrap();
        root
    }

    #[test]
    fn parses_unpack_and_analysis_commands_without_reinterpreting_other_dash_paths() {
        assert_eq!(
            parse_command(
                [OsString::from("packed.exe"), OsString::from("unpacked.exe")].into_iter()
            )
            .unwrap(),
            Command::Unpack {
                packed: PathBuf::from("packed.exe"),
                output: PathBuf::from("unpacked.exe"),
            }
        );
        assert_eq!(
            parse_command([OsString::from("packed.exe")].into_iter()).unwrap(),
            Command::Unpack {
                packed: PathBuf::from("packed.exe"),
                output: PathBuf::from("packed_unpacked.exe"),
            }
        );
        assert_eq!(
            parse_command(
                [
                    OsString::from("--analyze-json"),
                    OsString::from("packed.exe")
                ]
                .into_iter()
            )
            .unwrap(),
            Command::AnalyzeJson {
                packed: PathBuf::from("packed.exe"),
            }
        );
        assert_eq!(
            parse_command(
                [OsString::from("-packed.exe"), OsString::from("-output.exe")].into_iter()
            )
            .unwrap(),
            Command::Unpack {
                packed: PathBuf::from("-packed.exe"),
                output: PathBuf::from("-output.exe"),
            }
        );
    }

    #[test]
    fn analysis_command_requires_exactly_one_input() {
        for args in [
            vec![OsString::from("--analyze-json")],
            vec![
                OsString::from("--analyze-json"),
                OsString::from("packed.exe"),
                OsString::from("extra"),
            ],
        ] {
            assert_eq!(
                parse_command(args.into_iter()).unwrap_err().to_string(),
                usage()
            );
        }
    }

    #[test]
    fn accepts_explicit_output_path() {
        assert_eq!(
            positional_paths(
                [OsString::from("packed.exe"), OsString::from("unpacked.exe")].into_iter()
            )
            .unwrap(),
            (PathBuf::from("packed.exe"), PathBuf::from("unpacked.exe"))
        );
    }

    #[test]
    fn derives_output_beside_input_and_preserves_its_extension() {
        for (packed, output) in [
            ("packed.exe", "packed_unpacked.exe"),
            (
                "directory/archive.part.dll",
                "directory/archive.part_unpacked.dll",
            ),
            ("directory/no-extension", "directory/no-extension_unpacked"),
        ] {
            assert_eq!(
                positional_paths([OsString::from(packed)].into_iter()).unwrap(),
                (PathBuf::from(packed), PathBuf::from(output))
            );
        }
    }

    #[test]
    fn accepts_dash_leading_paths_as_positional_arguments() {
        assert_eq!(
            positional_paths(
                [
                    OsString::from("-packed.exe"),
                    OsString::from("-unpacked.exe")
                ]
                .into_iter()
            )
            .unwrap(),
            (PathBuf::from("-packed.exe"), PathBuf::from("-unpacked.exe"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn lexical_parent_components_cannot_pop_the_root() {
        assert_eq!(
            lexical_absolute(Path::new("/../../output.exe")).unwrap(),
            PathBuf::from("/output.exe")
        );
    }

    #[test]
    fn bounded_reader_accepts_the_limit_and_rejects_one_extra_byte() {
        assert_eq!(
            read_with_limit(std::io::Cursor::new([1u8, 2, 3, 4]), 4).unwrap(),
            [1, 2, 3, 4]
        );
        let error = read_with_limit(std::io::Cursor::new([1u8, 2, 3, 4, 5]), 4)
            .unwrap_err()
            .to_string();
        assert!(error.contains("4-byte size cap"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn accepts_non_utf8_paths_without_changing_their_identity() {
        use std::os::unix::ffi::OsStringExt;

        let packed = OsString::from_vec(vec![0xff, b'p', b'a', b'c', b'k', b'e', b'd']);
        let output = OsString::from_vec(vec![0xfe, b'o', b'u', b't', b'p', b'u', b't']);

        assert_eq!(
            positional_paths(vec![packed.clone(), output.clone()].into_iter()).unwrap(),
            (PathBuf::from(packed), PathBuf::from(output))
        );

        let packed = OsString::from_vec(vec![0xff, b'.', b'e', b'x', b'e']);
        let derived = OsString::from_vec(vec![
            0xff, b'_', b'u', b'n', b'p', b'a', b'c', b'k', b'e', b'd', b'.', b'e', b'x', b'e',
        ]);
        assert_eq!(
            positional_paths(vec![packed.clone()].into_iter()).unwrap(),
            (PathBuf::from(packed), PathBuf::from(derived))
        );
    }

    #[test]
    fn rejects_missing_and_extra_arguments() {
        for args in [&[][..], &["packed.exe", "unpacked.exe", "extra"][..]] {
            let error = positional_paths(args.iter().map(OsString::from)).unwrap_err();
            assert_eq!(error.to_string(), usage());
        }
    }

    #[test]
    fn failure_lines_keep_the_top_level_and_root_cause_once() {
        assert_eq!(
            failure_line(&anyhow::anyhow!("usage: test")),
            "error: usage: test"
        );
        assert_eq!(
            failure_line(&anyhow::anyhow!("permission denied").context("reading packed input")),
            "error: reading packed input: permission denied"
        );
    }

    #[test]
    fn rejects_input_output_alias_before_reading_or_writing() {
        let root = temporary_test_directory("same-path");
        let input = root.join("packed.exe");
        fs::write(&input, b"original input").unwrap();

        let error = run_paths(&input, &input).unwrap_err();
        assert!(error.to_string().contains("input and output paths"));
        assert_eq!(fs::read(&input).unwrap(), b"original input");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);

        fs::remove_file(input).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn failed_one_image_unpack_preserves_existing_output() {
        let root = temporary_test_directory("one-image-failure");
        let input = root.join("packed.exe");
        let output = root.join("unpacked.exe");
        fs::write(&input, b"not a PE image").unwrap();
        fs::write(&output, b"previous output").unwrap();

        assert!(run_paths(&input, &output).is_err());
        assert_eq!(fs::read(&output).unwrap(), b"previous output");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 2);

        fs::remove_file(input).unwrap();
        fs::remove_file(output).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn analysis_returns_json_ready_failure_evidence_without_an_output_path() {
        let root = temporary_test_directory("analysis-failure");
        let input = root.join("packed.exe");
        fs::write(&input, b"not a PE image").unwrap();

        let report = analyze_path(&input).unwrap();
        assert_eq!(
            report.error.as_ref().map(|error| error.step),
            Some(crackproof_unpacker::AnalysisStep::InputPe)
        );
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["schema"], "crackproof-analysis/v2");
        assert_eq!(json["error"]["step"], "input_pe");
        for old_key in [
            "last_completed_stage",
            "family",
            concat!("material", "ization"),
            "output_profile",
            "output_size",
            "failure",
        ] {
            assert!(json.get(old_key).is_none(), "obsolete key {old_key}");
        }
        assert!(json["error"].get("stage").is_none());

        fs::remove_file(input).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn rejects_lexically_aliased_input_and_output_destinations() {
        let root = temporary_test_directory("lexical-alias");
        let child = root.join("child");
        let input = root.join("packed.exe");
        let output_alias = child.join("..").join(".").join("packed.exe");
        fs::create_dir(&child).unwrap();
        fs::write(&input, b"original input").unwrap();

        assert!(ensure_distinct_input_output(&input, &output_alias).is_err());
        assert_eq!(fs::read(&input).unwrap(), b"original input");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 2);

        fs::remove_file(input).unwrap();
        fs::remove_dir(child).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn case_distinct_paths_remain_distinct_on_unix() {
        let root = temporary_test_directory("case-distinct");
        let input = root.join("packed.exe");
        let case_distinct_output = root.join("PACKED.EXE");
        assert!(ensure_distinct_input_output(&input, &case_distinct_output).is_ok());

        fs::remove_dir(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_parent_input_output_alias_before_writing() {
        use std::os::unix::fs::symlink;

        let root = temporary_test_directory("parent-alias");
        let real_parent = root.join("real");
        let alias_parent = root.join("alias");
        fs::create_dir(&real_parent).unwrap();
        symlink(&real_parent, &alias_parent).unwrap();

        assert!(
            ensure_distinct_input_output(
                &real_parent.join("packed.exe"),
                &alias_parent.join("packed.exe")
            )
            .is_err()
        );
        assert_eq!(fs::read_dir(&real_parent).unwrap().count(), 0);

        fs::remove_file(alias_parent).unwrap();
        fs::remove_dir(real_parent).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_existing_symlink_input_output_alias_before_writing() {
        use std::os::unix::fs::symlink;

        let root = temporary_test_directory("symlink-alias");
        let input = root.join("packed.exe");
        let output = root.join("unpacked.exe");
        fs::write(&input, b"original input").unwrap();
        symlink(&input, &output).unwrap();

        assert!(ensure_distinct_input_output(&input, &output).is_err());
        assert_eq!(fs::read(&input).unwrap(), b"original input");
        assert_eq!(fs::read(&output).unwrap(), b"original input");

        fs::remove_file(output).unwrap();
        fs::remove_file(input).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn std_writer_replaces_an_existing_file() {
        let root = temporary_test_directory("std-write-existing");
        let output = root.join("unpacked.exe");
        fs::write(&output, b"previous output").unwrap();

        write_output(&output, b"new output").unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"new output");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);

        fs::remove_file(output).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn std_writer_creates_a_new_file() {
        let root = temporary_test_directory("std-write-new");
        let output = root.join("unpacked.exe");

        write_output(&output, b"new output").unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"new output");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);

        fs::remove_file(output).unwrap();
        fs::remove_dir(root).unwrap();
    }
}

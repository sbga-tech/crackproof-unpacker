use std::time::Instant;

use anyhow::{Context, Result, ensure};
use tracing::{Span, debug, info, info_span, trace};

use self::outcome::{ImportSource, ImportSummary, OutputArtifactSummary, PeSummary, ProtectorInfo};
use crate::pe::{Machine, Pe, PeKind};

use self::cancellation::{CancellationToken, Cancelled};
use self::failure::{FailureReason, PipelineFailure};
use self::observer::{Observer, StateEvent};
use self::outcome::{PipelineOutput, RunSummary, StageTiming};
use self::progress::ProgressUnit;
use self::request::PipelineRequest;
use self::stage::{Operation, Stage};
use self::stages::payload::{bootstrap, decrypt};
use self::stages::rebuild::{self, ReconstructionInput};
use self::stages::startup::OutputEntry;
use self::stages::{detect, imports, read, startup, write};

pub mod cancellation;
pub mod failure;
pub mod observer;
pub mod outcome;
pub mod progress;
pub mod request;
pub mod stage;
pub(crate) mod stages;

#[cfg(test)]
mod tests;

const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

fn span_for_stage(stage: Stage) -> Span {
    match stage {
        Stage::ReadInput => info_span!("read_input"),
        Stage::InputValidation => info_span!("input_validation"),
        Stage::ProtectorDetection => info_span!("protector_detection"),
        Stage::PayloadRecovery => info_span!("payload_recovery"),
        Stage::ImageValidation => info_span!("image_validation"),
        Stage::StartupRecovery => info_span!("startup_recovery"),
        Stage::ImportRecovery => info_span!("import_recovery"),
        Stage::OutputRebuild => info_span!("output_rebuild"),
        Stage::WriteOutput => info_span!("write_output"),
    }
}

fn emit_completed_progress(
    observer: &mut dyn Observer,
    stage: Stage,
    operation: Operation,
    completed: usize,
    unit: ProgressUnit,
) -> Result<()> {
    let completed = u64::try_from(completed).context("progress count does not fit u64")?;
    observer
        .observe(StateEvent::Progress {
            stage,
            operation,
            completed,
            total: completed,
            unit,
        })
        .context("emitting completed progress")
}

/// Complete CrackProof recovery pipeline, including filesystem I/O.
pub struct Pipeline<'a> {
    observer: &'a mut dyn Observer,
    cancellation: &'a CancellationToken,
    started: Option<Instant>,
}

impl<'a> Pipeline<'a> {
    pub fn new(observer: &'a mut dyn Observer, cancellation: &'a CancellationToken) -> Self {
        Self {
            observer,
            cancellation,
            started: None,
        }
    }

    pub fn run(&mut self, request: &PipelineRequest) -> Result<PipelineOutput, PipelineFailure> {
        let run_started = Instant::now();
        self.started = Some(run_started);
        self.observer
            .observe(StateEvent::RunStarted)
            .map_err(|error| {
                PipelineFailure::new(
                    FailureReason::Io,
                    None,
                    None,
                    anyhow::Error::new(error).context("emitting run-start state"),
                    RunSummary::default(),
                )
            })?;
        let mut summary = RunSummary::default();
        let cancellation = self.cancellation;

        summary.dry_run = request.dry_run;
        let stage_span = span_for_stage(Stage::ReadInput);
        let stage_guard = stage_span.enter();
        let packed = self.run_stage(
            &mut summary,
            Stage::ReadInput,
            Operation::ReadInput,
            |observer| {
                info!(path = %request.input.display(), "reading packed input");
                let packed = read::read_bounded(&request.input, cancellation)
                    .context("reading primary packed artifact")?;
                emit_completed_progress(
                    observer,
                    Stage::ReadInput,
                    Operation::ReadInput,
                    packed.len(),
                    ProgressUnit::Bytes,
                )?;
                info!(path = %request.input.display(), bytes = packed.len(), "read packed input");
                Ok(packed)
            },
        )?;
        summary.input_artifact = Some(read::summarize(
            &request.input,
            &packed,
            request.hash_artifacts,
        ));
        drop(stage_guard);
        drop(stage_span);

        let stage_span = span_for_stage(Stage::InputValidation);
        let stage_guard = stage_span.enter();
        let packed_pe = self.run_stage(
            &mut summary,
            Stage::InputValidation,
            Operation::ParseInputPe,
            |observer| {
                let pe = Pe::parse(&packed).context("parsing packed PE image")?;
                emit_completed_progress(
                    observer,
                    Stage::InputValidation,
                    Operation::ParseInputPe,
                    packed.len(),
                    ProgressUnit::Bytes,
                )?;
                Ok(pe)
            },
        )?;
        summary.input_pe = Some(PeSummary {
            kind: match packed_pe.kind() {
                PeKind::Pe32 => "PE32",
                PeKind::Pe32Plus => "PE32+",
            },
            machine: match packed_pe.machine_kind() {
                Machine::I386 => "I386",
                Machine::Amd64 => "AMD64",
            },
            image_base: packed_pe.image_base,
            entry_rva: packed_pe.entry_rva,
            size_of_image: packed_pe.size_of_image,
            section_count: packed_pe.section_count,
        });
        info!(
            kind = ?packed_pe.kind(),
            machine = ?packed_pe.machine_kind(),
            image_base = packed_pe.image_base,
            entry_rva = packed_pe.entry_rva,
            section_alignment = packed_pe.section_alignment,
            file_alignment = packed_pe.file_alignment,
            size_of_image = packed_pe.size_of_image,
            "validated packed PE"
        );
        for section in &packed_pe.sections {
            debug!(
                index = section.index,
                name = %String::from_utf8_lossy(&section.name_bytes).trim_end_matches('\0'),
                rva = section.virtual_address,
                virtual_size = section.virtual_size,
                raw_pointer = section.raw_pointer,
                raw_size = section.raw_size,
                characteristics = section.characteristics,
                "packed PE section"
            );
        }
        for (index, directory) in packed_pe.directories.iter().enumerate() {
            if !directory.is_empty() {
                debug!(
                    index,
                    rva = directory.virtual_address,
                    size = directory.size,
                    "packed PE data directory"
                );
            }
        }
        drop(stage_guard);
        drop(stage_span);

        let stage_span = span_for_stage(Stage::ProtectorDetection);
        let stage_guard = stage_span.enter();
        let (family, discovered_sidecar_path, sidecar) = self.run_stage(
            &mut summary,
            Stage::ProtectorDetection,
            Operation::ScanDescriptors,
            |observer| {
                let family = detect::detect_family_with_cancellation(
                    &packed,
                    &packed_pe,
                    cancellation,
                    |completed, total| {
                        observer
                            .observe(StateEvent::Progress {
                                stage: Stage::ProtectorDetection,
                                operation: Operation::ScanDescriptors,
                                completed,
                                total,
                                unit: ProgressUnit::Offsets,
                            })
                            .context("emitting descriptor scan progress")
                    },
                )
                .context("detecting one unambiguous CrackProof family")?;
                let discovered_sidecar_path = read::sidecar_path(&request.input);
                let sidecar = if discovered_sidecar_path
                    .try_exists()
                    .with_context(|| {
                        format!(
                            "checking packed sidecar {}",
                            discovered_sidecar_path.display()
                        )
                    })?
                {
                    info!(path = %discovered_sidecar_path.display(), "reading packed sidecar");
                    let sidecar = read::read_bounded(&discovered_sidecar_path, cancellation)
                        .context("reading packer-selected sidecar artifact")?;
                    info!(path = %discovered_sidecar_path.display(), bytes = sidecar.len(), "read packed sidecar");
                    Some(sidecar)
                } else {
                    debug!(path = %discovered_sidecar_path.display(), "no packed sidecar present");
                    None
                };
                Ok((family, discovered_sidecar_path, sidecar))
            },
        )?;
        summary.sidecar_artifact = sidecar
            .as_deref()
            .map(|bytes| read::summarize(&discovered_sidecar_path, bytes, request.hash_artifacts));
        summary.protector = Some(ProtectorInfo {
            format: "cp-konn1",
            descriptor_file_offset: family.descriptor.file_offset,
            key: family.descriptor.key,
            packed_entry_rva: family.descriptor.entry_rva,
            destination_rva: family.descriptor.destination_rva,
            source_offset: family.descriptor.source_offset,
            length: family.descriptor.length,
            source_rva: family.descriptor.source_rva,
            destination_section_index: family.descriptor.destination_section_index,
        });
        info!(
            descriptor_offset = family.descriptor.file_offset,
            key = family.descriptor.key,
            entry_rva = family.descriptor.entry_rva,
            destination_rva = family.descriptor.destination_rva,
            source_offset = family.descriptor.source_offset,
            source_length = family.descriptor.length,
            source_rva = family.descriptor.source_rva,
            "selected CrackProof KONN descriptor"
        );
        drop(stage_guard);
        drop(stage_span);

        let stage_span = span_for_stage(Stage::PayloadRecovery);
        let stage_guard = stage_span.enter();
        let decryption = self.run_stage(
            &mut summary,
            Stage::PayloadRecovery,
            Operation::MaterializeImage,
            |observer| {
                let mut bootstrap = bootstrap::PackedBootstrap::from(&family.descriptor);
                let decryption = if let Some(sidecar) = sidecar.as_deref() {
                    let descriptor_end = family
                        .descriptor
                        .file_offset
                        .checked_add(detect::KONN_DESCRIPTOR_SIZE)
                        .context("sidecar descriptor range overflows")?;
                    let packed_descriptor = packed
                        .get(family.descriptor.file_offset..descriptor_end)
                        .context("packed KONN descriptor disappeared")?;
                    let sidecar_descriptor = sidecar
                        .get(..detect::KONN_DESCRIPTOR_SIZE)
                        .context("sidecar does not contain a complete KONN descriptor")?;
                    ensure!(
                        sidecar_descriptor == packed_descriptor,
                        "sidecar KONN descriptor does not match the packed image"
                    );
                    bootstrap.descriptor_file_offset = 0;
                    decrypt::decrypt_packed_image_from_source_with_cancellation(
                        &packed,
                        &packed_pe,
                        sidecar,
                        bootstrap,
                        None,
                        cancellation,
                    )
                } else {
                    decrypt::decrypt_packed_image_with_cancellation(
                        &packed,
                        &packed_pe,
                        bootstrap,
                        cancellation,
                    )
                }
                .context("recovering packed payload")?;
                emit_completed_progress(
                    observer,
                    Stage::PayloadRecovery,
                    Operation::MaterializeImage,
                    decryption.decryption_details.block_count,
                    ProgressUnit::Records,
                )?;
                Ok(decryption)
            },
        )?;
        let decrypt::DecryptedImage {
            mut image,
            destination_record_ranges,
            destination_ranges,
            decryption_details,
        } = decryption;
        summary.decryption = Some(decryption_details);
        info!(
            blocks = summary
                .decryption
                .as_ref()
                .map_or(0, |details| details.block_count),
            copied_blocks = summary
                .decryption
                .as_ref()
                .map_or(0, |details| details.copied_block_count),
            decoded_blocks = summary
                .decryption
                .as_ref()
                .map_or(0, |details| details.decoded_block_count),
            destination_ranges = destination_ranges.len(),
            image_bytes = image.len(),
            "materialized recovered mapped image"
        );
        drop(stage_guard);
        drop(stage_span);

        let stage_span = span_for_stage(Stage::ImageValidation);
        let stage_guard = stage_span.enter();
        let decrypted_pe = self.run_stage(
            &mut summary,
            Stage::ImageValidation,
            Operation::ParseRecoveredPe,
            |observer| {
                let pe = Pe::parse_mapped(&image).context("parsing recovered mapped PE image")?;
                emit_completed_progress(
                    observer,
                    Stage::ImageValidation,
                    Operation::ParseRecoveredPe,
                    image.len(),
                    ProgressUnit::Bytes,
                )?;
                Ok(pe)
            },
        )?;
        info!(
            kind = ?decrypted_pe.kind(),
            machine = ?decrypted_pe.machine_kind(),
            entry_rva = decrypted_pe.entry_rva,
            size_of_image = decrypted_pe.size_of_image,
            sections = decrypted_pe.section_count,
            "validated recovered PE image"
        );
        for section in &decrypted_pe.sections {
            debug!(
                index = section.index,
                name = %String::from_utf8_lossy(&section.name_bytes).trim_end_matches('\0'),
                rva = section.virtual_address,
                virtual_size = section.virtual_size,
                characteristics = section.characteristics,
                "recovered PE section"
            );
        }
        for (index, directory) in decrypted_pe.directories.iter().enumerate() {
            if !directory.is_empty() {
                debug!(
                    index,
                    rva = directory.virtual_address,
                    size = directory.size,
                    "recovered PE data directory"
                );
            }
        }
        drop(stage_guard);
        drop(stage_span);

        let stage_span = span_for_stage(Stage::StartupRecovery);
        let stage_guard = stage_span.enter();
        let selected_output = self.run_stage(
            &mut summary,
            Stage::StartupRecovery,
            Operation::ScanStartup,
            |observer| {
                let selected = startup::select_output_entry(&mut image, &decrypted_pe)
                    .context("selecting output entry profile")?;
                emit_completed_progress(
                    observer,
                    Stage::StartupRecovery,
                    Operation::ScanStartup,
                    1,
                    ProgressUnit::Candidates,
                )?;
                Ok(selected)
            },
        )?;
        summary.recovered_program = Some(selected_output.fingerprint());
        info!(
            startup_rva = selected_output.entry.entry_rva(),
            code_transform = ?selected_output.code_transform,
            "selected recovered startup profile"
        );
        let output_entry = selected_output.entry;
        drop(stage_guard);
        drop(stage_span);

        let stage_span = span_for_stage(Stage::ImportRecovery);
        let stage_guard = stage_span.enter();
        if matches!(output_entry, OutputEntry::Managed { .. })
            && let Some(directory) = decrypted_pe
                .directories
                .get(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
                .copied()
                .filter(|directory| !directory.is_empty())
        {
            validate_clr_directory(&image, &decrypted_pe, directory)
                .context("validating CLR metadata before standard import selection")
                .map_err(|error| {
                    self.make_failure(
                        &mut summary,
                        Stage::ImportRecovery,
                        Operation::DiscoverImports,
                        error,
                    )
                })?;
        }
        let (import_profile, discovery) = self.run_stage(
            &mut summary,
            Stage::ImportRecovery,
            Operation::DiscoverImports,
            |observer| {
                let (profile, discovery) = match output_entry {
                    OutputEntry::Managed { .. } => (
                        imports::ImportProfile::Standard,
                        imports::discover_imports_in_image(
                            &image,
                            &decrypted_pe,
                            imports::ImportProfile::Standard,
                        )?,
                    ),
                    OutputEntry::NativeDll { .. } => {
                        imports::discover_native_dll_imports_in_image(&image, &decrypted_pe)?
                    }
                    OutputEntry::Native(_) => (
                        imports::ImportProfile::EncodedLoader,
                        imports::discover_imports_in_image(
                            &image,
                            &decrypted_pe,
                            imports::ImportProfile::EncodedLoader,
                        )?,
                    ),
                };
                emit_completed_progress(
                    observer,
                    Stage::ImportRecovery,
                    Operation::DiscoverImports,
                    discovery.function_count,
                    ProgressUnit::Symbols,
                )?;
                Ok((profile, discovery))
            },
        )?;
        info!(
            profile = ?import_profile,
            table_rva = discovery.table_rva,
            modules = discovery.modules.len(),
            functions = discovery.function_count,
            named = discovery.named_count,
            ordinal = discovery.ordinal_count,
            "selected recovered import graph"
        );
        for module in &discovery.modules {
            debug!(
                dll = %module.dll,
                destination_rva = module.destination_rva,
                symbols = module.symbols.len(),
                "selected import module"
            );
            for (index, symbol) in module.symbols.iter().enumerate() {
                match symbol {
                    imports::ImportSymbol::Name { hint, name } => trace!(
                        dll = %module.dll,
                        index,
                        hint,
                        name = %name,
                        "selected named import"
                    ),
                    imports::ImportSymbol::Ordinal(ordinal) => trace!(
                        dll = %module.dll,
                        index,
                        ordinal,
                        "selected ordinal import"
                    ),
                }
            }
        }
        summary.imports = Some(ImportSummary {
            source: match import_profile {
                imports::ImportProfile::EncodedLoader => ImportSource::CrackproofLoader,
                imports::ImportProfile::Standard => ImportSource::PeImportTable,
            },
            module_count: discovery.modules.len(),
            function_count: discovery.function_count,
        });
        drop(stage_guard);
        drop(stage_span);

        let stage_span = span_for_stage(Stage::OutputRebuild);
        let stage_guard = stage_span.enter();
        let managed_kind = match output_entry {
            OutputEntry::Managed { kind, .. } => Some(kind),
            _ => None,
        };
        let rebuilt = self.run_stage(
            &mut summary,
            Stage::OutputRebuild,
            Operation::SerializeOutput,
            |observer| {
                let rebuilt = if let Some(kind) = managed_kind {
                    rebuild::managed::rebuild_semantic_clr(&image, &decrypted_pe, &discovery, kind)
                        .map(|rebuilt| {
                            (
                                rebuilt.output,
                                Some(rebuilt.generated),
                                Some(rebuilt.source),
                            )
                        })
                } else {
                    rebuild::rebuild(ReconstructionInput {
                        mapped: image,
                        decrypted_pe,
                        output_entry,
                        discovery,
                        import_profile,
                        destination_record_ranges,
                        destination_ranges,
                    })
                    .map(|output| (output, None, None))
                }
                .context("rebuilding static PE output")?;
                let output_pe =
                    Pe::parse(&rebuilt.0).context("validating reconstructed PE output")?;
                info!(
                    kind = ?output_pe.kind(),
                    machine = ?output_pe.machine_kind(),
                    image_base = output_pe.image_base,
                    entry_rva = output_pe.entry_rva,
                    size_of_image = output_pe.size_of_image,
                    file_bytes = rebuilt.0.len(),
                    managed = managed_kind.is_some(),
                    "verified reconstructed PE output"
                );
                for section in &output_pe.sections {
                    debug!(
                        index = section.index,
                        name = %String::from_utf8_lossy(&section.name_bytes).trim_end_matches('\0'),
                        rva = section.virtual_address,
                        virtual_size = section.virtual_size,
                        raw_pointer = section.raw_pointer,
                        raw_size = section.raw_size,
                        characteristics = section.characteristics,
                        "reconstructed PE section"
                    );
                }
                for (index, directory) in output_pe.directories.iter().enumerate() {
                    if !directory.is_empty() {
                        debug!(
                            index,
                            rva = directory.virtual_address,
                            size = directory.size,
                            "reconstructed PE data directory"
                        );
                    }
                }
                let output_pe_summary = PeSummary {
                    kind: match output_pe.kind() {
                        PeKind::Pe32 => "PE32",
                        PeKind::Pe32Plus => "PE32+",
                    },
                    machine: match output_pe.machine_kind() {
                        Machine::I386 => "I386",
                        Machine::Amd64 => "AMD64",
                    },
                    image_base: output_pe.image_base,
                    entry_rva: output_pe.entry_rva,
                    size_of_image: output_pe.size_of_image,
                    section_count: output_pe.section_count,
                };
                emit_completed_progress(
                    observer,
                    Stage::OutputRebuild,
                    Operation::SerializeOutput,
                    rebuilt.0.len(),
                    ProgressUnit::Bytes,
                )?;
                Ok((rebuilt, output_pe_summary))
            },
        )?;
        let (rebuilt, output_pe) = rebuilt;
        let (image, generated_semantic_clr_container, managed_semantic_clr_source) = rebuilt;
        summary.output_pe = Some(output_pe);
        summary.generated_semantic_clr_container = generated_semantic_clr_container;
        summary.managed_semantic_clr_source = managed_semantic_clr_source;
        summary.rebuilt_file_size = Some(image.len());
        drop(stage_guard);
        drop(stage_span);
        let stage_span = span_for_stage(Stage::WriteOutput);
        let stage_guard = stage_span.enter();
        let output_artifact = self.run_stage(
            &mut summary,
            Stage::WriteOutput,
            Operation::WriteOutput,
            |observer| {
                let output_path = if request.dry_run {
                    None
                } else {
                    let path = match &request.output {
                        Some(path) => path.clone(),
                        None => write::default_output_path(&request.input)?,
                    };
                    write::ensure_distinct_paths(&request.input, &path)?;
                    Some(path)
                };
                let output_hash = if let Some(path) = &output_path {
                    info!(path = %path.display(), bytes = image.len(), "committing reconstructed output atomically");
                    let hash = write::commit(
                        path,
                        &image,
                        cancellation,
                        request.hash_artifacts,
                    )?;
                    info!(path = %path.display(), bytes = image.len(), "committed reconstructed output");
                    hash
                } else if request.hash_artifacts {
                    Some(write::digest(&image))
                } else {
                    None
                };
                emit_completed_progress(
                    observer,
                    Stage::WriteOutput,
                    Operation::WriteOutput,
                    image.len(),
                    ProgressUnit::Bytes,
                )?;
                Ok(OutputArtifactSummary {
                    path: output_path.as_ref().map(|path| path.display().to_string()),
                    size: image.len(),
                    sha256: output_hash,
                    written: output_path.is_some(),
                })
            },
        )?;
        summary.output_artifact = Some(output_artifact);
        drop(stage_guard);
        drop(stage_span);
        summary.elapsed_ms = run_started.elapsed().as_millis();
        self.observer
            .observe(StateEvent::RunCompleted { summary: &summary })
            .map_err(|error| {
                PipelineFailure::new(
                    FailureReason::Io,
                    None,
                    None,
                    anyhow::Error::new(error).context("emitting terminal completion state"),
                    summary.clone(),
                )
            })?;
        Ok(PipelineOutput { image, summary })
    }

    fn run_stage<T>(
        &mut self,
        summary: &mut RunSummary,
        stage: Stage,
        operation: Operation,
        work: impl FnOnce(&mut dyn Observer) -> Result<T>,
    ) -> Result<T, PipelineFailure> {
        self.cancellation
            .checkpoint()
            .map_err(|error| self.make_failure(summary, stage, operation, error))?;
        let started = Instant::now();
        self.observer
            .observe(StateEvent::StageStarted { stage })
            .and_then(|()| {
                self.observer.observe(StateEvent::OperationStarted {
                    stage,
                    operation,
                    total: None,
                    unit: ProgressUnit::Bytes,
                })
            })
            .map_err(|error| {
                PipelineFailure::new(
                    FailureReason::Io,
                    Some(stage),
                    Some(operation),
                    anyhow::Error::new(error).context("emitting stage-start state"),
                    summary.clone(),
                )
            })?;

        let value = match work(self.observer) {
            Ok(value) => value,
            Err(error) => return Err(self.make_failure(summary, stage, operation, error)),
        };
        self.cancellation
            .checkpoint()
            .map_err(|error| self.make_failure(summary, stage, operation, error))?;
        let duration = started.elapsed();
        self.observer
            .observe(StateEvent::OperationCompleted { stage, operation })
            .and_then(|()| {
                self.observer
                    .observe(StateEvent::StageCompleted { stage, duration })
            })
            .map_err(|error| {
                PipelineFailure::new(
                    FailureReason::Io,
                    Some(stage),
                    Some(operation),
                    anyhow::Error::new(error).context("emitting stage-completion state"),
                    summary.clone(),
                )
            })?;
        summary
            .stage_timings
            .push(StageTiming::new(stage, duration));
        Ok(value)
    }

    fn make_failure(
        &mut self,
        summary: &mut RunSummary,
        stage: Stage,
        operation: Operation,
        error: anyhow::Error,
    ) -> PipelineFailure {
        summary.elapsed_ms = self
            .started
            .map_or(0, |started| started.elapsed().as_millis());
        if let Some(selection) = error.downcast_ref::<decrypt::PayloadPlanSelectionError>() {
            summary.decryption = Some(selection.decryption_details.clone());
        }
        let reason = classify_failure(stage, &error);
        let failure =
            PipelineFailure::new(reason, Some(stage), Some(operation), error, summary.clone());
        let _ = self.observer.observe(StateEvent::RunFailed {
            failure: &failure.failure,
        });
        failure
    }
}

fn classify_failure(stage: Stage, error: &anyhow::Error) -> FailureReason {
    if error.downcast_ref::<Cancelled>().is_some() {
        return FailureReason::Cancelled;
    }
    if stage == Stage::InputValidation {
        return FailureReason::InvalidInput;
    }
    if matches!(stage, Stage::ReadInput | Stage::WriteOutput)
        || error.downcast_ref::<std::io::Error>().is_some()
    {
        return FailureReason::Io;
    }
    let message = error.to_string().to_ascii_lowercase();
    if message.contains("ambiguous") || message.contains("multiple ") {
        FailureReason::Ambiguous
    } else {
        FailureReason::Unsupported
    }
}

fn validate_clr_directory(
    image: &[u8],
    pe: &Pe,
    directory: crate::pe::DataDirectory,
) -> Result<()> {
    let range = directory
        .checked_rva_range()?
        .context("CLR directory is partial")?;
    ensure!(directory.size >= 72, "CLR directory is truncated");
    pe.section_for_rva_range(range.start, usize::try_from(range.end - range.start)?)?;
    let header = image
        .get(usize::try_from(range.start)?..usize::try_from(range.start)? + 72)
        .context("CLR header exceeds mapped image")?;
    let cb = u32::from_le_bytes(header[..4].try_into().expect("four-byte CLR cb"));
    ensure!(cb >= 72 && cb <= directory.size, "CLR header cb is invalid");
    let metadata_rva =
        u32::from_le_bytes(header[8..12].try_into().expect("four-byte metadata RVA"));
    let metadata_size =
        u32::from_le_bytes(header[12..16].try_into().expect("four-byte metadata size"));
    ensure!(
        metadata_rva != 0 && metadata_size >= 16,
        "CLR metadata is absent or truncated"
    );
    pe.section_for_rva_range(metadata_rva, usize::try_from(metadata_size)?)?;
    let start = usize::try_from(metadata_rva)?;
    let end = start
        .checked_add(usize::try_from(metadata_size)?)
        .context("CLR metadata range overflows")?;
    let metadata = image
        .get(start..end)
        .context("CLR metadata exceeds mapped image")?;
    ensure!(
        &metadata[..4] == b"BSJB",
        "CLR metadata signature is invalid"
    );
    let version_len = usize::try_from(u32::from_le_bytes(
        metadata[12..16]
            .try_into()
            .expect("four-byte CLR version length"),
    ))?;
    ensure!(
        version_len.is_multiple_of(4),
        "CLR metadata version length is not aligned"
    );
    let root_end = 16usize
        .checked_add(version_len)
        .and_then(|offset| offset.checked_add(4))
        .context("CLR metadata root length overflows")?;
    ensure!(
        root_end <= metadata.len(),
        "CLR metadata version/root fields are truncated"
    );
    Ok(())
}

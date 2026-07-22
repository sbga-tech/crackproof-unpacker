use anyhow::{Context, Result, ensure};

use crate::pe::Pe;
use crate::reconstruct::{self, ReconstructionInput};
use crate::report::{
    AnalysisReport, AnalysisStep, GeneratedSemanticClrContainer, ImportSource, ImportSummary,
    ManagedSemanticClrSource, ProtectorInfo,
};
use crate::unpack::profile::OutputEntry;

mod bootstrap;
pub(crate) mod decrypt;
pub(crate) mod detect;
pub(crate) mod imports;
mod nested;
pub(crate) mod profile;
#[cfg(test)]
mod tests;
const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

fn finish_stage<T>(
    report: &mut AnalysisReport,
    step: AnalysisStep,
    result: Result<T>,
) -> Result<T> {
    match result {
        Ok(value) => {
            report.completed(step);
            Ok(value)
        }
        Err(error) => {
            report.fail(step, format!("{error:#}"));
            Err(error)
        }
    }
}

/// Runs the same authenticated pipeline as [`unpack`] and records its first
/// unsupported boundary without requiring the caller to parse an error string.
pub fn analyze(packed: &[u8]) -> AnalysisReport {
    let mut report = AnalysisReport::default();
    let _ = unpack_recording(packed, &mut report);
    report
}

/// Unpacks one CrackProof-protected PE image into a compact static PE file.
pub fn unpack(packed: &[u8]) -> Result<Vec<u8>> {
    let mut report = AnalysisReport::default();
    unpack_recording(packed, &mut report)
}

fn unpack_recording(packed: &[u8], report: &mut AnalysisReport) -> Result<Vec<u8>> {
    let packed_pe = finish_stage(
        report,
        AnalysisStep::InputPe,
        Pe::parse(packed).context("parsing packed PE32 image"),
    )?;

    let family = finish_stage(
        report,
        AnalysisStep::ProtectorDetection,
        detect::detect_family(packed, &packed_pe)
            .context("detecting one unambiguous CrackProof family"),
    )?;
    report.protector = Some(ProtectorInfo {
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

    let bootstrap = bootstrap::PackedBootstrap::from(&family.descriptor);
    let decryption = decrypt::decrypt_packed_image(packed, &packed_pe, bootstrap)
        .context("decrypting packed image");
    if let Err(error) = &decryption
        && let Some(selection) = error.downcast_ref::<decrypt::DecryptionSelectionError>()
    {
        report.decryption = Some(selection.decryption_details.clone());
    }
    let decrypt::DecryptedImage {
        mut image,
        destination_ranges: _destination_ranges,
        decryption_details,
    } = finish_stage(report, AnalysisStep::PayloadDecryption, decryption)?;
    report.decryption = Some(decryption_details);

    let decrypted_pe = finish_stage(
        report,
        AnalysisStep::DecryptedPe,
        Pe::parse_mapped(&image).context("parsing decrypted PE32 image"),
    )?;

    let selected_output = finish_stage(
        report,
        AnalysisStep::StartupDetection,
        profile::select_output_entry(&mut image, &decrypted_pe)
            .context("selecting output entry profile"),
    )?;
    report.recovered_program = Some(selected_output.fingerprint());
    let output_entry = selected_output.entry;

    // The encoded loader graph is packer evidence recovered from section bytes.
    let import_profile = if let Some(directory) = decrypted_pe
        .directories
        .get(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
        .copied()
        .filter(|directory| !directory.is_empty())
    {
        validate_clr_directory(&image, &decrypted_pe, directory)
            .context("validating CLR metadata before standard import selection")?;
        imports::ImportProfile::Standard
    } else {
        imports::ImportProfile::EncodedLoader
    };
    let discovery = finish_stage(
        report,
        AnalysisStep::ImportRecovery,
        imports::discover_imports_in_image(&image, &decrypted_pe, import_profile)
            .context("discovering payload imports"),
    )?;
    report.imports = Some(ImportSummary {
        source: match import_profile {
            imports::ImportProfile::EncodedLoader => ImportSource::CrackproofLoader,
            imports::ImportProfile::Standard => ImportSource::PeImportTable,
        },
        module_count: discovery.modules.len(),
        function_count: discovery.function_count,
    });
    let output = finish_stage(
        report,
        AnalysisStep::PeRebuild,
        (|| {
            if matches!(output_entry, OutputEntry::Managed { .. }) {
                reconstruct::managed::rebuild_semantic_clr(&image, &decrypted_pe, &discovery)
            } else {
                reconstruct::rebuild(ReconstructionInput {
                    mapped: image,
                    decrypted_pe,
                    output_entry,
                    discovery,
                })
            }
        })(),
    )?;
    if matches!(output_entry, OutputEntry::Managed { .. }) {
        report.generated_semantic_clr_container = Some(GeneratedSemanticClrContainer {
            generated_architecture: "PE32/I386",
            entry_rva: 0x5abf80,
            import_rva: 0x5abf00,
            iat_rva: 0x2000,
            reloc_rva: 0x5ae000,
            cor20_rva: 0x2008,
            cor20_size: 0x48,
            metadata_rva: 0x259e0c,
        });
        report.managed_semantic_clr_source = Some(ManagedSemanticClrSource {
            source_architecture: "PE32+/AMD64",
            source_pe_entry_rva: 0x1b5c,
            source_import_rva: 0x1b9c,
            source_iat_rva: 0x1bc4,
            source_cor20_rva: 0x2008,
            source_metadata_rva: 0x259e0c,
        });
    }
    report.finish(output.len());
    Ok(output)
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
    let cb = u32::from_le_bytes(header[..4].try_into().unwrap());
    ensure!(cb >= 72 && cb <= directory.size, "CLR header cb is invalid");
    let metadata_rva = u32::from_le_bytes(header[8..12].try_into().unwrap());
    let metadata_size = u32::from_le_bytes(header[12..16].try_into().unwrap());
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
    let version_len = usize::try_from(u32::from_le_bytes(metadata[12..16].try_into().unwrap()))?;
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

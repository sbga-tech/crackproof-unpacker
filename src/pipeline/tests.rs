use super::*;
use sha2::Digest as _;

use crate::pe::{DataDirectory, IMAGE_DIRECTORY_ENTRY_SECURITY, Machine, Section};
use crate::pipeline::stages::detect::{
    IMAGE_SCN_MEM_EXECUTE, KONN_MAGIC, KONN_WORD_COUNT, MAX_KONN_CANDIDATES, MAX_KONN_MATCHES,
    MAX_KONN_SCAN_BODY_BYTES, combine_family_evidence, decode_konn_words, detect_family,
    encode_konn_words, ensure_konn_scan_body_bound, reserve_konn_candidate, scan_konn_descriptors,
};

#[derive(Default)]
struct RecordingObserver {
    events: Vec<&'static str>,
    terminal_events: usize,
    failure_had_input_artifact: bool,
}

impl Observer for RecordingObserver {
    fn observe(&mut self, event: StateEvent<'_>) -> std::io::Result<()> {
        let kind = match event {
            StateEvent::RunStarted => "run_started",
            StateEvent::StageStarted { .. } => "stage_started",
            StateEvent::OperationStarted { .. } => "operation_started",
            StateEvent::Progress { .. } => "progress",
            StateEvent::OperationCompleted { .. } => "operation_completed",
            StateEvent::StageCompleted { .. } => "stage_completed",
            StateEvent::RunCompleted { .. } => {
                self.terminal_events += 1;
                "run_completed"
            }
            StateEvent::RunFailed { failure } => {
                self.terminal_events += 1;
                self.failure_had_input_artifact = failure.partial_summary.input_artifact.is_some();
                "run_failed"
            }
        };
        self.events.push(kind);
        Ok(())
    }
}

#[test]
fn every_stage_has_a_stable_tracing_span() {
    let stages = [
        Stage::ReadInput,
        Stage::InputValidation,
        Stage::ProtectorDetection,
        Stage::PayloadRecovery,
        Stage::ImageValidation,
        Stage::StartupRecovery,
        Stage::ImportRecovery,
        Stage::OutputRebuild,
        Stage::WriteOutput,
    ];
    assert_eq!(stages.len(), usize::from(Stage::COUNT));

    tracing::subscriber::with_default(tracing_subscriber::registry(), || {
        for stage in stages {
            let span = span_for_stage(stage);
            assert_eq!(
                span.metadata().map(tracing::Metadata::name),
                Some(stage.as_str())
            );
        }
    });
}

#[test]
fn invalid_pe_fails_at_the_typed_input_boundary() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("invalid.exe");
    std::fs::write(&input, b"not a PE").unwrap();
    let request = PipelineRequest {
        input,
        output: None,
        dry_run: true,
        hash_artifacts: true,
    };
    let mut observer = RecordingObserver::default();
    let cancellation = CancellationToken::default();
    let failure = Pipeline::new(&mut observer, &cancellation)
        .run(&request)
        .unwrap_err();
    assert_eq!(failure.failure.reason, FailureReason::InvalidInput);
    assert_eq!(failure.failure.stage, Some(Stage::InputValidation));
    assert_eq!(failure.failure.operation, Some(Operation::ParseInputPe));
    assert!(failure.failure.message.contains("parsing packed PE image"));
    assert_eq!(
        observer.events,
        [
            "run_started",
            "stage_started",
            "operation_started",
            "progress",
            "operation_completed",
            "stage_completed",
            "stage_started",
            "operation_started",
            "run_failed"
        ]
    );
    assert_eq!(observer.terminal_events, 1);
    assert!(observer.failure_had_input_artifact);
}

#[test]
fn reconstructs_polymorphic_pe32_staged_controller_fixture() {
    let input =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("packed/maimai_SDEY_1.99.exe");
    let request = PipelineRequest {
        input,
        output: None,
        dry_run: true,
        hash_artifacts: true,
    };
    let mut observer = RecordingObserver::default();
    let cancellation = CancellationToken::default();

    let output = Pipeline::new(&mut observer, &cancellation)
        .run(&request)
        .unwrap();
    let summary = &output.summary;
    let input_artifact = summary.input_artifact.as_ref().unwrap();
    assert_eq!(
        input_artifact.sha256.as_deref(),
        Some("81d359eeb029c881311a4ab770c1d350b068f9ef9d05dfa7ff0bd5d7456b2daa")
    );

    let decryption = summary.decryption.as_ref().unwrap();
    assert_eq!(
        decryption.plan_provenance,
        Some(crate::pipeline::outcome::PayloadPlanProvenance::StagedController)
    );
    assert_eq!(decryption.block_count, 2_264);
    assert_eq!(decryption.copied_block_count, 93);
    let staged = decryption.selected_staged_controller.as_ref().unwrap();
    assert_eq!(staged.shell_table_rva, 0x00c0_3790);
    assert_eq!(staged.seven_stage_rva, 0x00c0_4f70);
    assert_eq!(staged.eighth_stage_rva, 0x00c0_5ef8);
    assert_eq!(staged.file_decoder_rva, 0x00c3_8c00);
    assert_eq!(staged.stage_decoder_rva, 0x00c3_9bbe);
    assert_eq!(staged.file_aes_context_rva, 0x00c3_9aca);
    assert_eq!(staged.stage_aes_context_rva, 0x00c3_a7be);
    assert_eq!(staged.custom_program_offset, 0x0f00);
    assert_eq!(staged.custom_program_length, 71);
    assert_eq!(staged.custom_byte_map.len(), 256);
    assert_eq!(
        staged.stage_raw_key_hex,
        "214aa5f2ed74c698a91f1b8f7506bcb53121d15bfdcb754eb9f29674459d2b1b"
    );
    assert_eq!(staged.file_program_offset, 0x4de0);
    assert_eq!(staged.file_program_length, 67);
    assert_eq!(
        staged.file_raw_key_hex,
        "600c7cd4a476dfc2e85fba282c40151570a9f103b4934c68f8f42f563cdd8abc"
    );
    assert_eq!(staged.file_byte_map.len(), 256);
    assert_eq!(
        hex::encode(sha2::Sha256::digest(&staged.file_byte_map)),
        "70b8563af257c2c7a972288eda61d2ec42673cd50957807948a99119a70393cc"
    );

    let recovered = summary.recovered_program.as_ref().unwrap();
    assert_eq!(recovered.startup_rva, 0x0055_909d);
    assert_eq!(recovered.handoff_rva, None);
    assert_eq!(
        recovered.code_transform,
        crate::pipeline::outcome::CodeTransform::Unchanged
    );
    assert_eq!(
        recovered.startup_kind,
        crate::pipeline::outcome::StartupKind::I386MsvcStandalone
    );

    let imports = summary.imports.as_ref().unwrap();
    assert_eq!(
        imports.source,
        crate::pipeline::outcome::ImportSource::CrackproofLoader
    );
    assert_eq!((imports.module_count, imports.function_count), (21, 814));
    let artifact = summary.output_artifact.as_ref().unwrap();
    assert_eq!(artifact.size, 9_822_208);
    assert_eq!(
        artifact.sha256.as_deref(),
        Some("100e65c9326cf3de4b0a74eb2dad221cf590af4255088251b328a4d81bb67511")
    );
    assert!(!artifact.written);
    assert_eq!(output.image.len(), artifact.size);
    assert_eq!(observer.terminal_events, 1);
}

#[test]
fn staged_controller_prefilter_cannot_hide_authenticated_payload_blocks() {
    let input = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("packed/chusanApp_2.25.exe");
    let request = PipelineRequest {
        input,
        output: None,
        dry_run: true,
        hash_artifacts: true,
    };
    let mut observer = RecordingObserver::default();
    let cancellation = CancellationToken::default();

    let output = Pipeline::new(&mut observer, &cancellation)
        .run(&request)
        .unwrap();
    let summary = &output.summary;
    let input_artifact = summary.input_artifact.as_ref().unwrap();
    assert_eq!(
        input_artifact.sha256.as_deref(),
        Some("16061383b2bf2dc2773ee8379d16581201d517c347a60706f0c0e104fb800beb")
    );

    let decryption = summary.decryption.as_ref().unwrap();
    assert_eq!(
        decryption.plan_provenance,
        Some(crate::pipeline::outcome::PayloadPlanProvenance::EvidenceSearch)
    );
    assert_eq!(decryption.block_count, 7_485);
    assert_eq!(decryption.copied_block_count, 16);
    assert_eq!(decryption.decoded_block_count, 7_469);
    assert_eq!(decryption.aes_key_candidates, 2);
    assert_eq!(decryption.decoder_candidates, 2);
    assert_eq!(decryption.byte_transform_candidates, 3);
    assert!(decryption.selected_chain.is_some());
    assert!(decryption.selected_staged_controller.is_none());

    let recovered = summary.recovered_program.as_ref().unwrap();
    assert_eq!(recovered.startup_rva, 0x00a2_ce71);
    assert_eq!(recovered.handoff_rva, None);
    assert_eq!(
        recovered.code_transform,
        crate::pipeline::outcome::CodeTransform::PageRvaRol { rotation: 3 }
    );
    assert_eq!(
        recovered.startup_kind,
        crate::pipeline::outcome::StartupKind::I386MsvcStandalone
    );

    let imports = summary.imports.as_ref().unwrap();
    assert_eq!(
        imports.source,
        crate::pipeline::outcome::ImportSource::CrackproofLoader
    );
    assert_eq!((imports.module_count, imports.function_count), (22, 836));
    let artifact = summary.output_artifact.as_ref().unwrap();
    assert_eq!(artifact.size, 32_067_584);
    assert!(!artifact.written);
    assert_eq!(output.image.len(), artifact.size);
    assert_eq!(observer.terminal_events, 1);
}

#[test]
fn malformed_com_descriptor_cannot_select_standard_import_profile() {
    let mut pe = synthetic_pe(0);
    let directory = DataDirectory {
        virtual_address: 0x1000,
        size: 72,
    };
    pe.directories[14] = directory;
    let mut image = vec![0; usize::try_from(pe.size_of_image).unwrap()];
    image[0x1000..0x1004].copy_from_slice(&72u32.to_le_bytes());
    image[0x1008..0x100c].copy_from_slice(&0x1100u32.to_le_bytes());
    image[0x100c..0x1010].copy_from_slice(&16u32.to_le_bytes());
    assert!(validate_clr_directory(&image, &pe, directory).is_err());
}

#[test]
#[ignore = "manual family-fingerprint diagnostic"]
fn dump_detected_family_for_analysis() {
    let input = std::env::var("CRACKPROOF_ANALYSIS_INPUT").unwrap();
    let packed = std::fs::read(input).unwrap();
    let pe = Pe::parse(&packed).unwrap();
    let _family = detect::detect_family(&packed, &pe).unwrap();
}

#[test]
#[ignore = "manual mapped-image diagnostic"]
fn dump_decrypted_image_for_analysis() {
    let input = std::env::var("CRACKPROOF_ANALYSIS_INPUT").unwrap();
    let output = std::env::var("CRACKPROOF_ANALYSIS_MAPPED").unwrap();
    let packed = std::fs::read(&input).unwrap();
    let pe = Pe::parse(&packed).unwrap();
    let family = detect::detect_family(&packed, &pe).unwrap();
    let mut bootstrap = bootstrap::PackedBootstrap::from(&family.descriptor);
    let sidecar = std::fs::read(format!("{input}._")).ok();
    let decrypted = if let Some(sidecar) = sidecar.as_deref() {
        bootstrap.descriptor_file_offset = 0;
        decrypt::decrypt_packed_image_from_source(&packed, &pe, sidecar, bootstrap, None).unwrap()
    } else {
        decrypt::decrypt_packed_image(&packed, &pe, bootstrap).unwrap()
    };
    std::fs::write(output, decrypted.image).unwrap();
}

#[test]
#[ignore = "manual sparse-profile diagnostic"]
fn discover_sparse_profile_for_decrypted_image() {
    let input = std::env::var("CRACKPROOF_ANALYSIS_MAPPED").unwrap();
    let mut mapped = std::fs::read(input).unwrap();
    let pe = Pe::parse_mapped(&mapped).unwrap();
    let mut hits = Vec::new();
    if let Ok(entry) = crate::pipeline::stages::startup::discover_output_entry(&mapped, &pe) {
        hits.push((None, entry));
    }
    for page_key in crate::pipeline::stages::startup::unique_sparse_page_keys(&pe).unwrap() {
        crate::pipeline::stages::startup::decode_sparse_text_pages_in_place(
            &mut mapped,
            &pe,
            page_key,
        )
        .unwrap();
        let result = crate::pipeline::stages::startup::discover_output_entry(&mapped, &pe)
            .and_then(|entry| {
                crate::pipeline::stages::startup::authenticate_sparse_output_entry(
                    &mapped, &pe, entry,
                )?;
                Ok(entry)
            });
        crate::pipeline::stages::startup::decode_sparse_text_pages_in_place(
            &mut mapped,
            &pe,
            page_key,
        )
        .unwrap();
        if let Ok(entry) = result {
            hits.push((Some(page_key), entry));
        }
    }
    assert!(!hits.is_empty());
}

fn section(
    index: usize,
    virtual_address: u32,
    virtual_size: u32,
    raw_pointer: u32,
    raw_size: u32,
    characteristics: u32,
) -> Section {
    Section {
        index,
        header_offset: 0,
        name_bytes: [0; 8],
        virtual_size,
        virtual_address,
        raw_size,
        raw_pointer,
        characteristics,
    }
}

fn synthetic_pe(shift: u32) -> Pe {
    let sections = vec![
        section(
            0,
            shift + 0x1000,
            0x800,
            0x400,
            0x800,
            IMAGE_SCN_MEM_EXECUTE,
        ),
        section(1, shift + 0x4000, 0x1800, 0xc00, 0x400, 0x4000_0040),
    ];
    Pe {
        opt: 0,
        machine: Machine::I386,
        coff_characteristics: 0,
        section_count: sections.len(),
        entry_rva: shift + 0x1100,
        image_base: 0x10000,
        section_alignment: 0x1000,
        file_alignment: 0x200,
        size_of_image: shift + 0x6000,
        size_of_headers: 0x400,
        checksum_offset: 0,
        data_directory_table_offset: 0,
        directories: vec![
            DataDirectory {
                virtual_address: 0,
                size: 0,
            };
            16
        ],
        sections,
        file_len: 0x2000,
    }
}

fn encrypted_descriptor(shift: u32) -> [u32; KONN_WORD_COUNT] {
    encode_konn_words([
        0x1357_9bdf,
        KONN_MAGIC,
        shift + 0x1100,
        shift + 0x4500,
        0x80,
        0x180,
        shift + 0x1600,
        7,
    ])
}

fn place_words(data: &mut [u8], offset: usize, words: [u32; KONN_WORD_COUNT]) {
    for (index, word) in words.into_iter().enumerate() {
        let start = offset + index * size_of::<u32>();
        data[start..start + size_of::<u32>()].copy_from_slice(&word.to_le_bytes());
    }
}

#[test]
fn decodes_an_independent_vector_from_a_backed_descriptor_source() {
    let decoded = [
        0x2468_ace0,
        KONN_MAGIC,
        0x7100,
        0xa500,
        0x80,
        0x180,
        0x7600,
        7,
    ];
    let encrypted = [
        0x2468_ace0,
        0x6a26_e3ab,
        0x8e8f_e18b,
        0x1d1f_d714,
        0x3a3f_49a2,
        0x747e_9348,
        0xe8fd_501c,
        0xd1fa_762d,
    ];
    assert_eq!(decode_konn_words(encrypted), decoded);

    let pe = synthetic_pe(0x6000);
    let mut packed = vec![0; pe.file_len];
    place_words(&mut packed, 0, encrypted);
    let found = scan_konn_descriptors(&packed, &pe).expect("valid synthetic scan");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].file_offset, 0);
}

#[test]
fn descriptor_source_offset_is_an_independent_byte_offset() {
    let pe = synthetic_pe(0x3000);
    let mut packed = vec![0; pe.file_len];
    let mut decoded = decode_konn_words(encrypted_descriptor(0x3000));
    decoded[4] = 0x401;
    decoded[5] = 0x180;
    place_words(&mut packed, 0x100, encode_konn_words(decoded));

    let found = scan_konn_descriptors(&packed, &pe).expect("bounded descriptor source");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].file_offset, 0x100);
    assert_eq!(found[0].source_offset, 0x401);
    assert_eq!(found[0].length, 0x180);
}

#[test]
fn descriptor_key_and_unused_tail_word_are_unrestricted() {
    let pe = synthetic_pe(0x3000);
    let mut packed = vec![0; pe.file_len];
    let mut decoded = decode_konn_words(encrypted_descriptor(0x3000));
    decoded[0] = 0;
    decoded[7] = u32::MAX;
    place_words(&mut packed, 0x100, encode_konn_words(decoded));

    let found = scan_konn_descriptors(&packed, &pe).expect("zero-key descriptor");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].key, 0);
}

#[test]
fn descriptor_prefix_marker_need_not_cover_the_source_length() {
    let pe = synthetic_pe(0x3000);
    let mut packed = vec![0; pe.file_len];
    let mut decoded = decode_konn_words(encrypted_descriptor(0x3000));
    decoded[6] = 0x3000 + 0x5700;
    place_words(&mut packed, 0x100, encode_konn_words(decoded));

    let found = scan_konn_descriptors(&packed, &pe).expect("bounded prefix marker");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].source_rva, 0x3000 + 0x5700);
}

#[test]
fn descriptor_destination_may_cross_an_image_gap() {
    let shift = 0x3000;
    let pe = synthetic_pe(shift);
    let mut packed = vec![0; pe.file_len];
    let mut decoded = decode_konn_words(encrypted_descriptor(shift));
    decoded[3] = shift + 0x3f80;
    decoded[5] = 0x180;
    place_words(&mut packed, 0x100, encode_konn_words(decoded));

    let found = scan_konn_descriptors(&packed, &pe).expect("bounded cross-section destination");
    assert_eq!(
        found
            .iter()
            .map(|descriptor| (descriptor.file_offset, descriptor.destination_section_index))
            .collect::<Vec<_>>(),
        [(0x100, 1)]
    );
}

#[test]
fn shifted_unaligned_descriptors_are_found_and_decoys_rejected() {
    for (shift, offset) in [(0x2000, 19usize), (0x9000, 57usize)] {
        let pe = synthetic_pe(shift);
        let mut packed = vec![0xa5; pe.file_len];
        place_words(&mut packed, offset, encrypted_descriptor(shift));

        let mut entry_mismatch = encrypted_descriptor(shift);
        let mut decoded = decode_konn_words(entry_mismatch);
        decoded[2] = shift + 0x1200;
        entry_mismatch = encode_konn_words(decoded);
        place_words(&mut packed, offset + 101, entry_mismatch);

        let mut destination_outside_image = decode_konn_words(encrypted_descriptor(shift));
        destination_outside_image[3] = shift + 0x5f00;
        destination_outside_image[5] = 0x200;
        place_words(
            &mut packed,
            offset + 202,
            encode_konn_words(destination_outside_image),
        );

        let mut null_source = decode_konn_words(encrypted_descriptor(shift));
        null_source[6] = 0;
        place_words(&mut packed, offset + 303, encode_konn_words(null_source));

        let mut impossible_source_offset = decode_konn_words(encrypted_descriptor(shift));
        impossible_source_offset[4] = u32::MAX;
        place_words(
            &mut packed,
            offset + 404,
            encode_konn_words(impossible_source_offset),
        );

        let mut overflowing_source = decode_konn_words(encrypted_descriptor(shift));
        overflowing_source[6] = u32::MAX - 0x40;
        place_words(
            &mut packed,
            offset + 505,
            encode_konn_words(overflowing_source),
        );

        let mut source_outside_image = decode_konn_words(encrypted_descriptor(shift));
        source_outside_image[6] = shift + 0x5900;
        place_words(
            &mut packed,
            offset + 606,
            encode_konn_words(source_outside_image),
        );

        let mut unaligned_length = decode_konn_words(encrypted_descriptor(shift));
        unaligned_length[5] += 1;
        place_words(
            &mut packed,
            offset + 808,
            encode_konn_words(unaligned_length),
        );

        let found = scan_konn_descriptors(&packed, &pe).expect("bounded synthetic scan");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].file_offset, offset);
        assert_eq!(found[0].destination_section_index, 1);
    }
}

#[test]
fn descriptor_discovery_allows_internal_gaps_and_rejects_overlay_or_security() {
    let pe = synthetic_pe(0x3000);

    let mut raw_backed = vec![0; pe.file_len];
    place_words(&mut raw_backed, 0x420, encrypted_descriptor(0x3000));
    let found = scan_konn_descriptors(&raw_backed, &pe).expect("raw-backed scan");
    assert_eq!(
        found
            .iter()
            .map(|item| item.file_offset)
            .collect::<Vec<_>>(),
        [0x420]
    );

    let mut gap_pe = pe.clone();
    gap_pe.sections[0].raw_pointer = 0x800;
    gap_pe.sections[1].raw_pointer = 0x1000;
    let mut presection_gap = vec![0; gap_pe.file_len];
    place_words(&mut presection_gap, 0x500, encrypted_descriptor(0x3000));
    assert_eq!(
        scan_konn_descriptors(&presection_gap, &gap_pe)
            .expect("pre-section gap scan")
            .iter()
            .map(|item| item.file_offset)
            .collect::<Vec<_>>(),
        [0x500]
    );

    let mut boundary_crossing_descriptor = vec![0; pe.file_len];
    place_words(
        &mut boundary_crossing_descriptor,
        0x3f0,
        encrypted_descriptor(0x3000),
    );
    assert_eq!(
        scan_konn_descriptors(&boundary_crossing_descriptor, &pe)
            .expect("body-boundary descriptor scan")
            .len(),
        1
    );

    let mut boundary_crossing_source = vec![0; pe.file_len];
    place_words(
        &mut boundary_crossing_source,
        0x240,
        encrypted_descriptor(0x3000),
    );
    assert_eq!(
        scan_konn_descriptors(&boundary_crossing_source, &pe)
            .expect("body-boundary source scan")
            .len(),
        1
    );

    let mut overlay = vec![0; pe.file_len + 0x400];
    place_words(
        &mut overlay,
        pe.file_len + 0x20,
        encrypted_descriptor(0x3000),
    );
    assert!(
        scan_konn_descriptors(&overlay, &pe)
            .expect("overlay scan")
            .is_empty()
    );

    let mut security_descriptor = vec![0; pe.file_len];
    place_words(&mut security_descriptor, 0x20, encrypted_descriptor(0x3000));
    let mut security_pe = pe.clone();
    security_pe.directories[IMAGE_DIRECTORY_ENTRY_SECURITY] = DataDirectory {
        virtual_address: 0x20,
        size: 1,
    };
    assert!(
        scan_konn_descriptors(&security_descriptor, &security_pe)
            .expect("Security descriptor scan")
            .is_empty()
    );

    security_pe.directories[IMAGE_DIRECTORY_ENTRY_SECURITY] = DataDirectory {
        virtual_address: 0x100,
        size: 0x20,
    };
    assert!(
        scan_konn_descriptors(&security_descriptor, &security_pe)
            .expect("Security source scan")
            .is_empty()
    );

    security_pe.directories[IMAGE_DIRECTORY_ENTRY_SECURITY] = DataDirectory {
        virtual_address: 0x220,
        size: 0x20,
    };
    assert_eq!(
        scan_konn_descriptors(&security_descriptor, &security_pe)
            .expect("adjacent Security scan")
            .len(),
        1
    );
}

#[test]
fn descriptor_detection_requires_one_backed_match_without_aes_prescan() {
    let pe = synthetic_pe(0x3000);
    let mut packed = vec![0; pe.file_len];
    place_words(&mut packed, 0x20, encrypted_descriptor(0x3000));
    assert!(detect_family(&packed, &pe).is_ok());

    place_words(&mut packed, 0x80, encrypted_descriptor(0x3000));
    place_words(&mut packed, 0xe0, encrypted_descriptor(0x3000));
    let descriptors = scan_konn_descriptors(&packed, &pe).expect("capped descriptor scan");
    assert_eq!(descriptors.len(), MAX_KONN_MATCHES);
    assert!(combine_family_evidence(descriptors).is_err());
}

#[test]
fn descriptor_scan_caps_prefiltered_candidate_work() {
    let mut candidates = MAX_KONN_CANDIDATES - 1;
    reserve_konn_candidate(&mut candidates).expect("candidate work at limit");
    assert_eq!(candidates, MAX_KONN_CANDIDATES);
    assert!(reserve_konn_candidate(&mut candidates).is_err());
}

#[test]
fn descriptor_scan_caps_body_offsets_before_magic_prefilter() {
    ensure_konn_scan_body_bound(MAX_KONN_SCAN_BODY_BYTES)
        .expect("body scan work at the cap is accepted");
    let error = ensure_konn_scan_body_bound(MAX_KONN_SCAN_BODY_BYTES + 1)
        .expect_err("body scan work above the cap is rejected");
    assert!(
        error.to_string().contains("packed-body bytes"),
        "unexpected body-scan error: {error:#}"
    );
}

use super::*;

#[test]
fn referenced_output_scalars_precede_exhaustive_output_words() {
    let bootstrap = PackedBootstrap {
        descriptor_file_offset: 0,
        key: 0,
        destination_rva: 0x1000,
        source_offset: 0,
        length: 0x100,
        source_rva: 0,
    };
    let stage_range = 0..0x40;
    let output_range = 0x80..0xc0;
    let mut staged_outer = vec![0u8; 0x100];

    // The scalar offset is deliberately unaligned in the stage metadata. The
    // encoded offset itself is dword-aligned relative to the output context.
    staged_outer[3..7].copy_from_slice(&8u32.to_le_bytes());
    let unreferenced = 0xf1f2_f3f4u32;
    staged_outer[output_range.start..output_range.start + 4]
        .copy_from_slice(&unreferenced.to_le_bytes());
    let referenced = 0xa1a2_a3a4u32;
    staged_outer[output_range.start + 8..output_range.start + 12]
        .copy_from_slice(&referenced.to_le_bytes());

    let candidates = nested_scalar_candidates(
        &staged_outer,
        bootstrap,
        stage_range,
        &[],
        std::slice::from_ref(&output_range),
        true,
        0,
        true,
    )
    .unwrap();
    let direct = &candidates.values[..candidates.direct_len];
    let exhaustive = &candidates.values[candidates.direct_len..];

    assert!(direct.contains(&referenced));
    assert!(!direct.contains(&unreferenced));
    assert!(exhaustive.contains(&unreferenced));
}

struct CompleteCandidateReplayer {
    calls: usize,
}

impl NestedRecordReplayer for CompleteCandidateReplayer {
    fn begin_graph(&mut self, _extended_profile: bool) -> Result<()> {
        Ok(())
    }

    fn replay(
        &mut self,
        _staged_outer: &[u8],
        _bootstrap: PackedBootstrap,
        _record: &NestedRecord,
        keys: &[u32],
        _byte_maps: &[(usize, Box<[u8; 256]>)],
    ) -> Result<NestedReplay> {
        self.calls += 1;
        if keys == [1, 2] {
            Ok(NestedReplay::Unique(vec![0], 2))
        } else {
            Ok(NestedReplay::Ambiguous)
        }
    }
}

#[test]
fn direct_and_speculative_keys_are_validated_together() {
    let bootstrap = PackedBootstrap {
        descriptor_file_offset: 0,
        key: 0,
        destination_rva: 0,
        source_offset: 0,
        length: 0,
        source_rva: 0,
    };
    let record = NestedRecord {
        descriptor_offset: 0,
        source_rva: 0,
        encoded_length: 1,
        destination_rva: 0,
        destination_length: 2,
    };
    let mut replayer = CompleteCandidateReplayer { calls: 0 };

    let result = replay_nested_keys(
        &mut replayer,
        &[],
        bootstrap,
        &record,
        &[1, 2],
        1,
        &[],
        true,
    )
    .unwrap();

    assert_eq!(result, NestedReplay::Unique(vec![0], 2));
    assert_eq!(replayer.calls, 2);
}

#[test]
fn legacy_profile_keeps_direct_ambiguity_terminal() {
    let bootstrap = PackedBootstrap {
        descriptor_file_offset: 0,
        key: 0,
        destination_rva: 0,
        source_offset: 0,
        length: 0,
        source_rva: 0,
    };
    let record = NestedRecord {
        descriptor_offset: 0,
        source_rva: 0,
        encoded_length: 1,
        destination_rva: 0,
        destination_length: 2,
    };
    let mut replayer = CompleteCandidateReplayer { calls: 0 };

    let result = replay_nested_keys(
        &mut replayer,
        &[],
        bootstrap,
        &record,
        &[1, 2],
        1,
        &[],
        false,
    )
    .unwrap();

    assert_eq!(result, NestedReplay::Ambiguous);
    assert_eq!(replayer.calls, 1);
}

struct UnstructuredFallbackReplayer {
    calls: usize,
}

impl NestedRecordReplayer for UnstructuredFallbackReplayer {
    fn begin_graph(&mut self, _extended_profile: bool) -> Result<()> {
        Ok(())
    }

    fn replay(
        &mut self,
        _staged_outer: &[u8],
        _bootstrap: PackedBootstrap,
        _record: &NestedRecord,
        keys: &[u32],
        _byte_maps: &[(usize, Box<[u8; 256]>)],
    ) -> Result<NestedReplay> {
        self.calls += 1;
        if keys == [1] {
            Ok(NestedReplay::Unique(vec![1], 1))
        } else {
            Ok(NestedReplay::Ambiguous)
        }
    }
}

#[test]
fn unique_reference_rooted_output_avoids_speculative_replay() {
    let bootstrap = PackedBootstrap {
        descriptor_file_offset: 0,
        key: 0,
        destination_rva: 0,
        source_offset: 0,
        length: 0,
        source_rva: 0,
    };
    let record = NestedRecord {
        descriptor_offset: 0,
        source_rva: 0,
        encoded_length: 1,
        destination_rva: 0,
        destination_length: 2,
    };
    let mut replayer = UnstructuredFallbackReplayer { calls: 0 };

    let result = replay_nested_keys(
        &mut replayer,
        &[],
        bootstrap,
        &record,
        &[1, 2],
        1,
        &[],
        true,
    )
    .unwrap();

    assert_eq!(result, NestedReplay::Unique(vec![1], 1));
    assert_eq!(replayer.calls, 1);
}

#[test]
fn nested_map_graph_completes_after_two_nonempty_generations() {
    let original = Box::new([0x11; 256]);
    let first = Box::new([0x22; 256]);
    let second = Box::new([0x33; 256]);
    let mut maps = vec![(1, original)];
    let mut generations = 0;

    assert!(!commit_nested_output_maps(
        &mut maps,
        Vec::new(),
        &mut generations
    ));
    assert_eq!(generations, 0);
    assert_eq!(maps[0].1.as_ref(), &[0x11; 256]);

    assert!(!commit_nested_output_maps(
        &mut maps,
        vec![(2, first)],
        &mut generations
    ));
    assert_eq!(generations, 1);
    assert_eq!(maps[0].0, 2);
    assert_eq!(maps[0].1.as_ref(), &[0x22; 256]);

    assert!(commit_nested_output_maps(
        &mut maps,
        vec![(3, second)],
        &mut generations
    ));
    assert_eq!(generations, 2);
    assert_eq!(maps[0].0, 3);
    assert_eq!(maps[0].1.as_ref(), &[0x33; 256]);
}

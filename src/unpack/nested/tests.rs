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
    )
    .unwrap();
    let direct = &candidates.values[..candidates.direct_len];
    let exhaustive = &candidates.values[candidates.direct_len..];

    assert!(direct.contains(&referenced));
    assert!(!direct.contains(&unreferenced));
    assert!(exhaustive.contains(&unreferenced));
}

struct AmbiguousDirectReplayer {
    calls: usize,
}

impl NestedRecordReplayer for AmbiguousDirectReplayer {
    fn begin_graph(&mut self) -> Result<()> {
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
            Ok(NestedReplay::Ambiguous)
        } else {
            Ok(NestedReplay::Unique(vec![0], 2))
        }
    }
}

#[test]
fn ambiguous_direct_keys_do_not_fall_through_to_speculative_keys() {
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
    let mut replayer = AmbiguousDirectReplayer { calls: 0 };

    let result =
        replay_nested_key_tiers(&mut replayer, &[], bootstrap, &record, &[1, 2], 1, &[]).unwrap();

    assert_eq!(result, NestedReplay::Ambiguous);
    assert_eq!(replayer.calls, 1);
}

use super::model::{
    MAX_MAPPABLE_IMAGE_SIZE, MAX_PE_SECTIONS, PE32_PLUS_OPTIONAL_HEADER_MAGIC, SECTION_HEADER_SIZE,
};
use super::{
    DataDirectory, IMAGE_DIRECTORY_ENTRY_SECURITY, IMAGE_FILE_DLL, IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_I386, Machine, Pe, PeKind, PointerWidth, align_up, pe_checksum, read_u32,
    read_u64, write_u32, write_u64,
};

fn fixture(identity: bool) -> Vec<u8> {
    let file_alignment: u32 = if identity { 0x1000 } else { 0x200 };
    let header_size = file_alignment;
    let first_raw: u32 = if identity { 0x1000 } else { 0x200 };
    let second_raw: u32 = if identity { 0x2000 } else { 0x400 };
    let raw_size = file_alignment;
    let file_len = usize::try_from(second_raw + raw_size + 0x20).unwrap();
    let mut data = vec![0u8; file_len];
    data[..2].copy_from_slice(b"MZ");
    data[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    data[0x80..0x84].copy_from_slice(b"PE\0\0");
    let coff = 0x84;
    data[coff..coff + 2].copy_from_slice(&IMAGE_FILE_MACHINE_I386.to_le_bytes());
    data[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
    data[coff + 16..coff + 18].copy_from_slice(&0xe0u16.to_le_bytes());
    data[coff + 18..coff + 20].copy_from_slice(&0x0102u16.to_le_bytes());
    let opt = 0x98;
    data[opt..opt + 2].copy_from_slice(&0x010bu16.to_le_bytes());
    data[opt + 16..opt + 20].copy_from_slice(&0x1010u32.to_le_bytes());
    data[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
    data[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    data[opt + 36..opt + 40].copy_from_slice(&file_alignment.to_le_bytes());
    data[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes());
    data[opt + 60..opt + 64].copy_from_slice(&header_size.to_le_bytes());
    data[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes());
    data[opt + 96 + 8..opt + 100 + 8].copy_from_slice(&0x2020u32.to_le_bytes());
    data[opt + 100 + 8..opt + 104 + 8].copy_from_slice(&0x10u32.to_le_bytes());
    let security = opt + 96 + IMAGE_DIRECTORY_ENTRY_SECURITY * 8;
    data[security..security + 4].copy_from_slice(&(second_raw + raw_size).to_le_bytes());
    data[security + 4..security + 8].copy_from_slice(&0x20u32.to_le_bytes());

    let section_table = opt + 0xe0;
    data[section_table..section_table + 8].copy_from_slice(b".text\0\0\0");
    data[section_table + 8..section_table + 12].copy_from_slice(&0x180u32.to_le_bytes());
    data[section_table + 12..section_table + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    data[section_table + 16..section_table + 20].copy_from_slice(&raw_size.to_le_bytes());
    data[section_table + 20..section_table + 24].copy_from_slice(&first_raw.to_le_bytes());
    data[section_table + 36..section_table + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    let second = section_table + SECTION_HEADER_SIZE;
    data[second..second + 8].copy_from_slice(b".data\0\0\0");
    data[second + 8..second + 12].copy_from_slice(&0x100u32.to_le_bytes());
    data[second + 12..second + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    data[second + 16..second + 20].copy_from_slice(&raw_size.to_le_bytes());
    data[second + 20..second + 24].copy_from_slice(&second_raw.to_le_bytes());
    data[second + 36..second + 40].copy_from_slice(&0xc000_0040u32.to_le_bytes());

    data[usize::try_from(first_raw).unwrap()] = 0x5a;
    data[usize::try_from(second_raw + 0x20).unwrap()] = 0xa5;
    data
}

fn pe32_plus_fixture() -> Vec<u8> {
    let file_alignment = 0x200u32;
    let first_raw = 0x200u32;
    let second_raw = 0x400u32;
    let raw_size = 0x200u32;
    let mut data = vec![0u8; usize::try_from(second_raw + raw_size + 0x20).unwrap()];
    data[..2].copy_from_slice(b"MZ");
    data[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    data[0x80..0x84].copy_from_slice(b"PE\0\0");
    let coff = 0x84;
    data[coff..coff + 2].copy_from_slice(&IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
    data[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
    data[coff + 16..coff + 18].copy_from_slice(&0xf0u16.to_le_bytes());
    data[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes());
    let opt = 0x98;
    data[opt..opt + 2].copy_from_slice(&PE32_PLUS_OPTIONAL_HEADER_MAGIC.to_le_bytes());
    data[opt + 16..opt + 20].copy_from_slice(&0x1010u32.to_le_bytes());
    data[opt + 24..opt + 32].copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes());
    data[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    data[opt + 36..opt + 40].copy_from_slice(&file_alignment.to_le_bytes());
    data[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes());
    data[opt + 60..opt + 64].copy_from_slice(&file_alignment.to_le_bytes());
    data[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
    data[opt + 112 + 8..opt + 112 + 12].copy_from_slice(&0x2020u32.to_le_bytes());
    data[opt + 112 + 12..opt + 112 + 16].copy_from_slice(&0x10u32.to_le_bytes());
    let security = opt + 112 + IMAGE_DIRECTORY_ENTRY_SECURITY * 8;
    data[security..security + 4].copy_from_slice(&(second_raw + raw_size).to_le_bytes());
    data[security + 4..security + 8].copy_from_slice(&0x20u32.to_le_bytes());

    let section_table = opt + 0xf0;
    data[section_table..section_table + 8].copy_from_slice(b".text\0\0\0");
    data[section_table + 8..section_table + 12].copy_from_slice(&0x180u32.to_le_bytes());
    data[section_table + 12..section_table + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    data[section_table + 16..section_table + 20].copy_from_slice(&raw_size.to_le_bytes());
    data[section_table + 20..section_table + 24].copy_from_slice(&first_raw.to_le_bytes());
    data[section_table + 36..section_table + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    let second = section_table + SECTION_HEADER_SIZE;
    data[second..second + 8].copy_from_slice(b".data\0\0\0");
    data[second + 8..second + 12].copy_from_slice(&0x100u32.to_le_bytes());
    data[second + 12..second + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    data[second + 16..second + 20].copy_from_slice(&raw_size.to_le_bytes());
    data[second + 20..second + 24].copy_from_slice(&second_raw.to_le_bytes());
    data[second + 36..second + 40].copy_from_slice(&0xc000_0040u32.to_le_bytes());

    data[usize::try_from(first_raw).unwrap()] = 0x5a;
    data[usize::try_from(second_raw + 0x20).unwrap()] = 0xa5;
    data
}

#[test]
fn parses_pe32_plus_with_nonidentity_sections_and_wide_addresses() {
    let mut data = pe32_plus_fixture();
    let pe = Pe::parse(&data).unwrap();

    assert_eq!(pe.kind(), PeKind::Pe32Plus);
    assert_eq!(pe.machine_kind(), Machine::Amd64);
    assert_eq!(pe.machine.raw(), IMAGE_FILE_MACHINE_AMD64);
    assert_eq!(pe.pointer_width(), PointerWidth::U64);
    assert_eq!(pe.pointer_width().bytes(), 8);
    assert_eq!(pe.image_base, 0x0000_0001_4000_0000);
    assert_eq!(pe.fixed_optional_header_size(), 0x70);
    assert_eq!(pe.image_base_offset(), 0x98 + 24);
    assert_eq!(pe.number_of_rva_and_sizes_offset(), 0x98 + 108);
    assert_eq!(pe.data_directory_table_offset, 0x98 + 112);
    assert_eq!(pe.sections[0].header_offset, 0x98 + 0xf0);
    assert_eq!(pe.data_directory_offset(1).unwrap(), 0x98 + 112 + 8);
    assert_eq!(pe.entry_rva_offset(), 0x98 + 16);
    assert_eq!(pe.size_of_code_offset(), 0x98 + 4);
    assert_eq!(pe.size_of_initialized_data_offset(), 0x98 + 8);
    assert_eq!(pe.size_of_uninitialized_data_offset(), 0x98 + 12);
    assert_eq!(pe.size_of_image_offset(), 0x98 + 56);
    assert_eq!(pe.dll_characteristics_offset(), 0x98 + 70);

    assert_eq!(pe.rva_to_file_offset(0x1010).unwrap(), 0x210);
    assert_eq!(pe.rva_to_file_offset(0x2020).unwrap(), 0x420);
    assert_eq!(pe.rva_to_va(0x2020).unwrap(), 0x0000_0001_4000_2020);
    assert_eq!(pe.va_to_rva(0x0000_0001_4000_2020).unwrap(), 0x2020);
    assert_eq!(
        pe.security_directory_file_range(data.len()).unwrap(),
        Some(0x600..0x620)
    );

    let pointer_offset = 0x218;
    let pointer = 0x0000_0001_4000_2020;
    pe.write_pointer(&mut data, pointer_offset, pointer)
        .unwrap();
    assert_eq!(read_u64(&data, pointer_offset).unwrap(), pointer);
    assert_eq!(pe.read_pointer(&data, pointer_offset).unwrap(), pointer);

    let image = pe.map_image(&data).unwrap();
    assert_eq!(image[0x1000], 0x5a);
    assert_eq!(image[0x2020], 0xa5);
    assert_eq!(&image[0x1018..0x1020], &pointer.to_le_bytes());
}

#[test]
fn rejects_pe32_plus_mismatches_and_address_overflow() {
    let mut mismatched_machine = pe32_plus_fixture();
    mismatched_machine[0x84..0x86].copy_from_slice(&IMAGE_FILE_MACHINE_I386.to_le_bytes());
    let error = Pe::parse(&mismatched_machine).unwrap_err().to_string();
    assert!(error.contains("does not match"), "{error}");

    let mut undersized_optional_header = pe32_plus_fixture();
    undersized_optional_header[0x84 + 16..0x84 + 18].copy_from_slice(&0x60u16.to_le_bytes());
    let error = Pe::parse(&undersized_optional_header)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("Pe32Plus optional header") && error.contains("0x60"),
        "{error}"
    );

    let mut unsupported_magic = pe32_plus_fixture();
    unsupported_magic[0x98..0x9a].copy_from_slice(&0x0107u16.to_le_bytes());
    let error = Pe::parse(&unsupported_magic).unwrap_err().to_string();
    assert!(
        error.contains("unsupported optional-header magic"),
        "{error}"
    );

    let mut misaligned_image_base = pe32_plus_fixture();
    misaligned_image_base[0x98 + 24..0x98 + 32]
        .copy_from_slice(&0x0000_0001_4000_0001u64.to_le_bytes());
    let error = Pe::parse(&misaligned_image_base).unwrap_err().to_string();
    assert!(
        error.contains("ImageBase") && error.contains("aligned"),
        "{error}"
    );

    let pe = Pe::parse(&pe32_plus_fixture()).unwrap();
    assert!(pe.va_to_rva(pe.image_base - 1).is_err());
    assert!(pe.va_to_rva(pe.image_base + 0x1_0000_0000).is_err());

    let mut overflowing_image_base = pe32_plus_fixture();
    overflowing_image_base[0x98 + 24..0x98 + 32]
        .copy_from_slice(&0xffff_ffff_ffff_0000u64.to_le_bytes());
    let pe = Pe::parse(&overflowing_image_base).unwrap();
    assert!(pe.rva_to_va(u32::MAX).is_err());
}

#[test]
fn maps_nonidentity_rvas_in_both_directions() {
    let data = fixture(false);
    let pe = Pe::parse(&data).unwrap();
    assert_eq!(pe.kind(), PeKind::Pe32);
    assert_eq!(pe.machine_kind(), Machine::I386);
    assert_eq!(pe.pointer_width(), PointerWidth::U32);
    assert_eq!(pe.image_base, 0x0040_0000);
    let mut pointer_cell = [0u8; 8];
    pe.write_pointer(&mut pointer_cell, 0, 0x0040_2020).unwrap();
    assert_eq!(pe.read_pointer(&pointer_cell, 0).unwrap(), 0x0040_2020);
    assert_eq!(&pointer_cell[4..], &[0; 4]);
    assert!(
        pe.write_pointer(&mut pointer_cell, 0, 0x1_0000_0000)
            .is_err()
    );
    assert_eq!(pe.rva_to_file_offset(0x1010).unwrap(), 0x210);
    assert_eq!(pe.rva_to_file_offset(0x2020).unwrap(), 0x420);
    assert_eq!(pe.rva_to_file_offset(0x100).unwrap(), 0x100);
    assert_eq!(pe.directory(1).unwrap().virtual_address, 0x2020);
    assert!(pe.rva_to_file_offset(0x2200).is_err());
    assert_eq!(
        pe.security_directory_file_range(data.len()).unwrap(),
        Some(0x600..0x620)
    );
    assert!(pe.rva_to_file_offset(0x600).is_err());

    let image = pe.map_image(&data).unwrap();
    assert_eq!(image.len(), 0x3000);
    assert_eq!(image[0x1000], 0x5a);
    assert_eq!(image[0x2020], 0xa5);
}

#[test]
fn parses_mapped_image_when_disk_raw_data_lies_beyond_size_of_image() {
    let mut disk = fixture(false);
    let section_table = 0x98 + 0xe0;
    let text_raw = 0x0010_0000u32;
    let data_raw = 0x0010_1000u32;
    disk.resize(usize::try_from(data_raw + 0x220).unwrap(), 0);
    disk[section_table + 20..section_table + 24].copy_from_slice(&text_raw.to_le_bytes());
    disk[section_table + SECTION_HEADER_SIZE + 20..section_table + SECTION_HEADER_SIZE + 24]
        .copy_from_slice(&data_raw.to_le_bytes());
    disk[usize::try_from(text_raw).unwrap()] = 0x5a;
    disk[usize::try_from(data_raw + 0x20).unwrap()] = 0xa5;

    let disk_pe = Pe::parse(&disk).unwrap();
    let image = disk_pe.map_image(&disk).unwrap();
    assert_eq!(image[0x1000], 0x5a);
    assert_eq!(image[0x2020], 0xa5);

    let mapped_pe = Pe::parse_mapped(&image).unwrap();
    assert_eq!(mapped_pe.sections[0].raw_pointer, text_raw);
    assert_eq!(mapped_pe.sections[1].raw_pointer, data_raw);

    let error = Pe::parse(&image).unwrap_err().to_string();
    assert!(error.contains("raw range") && error.contains("exceeds input length"));

    let error = Pe::parse_mapped(&image[..image.len() - 1])
        .unwrap_err()
        .to_string();
    assert!(error.contains("smaller than SizeOfImage"), "{error}");

    let mut malformed = image;
    malformed[section_table + 8..section_table + 12].copy_from_slice(&0x3000u32.to_le_bytes());
    let error = Pe::parse_mapped(&malformed).unwrap_err().to_string();
    assert!(error.contains("shadows section"), "{error}");
}

#[test]
fn maps_identity_layout_without_special_cases() {
    let data = fixture(true);
    let pe = Pe::parse(&data).unwrap();
    assert_eq!(pe.rva_to_file_offset(0x2020).unwrap(), 0x2020);
    let image = pe.map_image(&data).unwrap();
    assert_eq!(image[0x1000], data[0x1000]);
    assert_eq!(image[0x2020], data[0x2020]);
}

#[test]
fn rejects_section_counts_above_the_windows_image_limit() {
    let mut malformed = fixture(false);
    malformed[0x84 + 2..0x84 + 4]
        .copy_from_slice(&u16::try_from(MAX_PE_SECTIONS + 1).unwrap().to_le_bytes());
    let error = Pe::parse(&malformed).unwrap_err().to_string();
    assert!(error.contains("section count 97"), "{error}");
    assert!(error.contains("Windows image limit 96"), "{error}");
}

#[test]
fn rejects_oversized_size_of_image_before_mapping() {
    let oversized = MAX_MAPPABLE_IMAGE_SIZE + 0x1000;

    let mut malformed = fixture(false);
    malformed[0x98 + 56..0x98 + 60].copy_from_slice(&oversized.to_le_bytes());
    let parse_result = std::panic::catch_unwind(|| Pe::parse(&malformed));
    let parse_error = parse_result
        .expect("oversized SizeOfImage must return an error instead of panicking")
        .unwrap_err();
    let parse_error = parse_error.to_string();
    assert!(
        parse_error.contains("maximum mappable image size"),
        "{parse_error}"
    );

    let data = fixture(false);
    let mut pe = Pe::parse(&data).unwrap();
    pe.size_of_image = oversized;
    let map_result = std::panic::catch_unwind(|| pe.map_image(&data));
    let map_error = map_result
        .expect("oversized SizeOfImage must fail before allocation")
        .unwrap_err();
    let map_error = map_error.to_string();
    assert!(
        map_error.contains("maximum mappable image size"),
        "{map_error}"
    );
}

#[test]
fn honors_the_declared_directory_count() {
    let mut data = fixture(false);
    data[0x98 + 92..0x98 + 96].copy_from_slice(&2u32.to_le_bytes());
    let pe = Pe::parse(&data).unwrap();
    assert_eq!(pe.directories.len(), 2);
    assert!(pe.directory(2).is_err());
    assert!(pe.data_directory_offset(2).is_err());
}

#[test]
fn rejects_section_headers_out_of_rva_order() {
    let mut malformed = fixture(false);
    let second_header = 0x98 + 0xe0 + SECTION_HEADER_SIZE;
    malformed[second_header + 12..second_header + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    let error = Pe::parse(&malformed).unwrap_err().to_string();
    assert!(
        error.contains("section RVAs are not strictly increasing"),
        "{error}"
    );
}

#[test]
fn rejects_zero_span_section_headers_shadowing_a_mapped_owner() {
    let mut malformed = fixture(false);
    let section_table = 0x98 + 0xe0;
    malformed[section_table + 8..section_table + 12].copy_from_slice(&0x2000u32.to_le_bytes());
    let second_header = section_table + SECTION_HEADER_SIZE;
    malformed[second_header + 8..second_header + 12].copy_from_slice(&0u32.to_le_bytes());
    malformed[second_header + 16..second_header + 24].copy_from_slice(&[0u8; 8]);
    let error = Pe::parse(&malformed).unwrap_err().to_string();
    assert!(error.contains("shadows section"), "{error}");
}

#[test]
fn rejects_malformed_bounds_and_overlaps() {
    let mut truncated = fixture(false);
    truncated.truncate(0x500);
    let error = Pe::parse(&truncated).unwrap_err().to_string();
    assert!(error.contains("exceeds input length"), "{error}");

    let mut overlapping = fixture(false);
    let second_header = 0x98 + 0xe0 + SECTION_HEADER_SIZE;
    overlapping[second_header + 20..second_header + 24].copy_from_slice(&0x200u32.to_le_bytes());
    let error = Pe::parse(&overlapping).unwrap_err().to_string();
    assert!(
        error.contains("raw range") && error.contains("overlaps"),
        "{error}"
    );

    let partial = DataDirectory {
        virtual_address: 0x1000,
        size: 0,
    };
    assert!(partial.checked_rva_range().is_err());
    let overflowing = DataDirectory {
        virtual_address: u32::MAX - 1,
        size: 4,
    };
    assert!(overflowing.checked_rva_range().is_err());

    assert!(read_u32(&[0; 3], 0).is_err());
    assert!(write_u32(&mut [0; 3], 0, 1).is_err());
    assert!(read_u64(&[0; 7], 0).is_err());
    assert!(write_u64(&mut [0; 7], 0, 1).is_err());
}

#[test]
fn rejects_invalid_pe32_alignment_relationships() {
    let mut too_small = fixture(false);
    too_small[0x98 + 36..0x98 + 40].copy_from_slice(&0x100u32.to_le_bytes());
    let error = Pe::parse(&too_small).unwrap_err().to_string();
    assert!(
        error.contains("FileAlignment") && error.contains("outside"),
        "{error}"
    );

    let mut mismatched_low_alignment = fixture(false);
    mismatched_low_alignment[0x98 + 32..0x98 + 36].copy_from_slice(&0x400u32.to_le_bytes());
    let error = Pe::parse(&mismatched_low_alignment)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("low-alignment PE images are unsupported"),
        "{error}"
    );
    let mut misaligned_image_base = fixture(false);
    misaligned_image_base[0x98 + 28..0x98 + 32].copy_from_slice(&0x0040_0001u32.to_le_bytes());
    let error = Pe::parse(&misaligned_image_base).unwrap_err().to_string();
    assert!(
        error.contains("ImageBase") && error.contains("aligned"),
        "{error}"
    );
}

#[test]
fn parses_coff_dll_characteristic() {
    let mut data = pe32_plus_fixture();
    let coff = 0x84;
    data[coff + 18..coff + 20].copy_from_slice(&(0x0022 | IMAGE_FILE_DLL).to_le_bytes());
    assert!(Pe::parse(&data).unwrap().is_dll());

    data[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes());
    assert!(!Pe::parse(&data).unwrap().is_dll());
}

#[test]
fn alignment_is_checked() {
    assert_eq!(align_up(0, 0x200).unwrap(), 0);
    assert_eq!(align_up(1, 0x200).unwrap(), 0x200);
    assert_eq!(align_up(0x400, 0x200).unwrap(), 0x400);
    assert!(align_up(1, 3).is_err());
    assert!(align_up(u32::MAX, 2).is_err());
}

#[test]
fn checksum_zeros_its_field_and_includes_file_length() {
    let mut data = [1, 2, 0xaa, 0xbb, 0xcc, 0xdd, 7, 8];
    assert_eq!(pe_checksum(&data, 2).unwrap(), 0x0a10);
    data[2..6].copy_from_slice(&0x0a10u32.to_le_bytes());
    assert_eq!(pe_checksum(&data, 2).unwrap(), 0x0a10);
    assert!(pe_checksum(&data, 5).is_err());
}

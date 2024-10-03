use std::ffi::c_void;
use std::fs::File;
use std::panic;
use anyhow::{anyhow, Result};
use simplelog::{Config, LevelFilter, WriteLogger};
use windows::Win32::Foundation::{BOOL, HMODULE};
use windows::Win32::System::Memory::{PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_WRITECOPY, PAGE_EXECUTE_READWRITE};
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;

mod patch;
mod game;

const ICON_TEX_NAME: &'static [u8] = b"data/pic/etc/itemmenu2.tex";
const MARIA_ICON_DRAW_CALL: [u8; 7] = [0x50, 0x0F, 0xB6, 0x46, 0xF0, 0x50, 0xE8];
const ICON_DRAW_LOOP: [u8; 16] = [0x66, 0x8B, 0x50, 0x04, 0x66, 0x2B, 0x10, 0x83, 0xC0, 0x3C, 0x66, 0x89, 0x51, 0xFE, 0x66, 0x8B];

fn open_log() -> Result<()> {
    let log_file = File::create("sh2hvnknf.log")?;
    WriteLogger::init(LevelFilter::Debug, Config::default(), log_file)?;
    panic::set_hook(Box::new(|info| {
        let msg = info.payload().downcast_ref::<&str>().unwrap_or(&"unknown");
        let (file, line) = info
            .location()
            .map_or(("unknown", 0), |l| (l.file(), l.line()));
        log::error!("Panic in {} on line {}: {}", file, line, msg);
    }));

    Ok(())
}

fn main(reason: u32) -> Result<()> {
    if reason != DLL_PROCESS_ATTACH {
        return Ok(());
    }

    open_log()?;

    log::debug!("Searching for patch locations");

    let mut searcher = patch::ByteSearcher::new();
    searcher.discover_modules()?;
    let searcher = searcher;

    let sh2pc = &["sh2pc.exe"];

    let tex_address = match searcher.find_bytes(&[ICON_TEX_NAME], Some(PAGE_READONLY), sh2pc)? {
        [Some(tex_address)] => tex_address,
        _ => return Err(anyhow!("Failed to find item icon texture name")),
    };
    log::debug!("Found item menu texture path at {:#08X}", tex_address as usize);

    let mut menu_data: [u8; 16] = [0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 1, 0, 0, 0];
    menu_data[..4].copy_from_slice(&(tex_address as usize).to_le_bytes());
    // we already rely on our icon coords game constant being a binary match for the exe's icon
    // coords, so let's just directly use it as our search data as well
    let icon_coords_ptr = (&game::ICON_COORDS).as_ptr() as *const u8;
    let icon_coords_buf = unsafe { std::slice::from_raw_parts(icon_coords_ptr, 12) };

    let (menu_address, icon_coord_address) = match searcher.find_bytes(&[&menu_data, icon_coords_buf], Some(PAGE_READWRITE | PAGE_WRITECOPY), sh2pc)? {
        [Some(menu_address), Some(icon_coord_address)] => (menu_address, icon_coord_address),
        _ => return Err(anyhow!("Failed to find .data values")),
    };
    log::debug!("Found menu data at {:#08X}, icon coords at {:#08X}", menu_address as usize, icon_coord_address as usize);

    // Maria vs James texture check
    let mut tex_ref_data: [u8; 7] = [0x50, 0x68, 0, 0, 0, 0, 0xE8];
    tex_ref_data[2..6].copy_from_slice(&(menu_address as usize).to_le_bytes());
    let (tex_ref_call_address, icon_draw_call_address, icon_draw_loop_address) = match searcher.find_bytes(&[&tex_ref_data, &MARIA_ICON_DRAW_CALL, &ICON_DRAW_LOOP], Some(PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE), sh2pc)? {
        [Some(tex_ref_call_address), Some(icon_draw_call_address), Some(icon_draw_loop_address)] => (tex_ref_call_address, icon_draw_call_address, icon_draw_loop_address),
        _ => return Err(anyhow!("Failed to find code addresses")),
    };
    log::debug!("Found tex ref data at {:#08X}, icon draw call at {:#08X}, icon draw loop at {:#08X}", tex_ref_call_address as usize, icon_draw_call_address as usize, icon_draw_loop_address as usize);

    unsafe {
        // sanity checks
        let tex_ref_check_address = tex_ref_call_address.offset(-27);
        patch::assert_byte(tex_ref_check_address, 0x75)?; // jnz

        let icon_check_address = icon_draw_call_address.offset(-7);
        patch::assert_byte(icon_check_address, 0x75)?; // jnz

        let coords_load_address = icon_draw_loop_address.offset(-8);
        patch::assert_byte(coords_load_address, 0xB8)?; // mov

        let coords_end_load_address = icon_draw_loop_address.offset(121);
        patch::assert_byte(coords_end_load_address, 0x3D)?; // cmp

        let id_check_address = icon_draw_loop_address.offset(146);
        patch::assert_byte(id_check_address, 0x39)?; // cmp

        let item_num_address = icon_draw_loop_address.offset(156);
        patch::assert_byte(item_num_address, 0x83)?; // cmp

        let float_address1 = icon_draw_loop_address.offset(203);
        patch::assert_byte(float_address1, 0xD8)?; // fmul

        let float_address2 = icon_draw_loop_address.offset(229);
        patch::assert_byte(float_address2, 0xD8)?; // fmul

        let coords_index_address1 = icon_draw_loop_address.offset(292);
        patch::assert_byte(coords_index_address1, 0x0F)?; // movsx

        let coords_index_address2 = icon_draw_loop_address.offset(299);
        patch::assert_byte(coords_index_address2, 0x0F)?; // movsx

        let icon_coords_addr_bytes = (icon_coords_ptr as usize).to_le_bytes();
        let icon_coords_field2_addr_bytes = (icon_coords_ptr.offset(2) as usize).to_le_bytes();
        let icon_coords_end_addr_bytes = (icon_coords_ptr.add(size_of_val(&game::ICON_COORDS)) as usize).to_le_bytes();
        let item_ids_addr_bytes = ((&game::ICON_ITEM_IDS).as_ptr() as usize).to_le_bytes();
        let icon_floats_addr_bytes = ((&game::ICON_FLOATS).as_ptr() as usize).to_le_bytes();

        // use new icon texture which includes DLC icons
        log::info!("Applying texture name patch at address {:#08X}", tex_address as usize);
        patch::patch(tex_address.offset(21), b"3")?;

        // always use main scenario icon texture
        log::info!("Applying menu texture patch at address {:#08X}", tex_ref_check_address as usize);
        patch::patch(tex_ref_check_address, &[0xEB])?;

        // always use main scenario icon dimensions
        log::info!("Applying icon draw patch at address {:#08X}", icon_check_address as usize);
        patch::patch(icon_check_address, &[0xEB])?;

        // use our expanded icon coordinate array
        log::info!("Applying icon coordinate patches at addresses {:#08X}, {:#08X}, {:#08X}, {:#08X}", coords_load_address as usize, coords_end_load_address as usize, coords_index_address1 as usize, coords_index_address2 as usize);
        patch::patch(coords_load_address.offset(1), &icon_coords_addr_bytes)?;
        patch::patch(coords_end_load_address.offset(1), &icon_coords_end_addr_bytes)?;
        patch::patch(coords_index_address1.offset(3), &icon_coords_addr_bytes)?;
        patch::patch(coords_index_address2.offset(3), &icon_coords_field2_addr_bytes)?;

        // use our expanded item ID array
        log::info!("Applying icon item ID patch at address {:#08X}", id_check_address as usize);
        patch::patch(id_check_address.offset(3), &item_ids_addr_bytes)?;

        // use our expanded icon float array
        log::info!("Applying icon float patches at addresses {:#08X}, {:#08X}", float_address1 as usize, float_address2 as usize);
        patch::patch(float_address1.offset(3), &icon_floats_addr_bytes)?;
        patch::patch(float_address2.offset(3), &icon_floats_addr_bytes)?;

        // increase number of items
        log::info!("Applying item count patch at address {:#08X}", item_num_address as usize);
        patch::patch(item_num_address.offset(2), &(game::NUM_ITEMS as u8).to_le_bytes())?;
    }

    log::info!("All patches applied successfully");

    Ok(())
}

#[no_mangle]
#[allow(non_snake_case)]
extern "system" fn DllMain(_dll_module: HMODULE, reason: u32, _reserved: *const c_void) -> BOOL {
    match main(reason) {
        Ok(_) => true,
        Err(e) => {
            log::error!("Fatal error: {e}");
            false
        }
    }.into()
}
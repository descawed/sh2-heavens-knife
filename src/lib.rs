#![allow(static_mut_refs)]

use std::ffi::c_void;
use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::{bail, Context, Result};
use simplelog::LevelFilter;
use windows::Win32::Foundation::{BOOL, HMODULE};
use windows::Win32::System::Memory::{
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
};
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;

mod error;
mod game;
mod patch;
mod input;
mod config;
mod global;
use global::*;

const CONFIG_FILENAME: &str = "knife.toml";

// search strings to find the areas we want to patch
const ICON_TEX_NAME: &[u8] = b"data/pic/etc/itemmenu2.tex\0";
const HANDGUN_MODEL_NAME: &[u8] = b"data/chr/wp/wp_handgun.mdl\0";
const REVOLVER_MODEL_NAME: &[u8] = b"data/chr2/wp/wp_colt.mdl\0";
const CHAINSAW_KG1_NAME: &[u8] = b"data/chr/wp/wp_csaw.kg1\0";
const REVOLVER_KG1_NAME: &[u8] = b"data/chr2/wp/wp_colt.kg1\0";
const PAUSED_TEXT: &[u8] = b"\\hPAUSED\0";
const JAMES_ICON_DRAW_LOOP: [u8; 16] = [
    0x66, 0x8B, 0x50, 0x04, 0x66, 0x2B, 0x10, 0x83, 0xC0, 0x3C, 0x66, 0x89, 0x51, 0xFE, 0x66, 0x8B,
];
const MARIA_ICON_DRAW_LOOP: [u8; 16] = [
    0x66, 0x8B, 0x50, 0x04, 0x66, 0x2B, 0x10, 0x83, 0xC0, 0x24, 0x66, 0x89, 0x51, 0xFE, 0x66, 0x8B,
];
const MARIA_WEAPON_ASSERT: [u8; 8] = [0xFF, 0x75, 0x1B, 0x68, 0x17, 0x03, 0x00, 0x00];
const MARIA_WEAPON_ASSERT2: [u8; 8] = [0xFF, 0x75, 0x1D, 0x68, 0x7C, 0x03, 0x00, 0x00];
const DRAW_MESSAGE_FUNC: [u8; 9] = [
    0x8B, 0x44, 0x24, 0x04, 0x85, 0xC0, 0x75, 0x06, 0xA3,
];
const JAMES_ACTION_SOUNDS: [u8; 6] = [
    0xFE, 0x83, 0xF8, 0x1B, 0x0F, 0x87,
];
const MARIA_ACTION_SOUNDS: [u8; 7] = [
    0x0C, 0x8D, 0x41, 0xFD, 0x83, 0xF8, 0x1A,
];
const GRUNT_SOUND_CALL: [u8; 5] = [
    0x1F, 0x2B, 0x00, 0x00, 0xE8,
];
const SOUND_PARAMETER_SELECT: [u8; 6] = [
    0x83, 0xE8, 0x06, 0x74, 0x15, 0x48,
];
const ROTATE_BONE_TRANSFORM: [u8; 10] = [
    0x89, 0x5D, 0x38, 0x89, 0x5D, 0x3C, 0x89, 0x5D, 0x40, 0xE8,
];
const MAIN_MENU_FUNC1: [u8; 5] = [
    0x00, 0x00, 0x70, 0x42, 0xB9,
];
const INIT_INVENTORY: [u8; 7] = [
    0x00, 0x00, 0x10, 0x00, 0x6A, 0x15, 0x89,
];
// there are two occurrences of this pattern, but they both come immediately after a call to the
// function we're trying to intercept
const AFTER_DESCRIPTION_CALL: [u8; 12] = [
    0x6A, 0x00, 0x68, 0x00, 0x00, 0x80, 0x3F, 0x68, 0x21, 0x2B, 0x00, 0x00,
];
const MENU_INPUT_LOOP: [u8; 8] = [
    0x09, 0x00, 0x00, 0x00, 0x83, 0xC4, 0x0C, 0x89,
];
const MARIA_SET_WEAPON_POSE: [u8; 6] = [
    0x50, 0x51, 0x6A, 0x06, 0x52, 0xE8,
];
const JAMES_SET_WEAPON_POSE: [u8; 9] = [
    0x83, 0xF8, 0x08, 0x0F, 0x87, 0x51, 0x01, 0x00, 0x00,
];
const FLASHLIGHT_CHECK: [u8; 7] = [
    0x83, 0xC4, 0x20, 0x83, 0xC4, 0x70, 0xC3,
];
const FLASHLIGHT_CHAR_CHECK1: [u8; 9] = [
    0x0F, 0xBF, 0x46, 0x10, 0x3D, 0x00, 0x01, 0x00, 0x00,
];
const FLASHLIGHT_CHAR_CHECK2: [u8; 9] = [
    0x0F, 0xBF, 0x47, 0x10, 0x3D, 0x00, 0x01, 0x00, 0x00,
];
const FLASHLIGHT_TRANSFORM_RETURN: [u8; 8] = [
    0x5D, 0x81, 0xC4, 0xF8, 0x01, 0x00, 0x00, 0xC3,
];

const FLASHLIGHT_CHAR_CHECK_PATCH: [u8; 13] = [
    0x90, // nop
    0x50, // push eax
    0xE8, 0, 0, 0, 0, // call <target>
    0x83, 0xC4, 0x04, // add esp, 4
    0x84, 0xC0, // test al, al
    0x74, // jz
];

static mut GLOBAL: PersistentData = PersistentData::new();
static mut CONFIG_INTERFACE: config::UserInterface = config::UserInterface::new(config::Config::new());

unsafe extern "C" fn override_animation_paths() {
    GLOBAL.set_weapon_animations();
}

unsafe extern "C" fn james_sound_check(sound_parameters: *mut game::Sound3dParameters, animation_id: u32, animation_description: *const game::AnimationDescription) -> u32 {
    if animation_id != 28 { // attacking
        return 0;
    }

    let sound_parameters = std::slice::from_raw_parts_mut(sound_parameters, 3);
    match GLOBAL.equipped_item_id() {
        game::ITEM_ID_REVOLVER => {
            let animation_id = (*animation_description).id;
            if animation_id == 21109 || animation_id == 21110 {
                sound_parameters[0].unk00 = 0.80000001;
                sound_parameters[0].start_frame = if animation_id == 21109 {
                    21
                } else {
                    26
                };

                game::HANDGUN_RELOAD_SOUND_ID
            } else {
                0
            }
        }
        game::ITEM_ID_CLEAVER => {
            let grunt_sound_value = GLOBAL.unk_grunt_sound_value();
            let mut character_sound = game::JAMES_GRUNT_SOUND_ID | if (grunt_sound_value & 1) == 0 {
                1
            } else {
                0
            };

            // set sound parameters
            if (*animation_description).unk04 > 0 {
                let sound_param_data = GLOBAL.sound_param_data();

                let start_frame = match (sound_param_data[0], sound_param_data[7]) {
                    (3, 0) => {
                        character_sound += 1;
                        Some(11)
                    }
                    (4, 0) => Some(10),
                    (3, _) => {
                        character_sound += 1;
                        Some(7)
                    }
                    (4, _) => Some(7),
                    _ => None,
                };
                if let Some(start_frame) = start_frame {
                    sound_parameters[0].start_frame = start_frame;
                    sound_parameters[1].start_frame = start_frame;
                }

                let grunt_sound_float = (GLOBAL.unk_grunt_sound_value() as f32) * 4.6566129e-10;

                sound_parameters[0].unk00 = 0.89999998;
                sound_parameters[1].unk00 = grunt_sound_float * 0.7;
            }

            (character_sound << 16) | game::CLEAVER_ATTACK_SOUND_ID
        }
        _ => 0,
    }
}

unsafe extern "C" fn maria_sound_check(sound_parameters: *mut game::Sound3dParameters, animation_id: u32, animation_description: *const game::AnimationDescription) -> u32 {
    let item_id = GLOBAL.equipped_item_id();
    let sound_parameters = std::slice::from_raw_parts_mut(sound_parameters, 3);

    match (animation_id, item_id) {
        (2, game::ITEM_ID_CHAINSAW) => {
            sound_parameters[0].unk00 = 0.40000001;
            sound_parameters[0].start_frame = 4;

            11025 // no symbolic constant for this because I don't know what it is
        }
        (8 | 9 | 10, game::ITEM_ID_GREAT_KNIFE) => {
            sound_parameters[0].unk00 = 0.30000001;
            sound_parameters[0].start_frame = 5;
            sound_parameters[1].unk00 = 0.30000001;
            sound_parameters[1].start_frame = 18;

            (game::GREAT_KNIFE_DRAG_SOUND_ID << 16) | game::GREAT_KNIFE_DRAG_SOUND_ID
        }
        (28, game::ITEM_ID_HANDGUN | game::ITEM_ID_SHOTGUN | game::ITEM_ID_RIFLE | game::ITEM_ID_HYPER_SPRAY) => {
            let mut character_sound = 0u32;
            let mut weapon_sound = 0u32;

            let animation_id = (*animation_description).id;
            match item_id {
                game::ITEM_ID_HANDGUN => {
                    if animation_id == 209 || animation_id == 210 {
                        weapon_sound = game::HANDGUN_RELOAD_SOUND_ID;
                        sound_parameters[0].unk00 = 0.80000001;
                        sound_parameters[0].start_frame = if animation_id == 209 {
                            21
                        } else {
                            26
                        };
                    }
                }
                game::ITEM_ID_SHOTGUN => {
                    sound_parameters[0].unk00 = 0.80000001;
                    if animation_id == 260 {
                        weapon_sound = game::SHOTGUN_SOUND_ID1;
                        sound_parameters[0].start_frame = 12;
                    } else {
                        weapon_sound = game::SHOTGUN_SOUND_ID2;
                        sound_parameters[0].start_frame = 23;
                    };
                }
                game::ITEM_ID_RIFLE => {
                    if animation_id == 304 {
                        weapon_sound = game::RIFLE_RELOAD_SOUND_ID;
                        sound_parameters[0].unk00 = 0.80000001;
                        sound_parameters[0].start_frame = 17;
                    }
                }
                game::ITEM_ID_HYPER_SPRAY => {
                    if animation_id == 510 || animation_id == 511 {
                        weapon_sound = game::HYPER_SPRAY_RELOAD_SOUND_ID;
                        character_sound = game::HYPER_SPRAY_RELOAD_SOUND_ID;

                        sound_parameters[0].unk00 = 0.80000001;
                        sound_parameters[1].unk00 = 0.80000001;

                        if animation_id == 510 {
                            sound_parameters[0].start_frame = 7;
                            sound_parameters[1].start_frame = 14;
                        } else {
                            sound_parameters[0].start_frame = 3;
                            sound_parameters[1].start_frame = 10;
                        }
                    }
                }
                _ => unreachable!(),
            }

            (character_sound << 16) | weapon_sound
        }
        (28, game::ITEM_ID_WOODEN_PLANK | game::ITEM_ID_STEEL_PIPE | game::ITEM_ID_GREAT_KNIFE) => {
            let grunt_sound_value = GLOBAL.unk_grunt_sound_value();
            let mut character_sound = game::MARIA_GRUNT_SOUND_ID | if (grunt_sound_value & 1) == 0 {
                1
            } else {
                0
            };

            let weapon_sound = if item_id == game::ITEM_ID_GREAT_KNIFE {
                game::GREAT_KNIFE_ATTACK_SOUND_ID
            } else {
                game::DEFAULT_MELEE_ATTACK_SOUND_ID
            };

            if (*animation_description).unk04 <= 0 {
                return (character_sound << 16) | weapon_sound;
            }

            let sound_param_data = GLOBAL.sound_param_data();
            match item_id {
                game::ITEM_ID_WOODEN_PLANK => {
                    match sound_param_data[0] {
                        3 => {
                            if sound_param_data[7] == 0 {
                                sound_parameters[0].start_frame = 11;
                                sound_parameters[1].start_frame = 11;
                            } else {
                                sound_parameters[0].start_frame = 7;
                                sound_parameters[1].start_frame = 7;
                            }

                            character_sound += 1;
                        }
                        4 => {
                            if sound_param_data[7] == 0 {
                                sound_parameters[0].start_frame = 10;
                                sound_parameters[1].start_frame = 10;
                            } else {
                                sound_parameters[0].start_frame = 7;
                                sound_parameters[1].start_frame = 7;
                            }
                        }
                        _ => (),
                    }
                }
                game::ITEM_ID_STEEL_PIPE => {
                    match sound_param_data[0] {
                        3 => {
                            if sound_param_data[7] == 0 {
                                sound_parameters[0].start_frame = 8;
                                sound_parameters[1].start_frame = 8;
                            } else {
                                sound_parameters[0].start_frame = 2;
                                sound_parameters[1].start_frame = 2;
                            }

                            character_sound += 1;
                        }
                        4 => {
                            if sound_param_data[7] == 0 {
                                sound_parameters[0].start_frame = 15;
                                sound_parameters[1].start_frame = 13;
                            } else {
                                sound_parameters[0].start_frame = 9;
                                sound_parameters[1].start_frame = 9;
                            }
                        }
                        5 => {
                            sound_parameters[0].start_frame = 8;
                            sound_parameters[1].start_frame = 7;
                            character_sound += 1;
                        }
                        _ => (),
                    }
                }
                game::ITEM_ID_GREAT_KNIFE => {
                    match sound_param_data[0] {
                        3 => {
                            if sound_param_data[4] == 0 {
                                sound_parameters[0].start_frame = 8;
                                sound_parameters[1].start_frame = 8;
                            } else {
                                sound_parameters[0].start_frame = 11;
                                sound_parameters[1].start_frame = 11;
                            }

                            character_sound += 1;
                        }
                        4 => {
                            if sound_param_data[4] == 0 {
                                sound_parameters[0].start_frame = 17;
                                sound_parameters[1].start_frame = 17;
                            } else {
                                sound_parameters[0].start_frame = 18;
                                sound_parameters[1].start_frame = 18;
                            }
                        }
                        _ => (),
                    }
                }
                _ => unreachable!(),
            }

            let grunt_sound_float = (GLOBAL.unk_grunt_sound_value() as f32) * 4.6566129e-10;

            sound_parameters[0].unk00 = 0.89999998;
            sound_parameters[1].unk00 = grunt_sound_float * 0.7;

            (character_sound << 16) | weapon_sound
        }
        _ => 0,
    }
}

unsafe extern "C" fn equipped_weapon_transform_override(animation: *const game::Animation, record: *const game::AnimationRecord, rotation: *const game::D3DXVECTOR4) -> *const game::AnimationRecord {
    let animation = animation.as_ref().expect("animation pointer should not be null");
    let is_player_maria = GLOBAL.is_player_maria();
    let frame_size = if is_player_maria {
        game::MARIA_ANIMATION_FRAME_SIZE
    } else {
        game::JAMES_ANIMATION_FRAME_SIZE
    };

    if rotation != &raw const animation.equipped_weapon_rotation || animation.frame_size != frame_size {
        // only want to intercept equipped weapon transform for the player
        return record;
    }

    let bone_index = record.offset_from(animation.records);
    let new_index = match (is_player_maria, GLOBAL.equipped_item_id(), bone_index) {
        (true, game::ITEM_ID_HANDGUN, 27) => 21, // left shoulder
        (true, game::ITEM_ID_HANDGUN, 28) => 23, // right shoulder
        (true, game::ITEM_ID_RIFLE, 8) => 6, // head/neck
        (true, game::ITEM_ID_RIFLE, 9) => 11, // head/neck
        (true, game::ITEM_ID_RIFLE, 10) => 16, // head/neck
        (false, game::ITEM_ID_REVOLVER, 21) => 27, // left shoulder
        (false, game::ITEM_ID_REVOLVER, 23) => 28, // right shoulder
        _ => bone_index,
    };

    animation.records.offset(new_index)
}

unsafe fn save_config() {
    let config_text = CONFIG_INTERFACE.save_config();
    let config_path = Path::new(CONFIG_FILENAME);
    if let Err(e) = File::create(config_path).and_then(|mut file| file.write_all(config_text.as_bytes())) {
        log::error!("Failed to save config file to {}: {}", CONFIG_FILENAME, e);
    }
}

// return 0 to trigger skipping main menu draw
unsafe extern "C" fn main_menu_hook() -> u32 {
    let main_menu_state = GLOBAL.get_main_menu_state();
    // only run on main menu, scenario select, or difficulty select
    if !matches!(main_menu_state, 2 | 3 | 4) {
        return 1;
    }

    // we can only rely on this flag once we've chosen our scenario and we're waiting to choose the
    // difficulty, which is state 4
    let is_james = (main_menu_state == 4).then(|| !GLOBAL.is_player_maria());
    if CONFIG_INTERFACE.show(is_james, None) {
        save_config();
    }

    if CONFIG_INTERFACE.has_focus() {
        0
    } else {
        1
    }
}

unsafe extern "C" fn init_inventory_hook() {
    // don't override the items that we add ourselves
    GLOBAL.disable_item_override();

    let inventory = GLOBAL.inventory();
    inventory.clear();

    let is_james = !GLOBAL.is_player_maria();
    match CONFIG_INTERFACE.starting_inventory(is_james) {
        Some(starting_inventory) => {
            for (item_id, count) in starting_inventory.iter_items() {
                if let Some(count) = count {
                    // we do this so we can override add_item_to_inventory's count logic
                    log::debug!("Adding {}x {} to inventory", count, game::item_name(item_id));
                    inventory.add_item(item_id);
                    inventory.set_count(item_id, count);
                    if item_id == game::ITEM_ID_HYPER_SPRAY {
                        GLOBAL.set_new_game_plus_item_flag(2);
                    } else {
                        GLOBAL.inc_item_count();
                    }
                } else {
                    log::debug!("Adding {} to inventory", game::item_name(item_id));
                    GLOBAL.add_item_to_inventory(item_id);
                }
            }

            inventory.equipped_item = starting_inventory.equipped_item;
        }
        None => {
            // assign normal starting inventory
            if is_james {
                inventory.add_item(game::ITEM_ID_PHOTO_OF_MARY);
                GLOBAL.add_item_to_inventory(game::ITEM_ID_LETTER_FROM_MARY);
            } else {
                inventory.add_item(game::ITEM_ID_REVOLVER);
                inventory.set_count(game::ITEM_ID_REVOLVER, 1);
                GLOBAL.inc_item_count();
            }
        }
    }

    // these are the game's default settings for James. because the flashlight isn't fully working
    // for Maria at the moment, we'll default it to off for her. for the radio, we'll go ahead and
    // default it to on and set the normal default volume, since it doesn't have any affect if you
    // don't have the radio anyway.
    inventory.is_flashlight_on = is_james;
    inventory.is_radio_on = true;
    inventory.radio_volume = 10;

    GLOBAL.enable_item_override();
}

unsafe extern "C" fn item_pickup_text_hook(message_file: *mut *const u16, message_id: *mut i32) {
    if !CONFIG_INTERFACE.is_enabled() || (*message_file).is_null() {
        return;
    }

    let offset = *(*message_file).offset(*message_id as isize + 1);
    let data = (*message_file).offset(offset as isize) as *const u8;
    let Some((item_id, language)) = GLOBAL.get_item_id_for_message(data) else {
        return;
    };

    let new_item = CONFIG_INTERFACE.map_item(item_id, !GLOBAL.is_player_maria());
    if new_item == item_id {
        return;
    }

    let Some((override_file, override_id)) = GLOBAL.get_message_for_item(new_item, language) else {
        return;
    };

    *message_file = override_file as *const u16;
    *message_id = override_id;
}

unsafe extern "C" fn item_pickup_inventory_hook(_return1: usize, _return2: usize, item_id: i32) -> i32 {
    if GLOBAL.is_item_override_enabled() {
        CONFIG_INTERFACE.map_item(item_id as i8, !GLOBAL.is_player_maria()) as i32
    } else {
        item_id
    }
}

unsafe extern "C" fn menu_input_loop_hook(state: u32) -> u32 {
    if CONFIG_INTERFACE.has_focus() {
        // make sure we're in the pause menu
        if state != 16 {
            CONFIG_INTERFACE.reset_ui();
            0
        } else {
            // when we suppress the menu loop, the draw call now no longer happens at all, so we
            // have to trigger it manually
            pause_menu_draw_hook();
            1
        }
    } else {
        0
    }
}

unsafe extern "C" fn pause_menu_draw_hook() -> u32 {
    if CONFIG_INTERFACE.show(Some(!GLOBAL.is_player_maria()), Some(GLOBAL.inventory())) {
        save_config();
    }

    if CONFIG_INTERFACE.has_focus() {
        4 // add 4 bytes to stack to skip the return address and return directly to caller
    } else {
        0
    }
}

unsafe extern "C" fn find_maria_weapon_info() -> isize {
    GLOBAL.get_maria_weapon_offset()
}

unsafe extern "C" fn get_weapon_index_for_maria_pose() -> u32 {
    // use revolver pose for all ranged weapons and cleaver pose for all melee weapons
    match GLOBAL.equipped_item_id() {
        game::ITEM_ID_HANDGUN | game::ITEM_ID_SHOTGUN | game::ITEM_ID_RIFLE | game::ITEM_ID_REVOLVER | game::ITEM_ID_HYPER_SPRAY => 9,
        game::ITEM_ID_WOODEN_PLANK | game::ITEM_ID_STEEL_PIPE | game::ITEM_ID_CHAINSAW | game::ITEM_ID_GREAT_KNIFE | game::ITEM_ID_CLEAVER => 10,
        _ => 0,
    }
}

unsafe extern "C" fn get_weapon_index_for_james_pose() -> u32 {
    // treat revolver as handgun and cleaver as wooden plank
    match GLOBAL.equipped_item_id() {
        game::ITEM_ID_REVOLVER => 1,
        game::ITEM_ID_CLEAVER => 5,
        equipped_item => game::get_weapon_index(equipped_item) as u32,
    }
}

unsafe extern "C" fn should_use_maria_flashlight_calc() -> u32 {
    // the game code has a check for Maria in part of the code that does calculations related to the
    // flashlight. Maria can normally never get the flashlight, but I assume there must be some
    // situation where this code is used since they bothered to write it. however, when we let this
    // block run when turning on the flashlight as Maria, the light doesn't appear (perhaps it's
    // placed in an odd spot where it's not visible). so as a compromise, we'll override this code,
    // but only when the flashlight is on
    // side note: this function logically returns bool, but the game code does a `test eax, eax`,
    // and I'm not sure if Rust sets the whole eax register when returning a bool or just does like
    // a `mov al, 1`, so we're returning a u32 to be safe
    if GLOBAL.is_player_maria() && !GLOBAL.is_flashlight_on() {
        1
    } else {
        0
    }
}

unsafe extern "C" fn is_player_character(char_id: i32) -> bool {
    matches!(char_id, game::JAMES_ID1 | game::JAMES_ID2 | game::MARIA_ID)
}

unsafe extern "C" fn adjust_flashlight_vector() {
    if !GLOBAL.is_player_maria() {
        return;
    }

    // for some reason, the flashlight points off to the side for Maria, so we'll rotate it to face
    // the right direction
    let vec = GLOBAL.flashlight_vector();
    let x = vec[0];
    vec[0] = vec[2];
    vec[2] = -x;
}

fn main(reason: u32) -> Result<()> {
    if reason != DLL_PROCESS_ATTACH {
        return Ok(());
    }

    let config_path = Path::new(CONFIG_FILENAME);
    let config_read_result = std::fs::read_to_string(config_path).with_context(|| format!("Failed to read config from {}", CONFIG_FILENAME)).and_then(|s| config::Config::from_text(&s));
    let log_level = match &config_read_result {
        Ok(config) => config.log_level(),
        Err(_) => LevelFilter::Info,
    };

    // we don't really want the mod to not work just because we can't open the log file, so we'll
    // swallow any errors here. unfortunately, without the log file, we don't have anywhere to
    // report what went wrong.
    let _ = error::open_log(log_level, "knife.log");

    // wait until the log is open to propagate a config error
    let config = config_read_result?;
    if config.is_disabled() {
        // log as an error to make sure it shows up (unless the user has disabled logging entirely)
        log::error!("Heaven's Knife is disabled; exiting.");
        log::error!("Note: to re-enable the mod, open {} in a text editor and change the line\n\tstartup = \"disabled\"\nto\n\tstartup = \"default_off\"", CONFIG_FILENAME);
        return Ok(());
    }

    log::debug!("Searching for patch locations");

    let mut searcher = patch::ByteSearcher::new();
    searcher.discover_modules()?;
    let searcher = searcher;

    let sh2pc = &["sh2pc.exe"];

    let [
        Some(tex_address),
        Some(handgun_model_name_address),
        Some(revolver_model_name_address),
        Some(chainsaw_kg1_name_address),
        Some(revolver_kg1_name_address),
        Some(paused_text_address),
    ] = searcher.find_bytes(
        &[
            ICON_TEX_NAME,
            HANDGUN_MODEL_NAME,
            REVOLVER_MODEL_NAME,
            CHAINSAW_KG1_NAME,
            REVOLVER_KG1_NAME,
            PAUSED_TEXT,
        ], Some(PAGE_READONLY), sh2pc)? else {
        bail!("Failed to find read-only data");
    };
    let handgun_model_name_address = handgun_model_name_address as usize;
    let revolver_model_name_address = revolver_model_name_address as usize;
    let chainsaw_kg1_name_address = chainsaw_kg1_name_address as usize;
    let revolver_kg1_name_address = revolver_kg1_name_address as usize;
    let paused_text_address = paused_text_address as usize;
    log::debug!(
        "Found item menu texture path at {:#08X}, handgun model name at {:#08X}, revolver model name at {:#08X}, chainsaw kg1 name at {:#08X}, revolver kg1 name at {:#08X}, paused text at {:#08X}",
        tex_address as usize, handgun_model_name_address, revolver_model_name_address, chainsaw_kg1_name_address, revolver_kg1_name_address, paused_text_address,
    );

    let mut menu_data: [u8; 16] = [0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 1, 0, 0, 0];
    menu_data[..4].copy_from_slice(&(tex_address as usize).to_le_bytes());
    // we already rely on our icon coords game constant being a binary match for the exe's icon
    // coords, so let's just directly use it as our search data as well
    let icon_coords_ptr = game::ICON_COORDS.as_ptr() as *const u8;

    let [
        Some(menu_address),
        Some(handgun_model_file_address),
        Some(revolver_model_file_address),
        Some(chainsaw_kg1_file_address),
        Some(revolver_kg1_file_address),
        Some(menu_text_array_address),
    ] = searcher.find_bytes(
        &[
            &menu_data, &handgun_model_name_address.to_le_bytes(), &revolver_model_name_address.to_le_bytes(), &chainsaw_kg1_name_address.to_le_bytes(), &revolver_kg1_name_address.to_le_bytes(),
            &paused_text_address.to_le_bytes(),
        ],
        Some(PAGE_READWRITE | PAGE_WRITECOPY),
        sh2pc,
    )? else {
        bail!("Failed to find .data values");
    };
    log::debug!(
        "Found menu data at {:#08X}, handgun model file at {:#08X}, revolver model file at {:#08X}, chainsaw kg1 file at {:#08X}, revolver kg1 file at {:#08X}, menu text array at {:#08X}",
        menu_address as usize,
        handgun_model_file_address as usize,
        revolver_model_file_address as usize,
        chainsaw_kg1_file_address as usize,
        revolver_kg1_file_address as usize,
        menu_text_array_address as usize,
    );

    // Maria vs James texture check
    let mut tex_ref_data: [u8; 7] = [0x50, 0x68, 0, 0, 0, 0, 0xE8];
    tex_ref_data[2..6].copy_from_slice(&(menu_address as usize).to_le_bytes());
    // reference to handgun model used to determine weapon model buffer size
    let handgun_model_data = patch::push(handgun_model_file_address as usize);
    // reference to chainsaw shadow used to determine weapon shadow buffer size
    let chainsaw_kg1_data = patch::push(chainsaw_kg1_file_address as usize);
    // reference to pause menu text
    let mut menu_text_data: [u8; 5] = [0, 0, 0, 0, 0xEB];
    menu_text_data[..4].copy_from_slice(&(menu_text_array_address as usize).to_le_bytes());

    let [
        Some(tex_ref_call_address),
        Some(pause_menu_address),
        Some(handgun_model_push_address),
        Some(chainsaw_kg1_push_address),
        Some(james_icon_draw_loop_address),
        Some(maria_icon_draw_loop_address),
        Some(weapon_assert_address),
        Some(weapon_assert_address2),
        Some(draw_message_func),
        Some(james_action_sounds_address),
        Some(maria_action_sounds_address),
        Some(grunt_sound_call_address),
        Some(sound_parameter_select_address),
        Some(rotate_bone_transform_address),
        Some(init_inventory_address),
        Some(after_description_call_address),
        Some(menu_input_loop_address),
        Some(main_menu_func1_address),
        Some(maria_set_pose_address),
        Some(james_set_pose_address),
        Some(flashlight_check_address),
        Some(flashlight_char_check1_address),
        Some(flashlight_char_check2_address),
        Some(flashlight_transform_return_address),
    ] = searcher.find_bytes(
        &[
            &tex_ref_data,
            &menu_text_data,
            &handgun_model_data,
            &chainsaw_kg1_data,
            &JAMES_ICON_DRAW_LOOP,
            &MARIA_ICON_DRAW_LOOP,
            &MARIA_WEAPON_ASSERT,
            &MARIA_WEAPON_ASSERT2,
            &DRAW_MESSAGE_FUNC,
            &JAMES_ACTION_SOUNDS,
            &MARIA_ACTION_SOUNDS,
            &GRUNT_SOUND_CALL,
            &SOUND_PARAMETER_SELECT,
            &ROTATE_BONE_TRANSFORM,
            &INIT_INVENTORY,
            &AFTER_DESCRIPTION_CALL,
            &MENU_INPUT_LOOP,
            &MAIN_MENU_FUNC1,
            &MARIA_SET_WEAPON_POSE,
            &JAMES_SET_WEAPON_POSE,
            &FLASHLIGHT_CHECK,
            &FLASHLIGHT_CHAR_CHECK1,
            &FLASHLIGHT_CHAR_CHECK2,
            &FLASHLIGHT_TRANSFORM_RETURN,
        ],
        Some(PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE),
        sh2pc,
    )? else {
        bail!("Failed to find code addresses");
    };
    log::debug!(
        "Found tex ref data at {:#08X}, pause menu at {:#08X}, James icon draw loop at {:#08X}, Maria icon draw loop at {:#08X}, weapon assert at {:#08X}, weapon assert 2 at {:#08X}, \
        draw msg call at {:#08X}, James action sounds at {:#08X}, Maria action sounds at {:#08X}, melee grunt sound call at {:#08X}, sound param select at {:#08X}, \
        handgun model push at {:#08X}, chainsaw kg1 push at {:#08X}, rotate bone transform at {:#08X}, init inventory at {:#08X}, after description call at {:#08X}, menu input loop at {:#08X}, \
        main menu func 1 at {:#08X}, Maria set weapon pose at {:#08X}, James set weapon pose at {:#08X}, flashlight check at {:#08X}, flashlight character check at {:#08X}, flashlight character check 2 at {:#08X}, \
        flashlight transform return at {:#08X}",
        tex_ref_call_address as usize,
        pause_menu_address as usize,
        james_icon_draw_loop_address as usize,
        maria_icon_draw_loop_address as usize,
        weapon_assert_address as usize,
        weapon_assert_address2 as usize,
        draw_message_func as usize,
        james_action_sounds_address as usize,
        maria_action_sounds_address as usize,
        grunt_sound_call_address as usize,
        sound_parameter_select_address as usize,
        handgun_model_push_address as usize,
        chainsaw_kg1_push_address as usize,
        rotate_bone_transform_address as usize,
        init_inventory_address as usize,
        after_description_call_address as usize,
        menu_input_loop_address as usize,
        main_menu_func1_address as usize,
        maria_set_pose_address as usize,
        james_set_pose_address as usize,
        flashlight_check_address as usize,
        flashlight_char_check1_address as usize,
        flashlight_char_check2_address as usize,
        flashlight_transform_return_address as usize,
    );

    unsafe {
        CONFIG_INTERFACE.set_config(config);

        // we need to find the main menu loop so we can patch in our configuration menu option
        let main_menu_func1_entry_point = main_menu_func1_address.offset(-104);
        patch::assert_byte(main_menu_func1_entry_point, 0x56)?; // push

        let [Some(main_menu_func1_ref_address)] = searcher.find_bytes(&[&(main_menu_func1_entry_point as usize).to_le_bytes()], Some(PAGE_READWRITE | PAGE_WRITECOPY), sh2pc)? else {
            bail!("Failed to find reference to main menu func 1 {:#08X}", main_menu_func1_entry_point as usize);
        };

        let [Some(main_menu_dynamic_dispatch_address)] = searcher.find_bytes(&[&(main_menu_func1_ref_address as usize).to_le_bytes()], Some(PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE), sh2pc)? else {
            bail!("Failed to find dynamic dispatch address for main menu func 1 {:#08X}", main_menu_func1_ref_address as usize);
        };

        // sanity checks

        // we'll patch here to show our UI on the main menu
        let main_menu_dispatch_func = main_menu_dynamic_dispatch_address.offset(-13);
        patch::assert_byte(main_menu_dispatch_func, 0xE8)?; // call

        let tex_ref_check_address = tex_ref_call_address.offset(-27);
        patch::assert_byte(tex_ref_check_address, 0x75)?; // jnz

        let james_action_sounds_switch = james_action_sounds_address.offset(4);
        patch::assert_byte(james_action_sounds_switch, 0x0F)?; // ja

        let maria_action_sounds_switch = maria_action_sounds_address.offset(7);
        patch::assert_byte(maria_action_sounds_switch, 0x0F)?; // ja

        let handgun_model_push_address2 = handgun_model_push_address.offset(410);
        patch::assert_byte(handgun_model_push_address2, 0x68)?; // push

        let rotate_bone_func_address = rotate_bone_transform_address.offset(-42);
        patch::assert_byte(rotate_bone_func_address, 0x83)?; // sub

        let add_inventory_call_address = init_inventory_address.offset(12);
        patch::assert_byte(add_inventory_call_address, 0xE8)?; // call

        let inc_item_count_address = init_inventory_address.offset(-51);
        patch::assert_byte(inc_item_count_address, 0xE8)?; // call

        let init_inventory_entry_point = init_inventory_address.offset(-85);
        patch::assert_byte(init_inventory_entry_point, 0x6A)?; // push

        let description_call_address = after_description_call_address.offset(-5);
        patch::assert_byte(description_call_address, 0xE8)?; // call

        // we'll patch here to add our option to the pause menu
        let pause_menu_entry_address = pause_menu_address.offset(-31);
        patch::assert_byte(pause_menu_entry_address, 0xE8)?; // call

        let menu_input_loop_start = menu_input_loop_address.offset(-2210); // yikes
        patch::assert_byte(menu_input_loop_start, 0x0F)?; // ja

        let is_flashlight_on_call = flashlight_check_address.offset(29);
        patch::assert_byte(is_flashlight_on_call, 0xE8)?; // call

        let flashlight_calc_call = flashlight_check_address.offset(132);
        patch::assert_byte(flashlight_calc_call, 0xE8)?; // call

        let james_sounds_switch_default = patch::get_conditional_jump_target(james_action_sounds_switch);
        let maria_sounds_switch_default = patch::get_conditional_jump_target(maria_action_sounds_switch);
        let add_item_to_inventory = patch::get_call_target(add_inventory_call_address) as usize;
        let inc_item_count = patch::get_call_target(inc_item_count_address) as usize;
        let description_func = patch::get_call_target(description_call_address) as usize;
        let main_menu_original_call = patch::get_call_target(main_menu_dispatch_func) as usize;
        let is_flashlight_on = patch::get_call_target(is_flashlight_on_call) as usize;
        let flashlight_calc = patch::get_call_target(flashlight_calc_call) as usize;
        // make sure the addresses look reasonable
        if !searcher.find_addresses_exec(
            &[
                james_sounds_switch_default as usize,
                maria_sounds_switch_default as usize,
                add_item_to_inventory,
                inc_item_count,
                description_func,
                main_menu_original_call,
                is_flashlight_on,
                flashlight_calc,
            ],
            sh2pc)?.iter().all(|f| *f) {
            bail!(
                "One or more of James sound switch default {:#08X}, Maria sound switch default {:#08X}, add inventory {:#08X}, inc item count {:#08X}, \
                description func {:#08X}, main menu original call {:#08X}, flashlight on call {:#08X}, flashlight calc {:#08X} don't look right",
                james_sounds_switch_default as usize, maria_sounds_switch_default as usize, add_item_to_inventory, inc_item_count, description_func,
                main_menu_original_call, is_flashlight_on, flashlight_calc,
            );
        };

        let new_game_plus_flag_call = (add_item_to_inventory + 64) as *const c_void;
        patch::assert_byte(new_game_plus_flag_call, 0xE8)?; // call

        let new_game_plus_flag_func = patch::get_call_target(new_game_plus_flag_call) as usize;
        // make sure the addresses look reasonable
        if !searcher.find_addresses_exec(&[new_game_plus_flag_func], sh2pc)?[0] {
            bail!("SetNewGamePlusFlag() address {:#08X} doesn't look right", new_game_plus_flag_func);
        };

        let maria_icon_func_address = maria_icon_draw_loop_address.offset(-16);
        patch::assert_byte(maria_icon_func_address, 0x83)?; // sub

        let james_icon_func_address = james_icon_draw_loop_address.offset(-16);
        patch::assert_byte(james_icon_func_address, 0x83)?; // sub

        let coords_load_address = james_icon_draw_loop_address.offset(-8);
        patch::assert_byte(coords_load_address, 0xB8)?; // mov

        let coords_end_load_address = james_icon_draw_loop_address.offset(121);
        patch::assert_byte(coords_end_load_address, 0x3D)?; // cmp

        let id_check_address = james_icon_draw_loop_address.offset(146);
        patch::assert_byte(id_check_address, 0x39)?; // cmp

        let item_num_address = james_icon_draw_loop_address.offset(156);
        patch::assert_byte(item_num_address, 0x83)?; // cmp

        let float_address1 = james_icon_draw_loop_address.offset(203);
        patch::assert_byte(float_address1, 0xD8)?; // fmul

        let float_address2 = james_icon_draw_loop_address.offset(229);
        patch::assert_byte(float_address2, 0xD8)?; // fmul

        let coords_index_address1 = james_icon_draw_loop_address.offset(292);
        patch::assert_byte(coords_index_address1, 0x0F)?; // movsx

        let coords_index_address2 = james_icon_draw_loop_address.offset(299);
        patch::assert_byte(coords_index_address2, 0x0F)?; // movsx

        // we don't patch this check so we can handle Maria's no-weapon animation
        /*let weapon_player_check_address1 = weapon_assert_address.offset(-63);
        patch::assert_byte(weapon_player_check_address1, 0x0F)?; // jnz*/

        let load_weapon_address = weapon_assert_address.offset(-82);
        patch::assert_byte(load_weapon_address, 0xE8)?; // call

        let weapon_player_check_address2 = weapon_assert_address.offset(357);
        patch::assert_byte(weapon_player_check_address2, 0x75)?; // jnz

        let maria_weapon_assert_address = weapon_assert_address.offset(3);
        // no point asserting since this is still within our search string

        let load_weapon_address2 = weapon_assert_address2.offset(-87);
        patch::assert_byte(load_weapon_address2, 0xE8)?; // call

        let maria_weapon_assert_address2 = weapon_assert_address2.offset(3);
        // no point asserting since this is still within our search string

        // get pointer to equipped item ID and player character flag
        let player_character_flag_address = std::ptr::read_unaligned(weapon_assert_address.offset(-75) as *const *const u8);
        let sound_param_data_address = std::ptr::read_unaligned(sound_parameter_select_address.offset(-4) as *const *mut u8);
        let inventory_address = std::ptr::read_unaligned(init_inventory_address.offset(8) as *const *mut game::Inventory);
        let main_menu_state_address = std::ptr::read_unaligned(main_menu_dispatch_func.offset(6) as *const *mut i32);
        // this points to the z-component of the vector, so offset -2 to get to the beginning
        let flashlight_vec_address = std::ptr::read_unaligned(flashlight_transform_return_address.offset(-4) as *const *mut f32).offset(-2);
        // make sure the addresses look reasonable
        if !searcher.find_addresses_write(
            &[player_character_flag_address as usize, sound_param_data_address as usize, inventory_address as usize, main_menu_state_address as usize, flashlight_vec_address as usize],
            sh2pc)?.iter().all(|&a| a) {
            bail!("One or more of the following addresses don't look right: player character flag address {:#08X}, sound param data address {:#08X}, inventory address {:#08X}, main menu state address {:#08X}, flashlight vec address {:#08X}",
                player_character_flag_address as usize, sound_param_data_address as usize, inventory_address as usize, main_menu_state_address as usize, flashlight_vec_address as usize,
            );
        };

        // prepare to rearrange weapon data entries
        let weapon_data_ptr_address = weapon_assert_address.offset(169);
        patch::assert_byte(weapon_data_ptr_address, 0xA1)?;

        let weapon_data_address = usize::from_le_bytes(
            std::slice::from_raw_parts(
                weapon_data_ptr_address.offset(1) as *const u8,
                size_of::<usize>(),
            )
            .try_into()?,
        ) as *mut game::WeaponInfo;
        patch::assert_byte(weapon_data_address, 0)?;

        let james_weapon_end = weapon_data_address.offset(9);
        patch::assert_byte(james_weapon_end, 0xFF)?;

        let maria_weapon_cleaver = weapon_data_address.offset(12);
        patch::assert_byte(maria_weapon_cleaver, 17)?;

        let maria_weapon_end = weapon_data_address.offset(13);
        patch::assert_byte(maria_weapon_end, 0xFF)?;

        // messages
        patch::assert_byte(draw_message_func, 0x8B)?; // mov

        let grunt_sound_call_check_address = grunt_sound_call_address.offset(4);
        patch::assert_byte(grunt_sound_call_check_address, 0xE8)?; // call

        let grunt_sound_call = patch::get_call_target(grunt_sound_call_check_address) as usize;

        let james_extra_weapon_sound_logic = james_sounds_switch_default.offset(942);
        patch::assert_byte(james_extra_weapon_sound_logic, 0x80)?; // cmp

        let maria_sound_return = maria_sounds_switch_default.offset(490);
        patch::assert_byte(maria_sound_return, 0x83)?; // add

        let maria_pose_weapon_check = maria_set_pose_address.offset(-0x68);
        patch::assert_byte(maria_pose_weapon_check, 0x0F)?; // movzx

        let james_pose_weapon_check = james_set_pose_address.offset(-7);
        patch::assert_byte(james_pose_weapon_check, 0x0F)?; // movzx

        let maria_flashlight_check = (flashlight_calc + 0x4f) as *const c_void;
        patch::assert_byte(maria_flashlight_check, 0xE8)?; // call

        let flashlight_char_patch1 = flashlight_char_check1_address.offset(4);
        patch::assert_byte(flashlight_char_patch1, 0x3D)?; // cmp

        let flashlight_char_patch2 = flashlight_char_check2_address.offset(4);
        patch::assert_byte(flashlight_char_patch2, 0x3D)?; // cmp

        let flashlight_transform_patch = flashlight_transform_return_address.offset(7);
        // there are 4 bytes of nops after the return, giving us enough room to patch a jump
        // no point asserting since this is still in our search string

        // initialize static data
        GLOBAL.init(player_character_flag_address, weapon_data_address, grunt_sound_call,
            sound_param_data_address, inc_item_count, add_item_to_inventory,
            inventory_address, new_game_plus_flag_func, main_menu_state_address,
            is_flashlight_on, flashlight_vec_address)?;
        CONFIG_INTERFACE.set_funcs(draw_message_func as usize);

        let icon_coords_addr_bytes = (icon_coords_ptr as usize).to_le_bytes();
        let icon_coords_field2_addr_bytes = (icon_coords_ptr.offset(2) as usize).to_le_bytes();
        let icon_coords_end_addr_bytes =
            (icon_coords_ptr.add(size_of_val(&game::ICON_COORDS)) as usize).to_le_bytes();
        let item_ids_addr_bytes = (game::ICON_ITEM_IDS.as_ptr() as usize).to_le_bytes();
        let icon_floats_addr_bytes = (game::ICON_FLOATS.as_ptr() as usize).to_le_bytes();

        // use new icon texture which includes DLC icons
        log::info!(
            "Applying texture name patch at address {:#08X}",
            tex_address as usize
        );
        patch::patch(tex_address.offset(21), b"3")?;

        // always use main scenario icon texture
        log::info!(
            "Applying menu texture patch at address {:#08X}",
            tex_ref_check_address as usize
        );
        patch::patch(tex_ref_check_address, &[0xEB])?;

        // always use main scenario icon dimensions
        log::info!(
            "Applying icon draw patch at address {:#08X}",
            maria_icon_func_address as usize,
        );
        let rel = james_icon_func_address.offset_from(maria_icon_func_address.offset(5)); // +5 for the instruction length
        let mut icon_func_jmp: [u8; 5] = [0xE9, 0, 0, 0, 0];
        icon_func_jmp[1..5].copy_from_slice(&rel.to_le_bytes());
        patch::patch(maria_icon_func_address, &icon_func_jmp)?;

        // use our expanded icon coordinate array
        log::info!(
            "Applying icon coordinate patches at addresses {:#08X}, {:#08X}, {:#08X}, {:#08X}",
            coords_load_address as usize,
            coords_end_load_address as usize,
            coords_index_address1 as usize,
            coords_index_address2 as usize
        );
        patch::patch(coords_load_address.offset(1), &icon_coords_addr_bytes)?;
        patch::patch(
            coords_end_load_address.offset(1),
            &icon_coords_end_addr_bytes,
        )?;
        patch::patch(coords_index_address1.offset(3), &icon_coords_addr_bytes)?;
        patch::patch(
            coords_index_address2.offset(3),
            &icon_coords_field2_addr_bytes,
        )?;

        // use our expanded item ID array
        log::info!(
            "Applying icon item ID patch at address {:#08X}",
            id_check_address as usize
        );
        patch::patch(id_check_address.offset(3), &item_ids_addr_bytes)?;

        // use our expanded icon float array
        log::info!(
            "Applying icon float patches at addresses {:#08X}, {:#08X}",
            float_address1 as usize,
            float_address2 as usize
        );
        patch::patch(float_address1.offset(3), &icon_floats_addr_bytes)?;
        patch::patch(float_address2.offset(3), &icon_floats_addr_bytes)?;

        // increase number of items
        log::info!(
            "Applying item count patch at address {:#08X}",
            item_num_address as usize
        );
        patch::patch(
            item_num_address.offset(2),
            &(game::NUM_ITEMS as u8).to_le_bytes(),
        )?;

        // merge James and Maria's weapon lists into a single contiguous list
        log::info!("Merging weapon lists");

        james_weapon_end.copy_from_nonoverlapping(maria_weapon_cleaver, 1); // replace James' end marker with the cleaver
        maria_weapon_cleaver.copy_from_nonoverlapping(maria_weapon_end, 1); // replace the cleaver with the end marker

        // we now have every weapon in one big list, but we'll still start Maria at the old start of her list
        // so she gets the proper animation for no weapon

        // now we patch the logic
        log::info!(
            "Patching weapon selection logic at addresses {:#08X}, {:#08X}, {:#08X}, {:#08X}, {:#08X}",
            maria_weapon_assert_address as usize,
            weapon_player_check_address2 as usize,
            maria_weapon_assert_address2 as usize,
            load_weapon_address as usize,
            load_weapon_address2 as usize,
        );

        // first, insert nop sled
        patch::patch(maria_weapon_assert_address, &[0x90; 27])?;
        // then, insert call to our function
        patch::patch(maria_weapon_assert_address, &patch::call(maria_weapon_assert_address as usize, find_maria_weapon_info as usize))?;

        patch::patch(weapon_player_check_address2, &[0x90, 0x90])?; // nop out jump to always use James path

        patch::patch(maria_weapon_assert_address2, &[0x90; 29])?;
        patch::patch(maria_weapon_assert_address2, &patch::call(maria_weapon_assert_address2 as usize, find_maria_weapon_info as usize))?;

        // when equipping a weapon, point the weapon to the animation files for the appropriate character
        let zero_memory_address = patch::get_call_target(load_weapon_address);
        patch::set_trampoline(&mut GLOBAL.load_weapon_thunk, 1, override_animation_paths as usize)?;
        let load_weapon_call = patch::call(load_weapon_address as usize, &raw const GLOBAL.load_weapon_thunk as usize);
        patch::set_trampoline(&mut GLOBAL.load_weapon_thunk, 7, zero_memory_address as usize)?;
        patch::patch(load_weapon_address, &load_weapon_call)?;

        // when equipping a weapon, point the weapon to the animation files for the appropriate character
        let zero_memory_address2 = patch::get_call_target(load_weapon_address2);
        patch::set_trampoline(&mut GLOBAL.load_weapon_thunk2, 1, override_animation_paths as usize)?;
        let load_weapon_call2 = patch::call(load_weapon_address2 as usize, &raw const GLOBAL.load_weapon_thunk as usize);
        patch::set_trampoline(&mut GLOBAL.load_weapon_thunk2, 7, zero_memory_address2 as usize)?;
        patch::patch(load_weapon_address2, &load_weapon_call2)?;

        // make sure James allocates enough memory to hold the Colt model
        log::info!("Patching weapon buffer allocation logic at addresses {:#08X}, {:#08X}, {:#08X}", handgun_model_push_address as usize, handgun_model_push_address2 as usize, chainsaw_kg1_push_address as usize);
        patch::patch(handgun_model_push_address, &patch::push(revolver_model_file_address as usize))?;
        patch::patch(handgun_model_push_address2, &patch::push(revolver_model_file_address as usize))?;
        patch::patch(chainsaw_kg1_push_address, &patch::push(revolver_kg1_file_address as usize))?;

        // patch weapon sound logic
        log::info!("Patching weapon sound logic at addresses {:#08X}, {:#08X}, {:#08X}, {:#08X}, {:#08X}", james_action_sounds_switch as usize, maria_action_sounds_switch as usize, james_sounds_switch_default as usize, maria_sounds_switch_default as usize, maria_sound_return as usize);

        // add in weapon sounds for Maria's weapons when wielded by James
        patch::set_trampoline_conditional(&mut GLOBAL.james_action_sound_thunk, 0, james_sounds_switch_default as usize)?;
        patch::set_trampoline(&mut GLOBAL.james_action_sound_thunk, 16, james_sound_check as usize)?;
        let james_sounds_switch2_default = patch::get_conditional_jump_target(james_sounds_switch_default.offset(16));
        patch::set_trampoline(&mut GLOBAL.james_action_sound_thunk, 57, james_sounds_switch2_default as usize)?;
        let james_sounds_original = james_action_sounds_switch.offset(6);
        patch::set_trampoline(&mut GLOBAL.james_action_sound_thunk, 63, james_sounds_original as usize)?;
        let james_sound_check_jump = patch::jmp(james_action_sounds_switch as usize, &raw const GLOBAL.james_action_sound_thunk as usize);
        patch::patch(james_action_sounds_switch, &james_sound_check_jump)?;

        // add in weapon sounds for James' weapons when wielded by Maria
        patch::set_trampoline_conditional(&mut GLOBAL.maria_action_sound_thunk, 0, maria_sounds_switch_default as usize)?;
        patch::set_trampoline(&mut GLOBAL.maria_action_sound_thunk, 16, maria_sound_check as usize)?;
        let maria_sounds_switch2_default = patch::get_conditional_jump_target(maria_sounds_switch_default.offset(6));
        patch::set_trampoline(&mut GLOBAL.maria_action_sound_thunk, 52, maria_sounds_switch2_default as usize)?;
        let maria_sounds_original = maria_action_sounds_switch.offset(6);
        patch::set_trampoline(&mut GLOBAL.maria_action_sound_thunk, 58, maria_sounds_original as usize)?;
        let maria_sound_check_jump = patch::jmp(maria_action_sounds_switch as usize, &raw const GLOBAL.maria_action_sound_thunk as usize);
        patch::patch(maria_action_sounds_switch, &maria_sound_check_jump)?;

        // after Maria's function plays her sounds, jump to the end of James' function, which has extra logic for the chainsaw and hyper spray
        patch::set_trampoline(&mut GLOBAL.maria_sound_return_thunk, 9, james_extra_weapon_sound_logic as usize)?;
        patch::patch(maria_sound_return, &patch::jmp(maria_sound_return as usize, &raw const GLOBAL.maria_sound_return_thunk as usize))?;

        // patch weapon transform logic
        log::info!("Patching equipped weapon transform logic at address {:#08X}", rotate_bone_func_address as usize);

        // apply hard-coded weapon-related transforms to the correct bones when the weapon is being wielded by the other character
        patch::set_trampoline(&mut GLOBAL.rotate_bone_transform_thunk, 20, equipped_weapon_transform_override as usize)?;
        patch::set_trampoline(&mut GLOBAL.rotate_bone_transform_thunk, 32, rotate_bone_func_address.offset(5) as usize)?;
        let rotate_bone_transform_jump = patch::jmp(rotate_bone_func_address as usize, &raw const GLOBAL.rotate_bone_transform_thunk as usize);
        patch::patch(rotate_bone_func_address, &rotate_bone_transform_jump)?;

        // patch UI for configuration
        log::info!("Patching configuration UI at addresses {:#08X}, {:#08X}, {:#08X}", menu_input_loop_start as usize, main_menu_dispatch_func as usize, init_inventory_entry_point as usize);

        // display status message and listen for config menu key on main menu
        patch::set_trampoline(&mut GLOBAL.main_menu_thunk, 0, main_menu_original_call)?;
        patch::set_trampoline(&mut GLOBAL.main_menu_thunk, 6, main_menu_hook as usize)?;
        patch::patch(main_menu_dispatch_func, &patch::call(main_menu_dispatch_func as usize, &raw const GLOBAL.main_menu_thunk as usize))?;

        // don't let the game listen for input while we're in one of our own menus
        let menu_input_loop_default = patch::get_conditional_jump_target(menu_input_loop_start);
        let menu_input_loop_return = menu_input_loop_start.offset(6);
        patch::set_trampoline(&mut GLOBAL.menu_input_loop_thunk, 4, menu_input_loop_hook as usize)?;
        patch::set_trampoline_conditional(&mut GLOBAL.menu_input_loop_thunk, 15, menu_input_loop_return as usize)?;
        patch::set_trampoline(&mut GLOBAL.menu_input_loop_thunk, 21, menu_input_loop_default as usize)?;
        patch::patch(menu_input_loop_start, &patch::jmp(menu_input_loop_start as usize, &raw const GLOBAL.menu_input_loop_thunk as usize))?;

        // display status message and listen for config menu key on pause menu
        let pause_menu_first_call = patch::get_call_target(pause_menu_entry_address);
        patch::set_trampoline(&mut GLOBAL.pause_menu_draw_thunk, 0, pause_menu_first_call as usize)?;
        patch::set_trampoline(&mut GLOBAL.pause_menu_draw_thunk, 5, pause_menu_draw_hook as usize)?;
        patch::patch(pause_menu_entry_address, &patch::call(pause_menu_entry_address as usize, &raw const GLOBAL.pause_menu_draw_thunk as usize))?;

        // patch adding items to player inventory
        log::info!("Patching inventory logic at address {:#08X}", init_inventory_entry_point as usize);
        let init_inventory_jump = patch::jmp(init_inventory_entry_point as usize, init_inventory_hook as usize);
        patch::patch(init_inventory_entry_point, &init_inventory_jump)?;

        // patch item pickup logic
        log::info!("Patching item pickup logic at addresses {:#08X}, {:#08X}", add_item_to_inventory, description_func);

        // hook add item logic so we can replace items overridden by the item mapper
        patch::set_trampoline(&mut GLOBAL.add_item_thunk, 0, item_pickup_inventory_hook as usize)?;
        let item_pickup_inv_call = patch::call(add_item_to_inventory, &raw const GLOBAL.add_item_thunk as usize);
        patch::patch(add_item_to_inventory as *const c_void, &item_pickup_inv_call)?;

        // hook interaction message display so we can display the appropriate message when picking up an item overridden
        // by the item mapper
        patch::set_trampoline(&mut GLOBAL.item_description_thunk, 9, item_pickup_text_hook as usize)?;
        let item_pickup_text_call = patch::call(description_func, &raw const GLOBAL.item_description_thunk as usize);
        // our patch overlaps two instructions totaling 6 bytes, so insert a nop at the end
        let call_padded = [item_pickup_text_call[0], item_pickup_text_call[1], item_pickup_text_call[2], item_pickup_text_call[3], item_pickup_text_call[4], 0x90];
        patch::patch(description_func as *const c_void, &call_padded)?;

        // patch logic for selecting hand pose based on equipped weapon
        log::info!("Patching weapon pose logic at addresses {:#08X}, {:#08X}", maria_pose_weapon_check as usize, james_pose_weapon_check as usize);

        // patch Maria pose logic to account for the possibility that she has a James weapon equipped
        let maria_pose_call = patch::call(maria_pose_weapon_check as usize, get_weapon_index_for_maria_pose as usize);
        // pad with nops to overwrite 7-byte movzx
        let call_padded = [maria_pose_call[0], maria_pose_call[1], maria_pose_call[2], maria_pose_call[3], maria_pose_call[4], 0x90, 0x90];
        patch::patch(maria_pose_weapon_check, &call_padded)?;

        // patch James pose logic to account for the possibility that he has a Maria weapon equipped
        let james_pose_call = patch::call(james_pose_weapon_check as usize, get_weapon_index_for_james_pose as usize);
        let call_padded = [james_pose_call[0], james_pose_call[1], james_pose_call[2], james_pose_call[3], james_pose_call[4], 0x90, 0x90];
        patch::patch(james_pose_weapon_check, &call_padded)?;

        // patches to make the flashlight work for Maria
        log::info!("Patching flashlight checks at addresses {:#08X}, {:#08X}, {:#08X}, {:#08X}", maria_flashlight_check as usize, flashlight_char_patch1 as usize, flashlight_char_patch2 as usize, flashlight_transform_patch as usize);

        // conditionally skip logic that uses a weird flashlight position for Maria, causing the light not to appear
        patch::patch(maria_flashlight_check, &patch::call(maria_flashlight_check as usize, should_use_maria_flashlight_calc as usize))?;

        // patch the first check that only runs the flashlight code for James
        patch::patch(flashlight_char_patch1, &FLASHLIGHT_CHAR_CHECK_PATCH)?;
        let call_address = flashlight_char_patch1.offset(2);
        patch::patch(call_address, &patch::call(call_address as usize, is_player_character as usize))?;

        // patch the second check that only runs the flashlight code for James
        patch::patch(flashlight_char_patch2, &FLASHLIGHT_CHAR_CHECK_PATCH)?;
        let call_address = flashlight_char_patch2.offset(2);
        patch::patch(call_address, &patch::call(call_address as usize, is_player_character as usize))?;

        // rotate the flashlight to point the right way for Maria
        patch::patch(flashlight_transform_patch, &patch::jmp(flashlight_transform_patch as usize, adjust_flashlight_vector as usize))?;
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
            log::logger().flush();
            false
        }
    }
    .into()
}

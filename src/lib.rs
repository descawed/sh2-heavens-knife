#![allow(static_mut_refs)]

use std::ffi::{c_void, CStr};
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::panic;
use std::path::Path;
use std::os::windows::fs::FileExt;

use anyhow::{bail, Result};
use simplelog::{Config, LevelFilter, WriteLogger};
use windows::Win32::Foundation::{BOOL, HMODULE};
use windows::Win32::System::Memory::{
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
};
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::UI::Input::KeyboardAndMouse::*;

mod game;
mod patch;
mod input;
mod config;
mod global;
use global::*;

use game::{Mat4, Vec3, Vec4};

// search strings to find the areas we want to patch
const ICON_TEX_NAME: &[u8] = b"data/pic/etc/itemmenu2.tex\0";
const COLT_ANIM_NAME: &CStr = c"data/chr2/mar/xmar_wpcolt.anm";
const ADDRESS_SET_MSG: &[u8] = b"bg_chara.c:Cant't set character address.";
const DEMO_ANIM_NAME: &[u8] = b"data/demo/jisatsu_a/bos.anm";
const HANDGUN_MODEL_NAME: &[u8] = b"data/chr/wp/wp_handgun.mdl\0";
const REVOLVER_MODEL_NAME: &[u8] = b"data/chr2/wp/wp_colt.mdl\0";
const CHAINSAW_KG1_NAME: &[u8] = b"data/chr/wp/wp_csaw.kg1\0";
const REVOLVER_KG1_NAME: &[u8] = b"data/chr2/wp/wp_colt.kg1\0";
const ANIM_SOURCE_FILE: &[u8] = b"\\projects\\sh2pc\\src\\Chacter\\m3_sc.c";
const MODEL_MAGIC: u32 = 0xffff0003;
const JAMES_ICON_DRAW_LOOP: [u8; 16] = [
    0x66, 0x8B, 0x50, 0x04, 0x66, 0x2B, 0x10, 0x83, 0xC0, 0x3C, 0x66, 0x89, 0x51, 0xFE, 0x66, 0x8B,
];
const MARIA_ICON_DRAW_LOOP: [u8; 16] = [
    0x66, 0x8B, 0x50, 0x04, 0x66, 0x2B, 0x10, 0x83, 0xC0, 0x24, 0x66, 0x89, 0x51, 0xFE, 0x66, 0x8B,
];
const MARIA_WEAPON_ASSERT: [u8; 8] = [0xFF, 0x75, 0x1B, 0x68, 0x17, 0x03, 0x00, 0x00];
const MARIA_WEAPON_ASSERT2: [u8; 8] = [0xFF, 0x75, 0x1D, 0x68, 0x7C, 0x03, 0x00, 0x00];
const CHECK_JAMES_WEAPON_LIST: [u8; 7] = [
    0x31, 0xD2, // xor edx, edx
    0xE9, 0x9F, 0x00, 0x00, 0x00, // jmp +159 bytes
];
const CHECK_JAMES_WEAPON_LIST2: [u8; 7] = [
    0x31, 0xD2, // xor edx, edx
    0xE9, 0x75, 0x00, 0x00, 0x00, // jmp +117 bytes
];
const JAMES_ANIMATION_SIZE1: [u8; 6] = [0x81, 0xC5, 0x00, 0x40, 0x08, 0x00];
const JAMES_ANIMATION_SIZE2: [u8; 6] = [0x81, 0xC1, 0x00, 0x40, 0x08, 0x00];
const ANIMATION_OFFSET_FUNC: [u8; 16] = [
    0x0F, 0xB7, 0x44, 0x24, 0x04, 0x3D, 0x09, 0x02, 0x00, 0x00, 0x0F, 0x8F, 0xBC, 0x00, 0x00, 0x00
];
const ANIMATION_READ_FUNC: [u8; 16] = [
    0x56, 0x8B, 0x74, 0x24, 0x08, 0x0F, 0xBF, 0x46, 0x10, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0x83, 0xF8,
];
/*const DRAW_MESSAGE_FUNC: [u8; 19] = [
    0x8B, 0x74, 0x24, 0x30, 0x8B, 0x7C, 0x24, 0x2C, 0x8B, 0x6C, 0x24, 0x28, 0x8B, 0x54, 0x24, 0x24, 0x8D, 0x46, 0x02,
];*/
const DRAW_MESSAGE_FUNC: [u8; 9] = [
    0x8B, 0x44, 0x24, 0x04, 0x85, 0xC0, 0x75, 0x06, 0xA3,
];
const HIT_ANIMATION_FUNC: [u8; 11] = [
    0x0E, 0x01, 0x56, 0x75, 0x44, 0x81, 0xFF, 0x21, 0x4E, 0x00, 0x00,
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
/*const DIFFICULTY_SELECTION: [u8; 7] = [
    0x03, 0x0F, 0x87, 0xE6, 0x01, 0x00, 0x00,
];*/
const DIFFICULTY_SELECTION: [u8; 10] = [
    0x68, 0x3C, 0xFF, 0xFF, 0xFF, 0xBF, 0x05, 0x00, 0x00, 0x00,
];
const DRAW_DARKENED_BACKGROUND: [u8; 5] = [
    0xC0, 0xFF, 0xFF, 0xFF, 0x1B,
];
const INIT_INVENTORY: [u8; 7] = [
    0x00, 0x00, 0x10, 0x00, 0x6A, 0x15, 0x89,
];
// there are two occurrences of this pattern, but they both come immediately after a call to the
// function we're trying to intercept
const AFTER_DESCRIPTION_CALL: [u8; 12] = [
    0x6A, 0x00, 0x68, 0x00, 0x00, 0x80, 0x3F, 0x68, 0x21, 0x2B, 0x00, 0x00,
];

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ControlSelection {
    Character,
    Bone,
    MaxCopy,
    Field,
}

impl ControlSelection {
    const fn next(self) -> Self {
        match self {
            ControlSelection::Character => ControlSelection::Bone,
            ControlSelection::Bone => ControlSelection::MaxCopy,
            ControlSelection::MaxCopy => ControlSelection::Field,
            ControlSelection::Field => ControlSelection::Character,
        }
    }

    const fn prev(self) -> Self {
        match self {
            ControlSelection::Character => ControlSelection::Field,
            ControlSelection::Bone => ControlSelection::Character,
            ControlSelection::MaxCopy => ControlSelection::Bone,
            ControlSelection::Field => ControlSelection::MaxCopy,
        }
    }
}

#[derive(Debug)]
struct ControlPanel {
    keyboard: input::Keyboard,
    is_james: bool,
    debug_bone_index: usize,
    debug_field: game::DebugField,
    selection: ControlSelection,
    is_enabled: bool,
    max_copy_index: usize,
    message: game::Message,
    draw_message_ptr: Option<unsafe extern "C" fn(*const u8)>,
    is_highlighting: bool,
    do_dump_animation: bool,
}

impl ControlPanel {
    pub const fn new() -> Self {
        Self {
            keyboard: input::Keyboard::new(),
            is_james: false,
            debug_bone_index: 0,
            debug_field: game::DebugField::None,
            selection: ControlSelection::Character,
            is_enabled: false,
            max_copy_index: game::MARIA_NUM_BONES - 1,
            message: game::Message::new(),
            draw_message_ptr: None,
            is_highlighting: false,
            do_dump_animation: false,
        }
    }

    pub fn set_draw_message_ptr(&mut self, draw_message_ptr: *const c_void) {
        self.draw_message_ptr = Some(unsafe { std::mem::transmute(draw_message_ptr) });
    }

    pub unsafe fn print(&self, data: *const u8) {
        self.draw_message_ptr.unwrap()(data);
    }

    pub unsafe fn print_message(&self, msg: &game::Message) {
        self.print(msg.data());
    }

    pub unsafe fn print_str(&mut self, text: &str) {
        self.message.set_message_from_str(text);
        self.print(self.message.data());
    }

    pub unsafe fn clear_message(&mut self) {
        // draw an empty string to clear the text on the screen, then call with a null pointer to
        // clear the reference to it
        self.print_str("");
        self.print(std::ptr::null());
    }

    pub const fn check_dump_animation(&mut self) -> bool {
        if self.do_dump_animation {
            self.do_dump_animation = false;
            return true;
        }
        false
    }

    pub const fn is_enabled(&self) -> bool {
        self.is_enabled
    }

    pub const fn get_settings(&self) -> Option<(bool, usize, game::DebugField, usize, usize)> {
        if self.is_enabled {
            Some((self.is_james, self.debug_bone_index, self.debug_field, self.max_copy_index,
                  if self.is_highlighting {
                      self.debug_bone_index
                  } else {
                      usize::MAX
                  }
            ))
        } else {
            None
        }
    }

    pub const fn num_bones(&self) -> usize {
        if self.is_james {
            game::JAMES_NUM_BONES
        } else {
            game::MARIA_NUM_BONES
        }
    }

    const fn toggle_character(&mut self) {
        self.is_james = !self.is_james;
        if self.debug_bone_index >= self.num_bones() {
            self.debug_bone_index = 0;
        }
    }

    pub fn update_settings(&mut self) -> Option<(bool, usize, game::DebugField, usize, usize)> {
        self.keyboard.update().expect("keyboard state update should not fail");

        if self.keyboard.is_key_down_once(VK_F7) {
            self.is_enabled = !self.is_enabled;
            log::debug!("Control panel toggled {}", if self.is_enabled { "on" } else { "off" });
            if !self.is_enabled {
                // on disable, clear any message we were displaying
                unsafe { self.clear_message() };
            }
        }

        if !self.is_enabled {
            return None;
        }

        if self.keyboard.is_key_down_once(VK_LEFT) {
            self.selection = self.selection.prev();
        } else if self.keyboard.is_key_down_once(VK_RIGHT) {
            self.selection = self.selection.next();
        } else if self.keyboard.is_key_down_once(VK_UP) {
            match self.selection {
                ControlSelection::Character => {
                    self.toggle_character();
                }
                ControlSelection::Bone => {
                    self.debug_bone_index = (self.debug_bone_index + 1) % self.num_bones();
                }
                ControlSelection::MaxCopy => {
                    self.max_copy_index = (self.max_copy_index + 1) % game::MARIA_NUM_BONES;
                }
                ControlSelection::Field => {
                    self.debug_field = self.debug_field.next();
                }
            }
        } else if self.keyboard.is_key_down_once(VK_DOWN) {
            match self.selection {
                ControlSelection::Character => {
                    self.toggle_character();
                }
                ControlSelection::Bone => {
                    self.debug_bone_index = if self.debug_bone_index > 0 {
                        self.debug_bone_index - 1
                    } else {
                        self.num_bones() - 1
                    };
                }
                ControlSelection::MaxCopy => {
                    self.max_copy_index = if self.max_copy_index > 0 {
                        self.max_copy_index - 1
                    } else {
                        game::MARIA_NUM_BONES - 1
                    };
                }
                ControlSelection::Field => {
                    self.debug_field = self.debug_field.prev();
                }
            }
        } else if self.keyboard.is_key_down_once(VK_H) {
            self.is_highlighting = !self.is_highlighting;
        } else if self.keyboard.is_key_down_once(VK_K) {
            self.do_dump_animation = true;
        }

        self.get_settings()
    }

    pub fn display(&mut self, debug_text: &str) {
        if !self.is_enabled {
            return;
        }

        self.message.set_message(|builder| {
            use game::ControlCode;

            if !debug_text.is_empty() {
                builder.add_text(debug_text);
                builder.add_control_code(ControlCode::LineBreak);
            }

            if self.selection == ControlSelection::Character {
                builder.add_control_code(ControlCode::Blue);
            }

            builder.add_text(if self.is_james { "Char: J" } else { "Char: M" });

            if self.selection == ControlSelection::Character {
                builder.add_control_code(ControlCode::White);
            }

            builder.add_text(" | ");

            if self.selection == ControlSelection::Bone {
                builder.add_control_code(ControlCode::Blue);
            }

            builder.add_text(&format!("Bone: {:>2}", self.debug_bone_index));

            if self.selection == ControlSelection::Bone {
                builder.add_control_code(ControlCode::White);
            }

            builder.add_text(" | ");

            if self.selection == ControlSelection::MaxCopy {
                builder.add_control_code(ControlCode::Blue);
            }

            builder.add_text(&format!("Copy Idx: {:>2}", self.max_copy_index));

            if self.selection == ControlSelection::MaxCopy {
                builder.add_control_code(ControlCode::White);
            }

            builder.add_text(" | ");

            if self.selection == ControlSelection::Field {
                builder.add_control_code(ControlCode::Blue);
            }

            builder.add_text(&format!("Field: {}", self.debug_field.get_name()));
        });

        unsafe { self.print_message(&self.message) };
    }
}

static mut GLOBAL: PersistentData = PersistentData::new();
static mut CONTROL_PANEL: ControlPanel = ControlPanel::new();
static mut CONFIG_INTERFACE: config::UserInterface = config::UserInterface::new(config::Config::new());

unsafe fn is_maria_player(character_id: i16) -> bool {
    PersistentData::is_player_id(character_id) && GLOBAL.is_player_maria()
}

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

unsafe extern "C" fn difficulty_select_hook() -> u32 {
    CONFIG_INTERFACE.show(!GLOBAL.is_player_maria());
    if CONFIG_INTERFACE.has_focus() {
        1
    } else {
        0
    }
}

unsafe extern "C" fn init_inventory_hook() {
    // don't override the items that we add ourselves
    GLOBAL.disable_item_override();

    let inventory = GLOBAL.inventory();
    inventory.clear();

    let is_maria = GLOBAL.is_player_maria();
    match CONFIG_INTERFACE.starting_inventory(!is_maria) {
        Some(starting_inventory) => {
            for (item_id, count) in starting_inventory.iter_items() {
                if let Some(count) = count {
                    // we do this so we can override add_item_to_inventory's count logic
                    log::debug!("Adding {}x {} to inventory", count, game::item_name(item_id));
                    inventory.add_item(item_id);
                    inventory.set_item_count(item_id, count);
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

            inventory.equipped_item = starting_inventory.equipped_item();
        }
        None => {
            // assign normal starting inventory
            if is_maria {
                inventory.add_item(game::ITEM_ID_REVOLVER);
                inventory.set_item_count(game::ITEM_ID_REVOLVER, 1);
                GLOBAL.inc_item_count();
            } else {
                inventory.add_item(game::ITEM_ID_PHOTO_OF_MARY);
                GLOBAL.add_item_to_inventory(game::ITEM_ID_LETTER_FROM_MARY);
            }
        }
    }

    if is_maria {
        // Maria must start with the revolver equipped, otherwise the game crashes
        inventory.equipped_item = game::ITEM_ID_REVOLVER;
    } else {
        // I don't know what these do, but the original code sets them for James, so we will, too
        inventory.unk26 = 1;
        inventory.unk27 = 1;
        inventory.unk28 = 10;
    }

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

fn open_log() -> Result<()> {
    let log_file = File::create("sh2hvnknf.log")?;
    WriteLogger::init(LevelFilter::Debug, Config::default(), log_file)?;
    panic::set_hook(Box::new(|info| {
        let msg = if let Some(msg) = info.payload().downcast_ref::<&str>() {
            *msg
        } else if let Some(msg) = info.payload().downcast_ref::<String>() {
            msg.as_str()
        } else {
            "unknown"
        };
        let (file, line) = info
            .location()
            .map_or(("unknown", 0), |l| (l.file(), l.line()));
        log::error!("Panic in {} on line {}: {}", file, line, msg);
        let logger = log::logger();
        logger.flush();
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

    let [
        Some(tex_address),
        Some(colt_anim_address),
        Some(address_set_msg_address),
        Some(demo_anim_address),
        Some(anim_source_file_address),
        Some(handgun_model_name_address),
        Some(revolver_model_name_address),
        Some(chainsaw_kg1_name_address),
        Some(revolver_kg1_name_address),
    ] = searcher.find_bytes(&[ICON_TEX_NAME, COLT_ANIM_NAME.to_bytes(), ADDRESS_SET_MSG, DEMO_ANIM_NAME, ANIM_SOURCE_FILE, HANDGUN_MODEL_NAME, REVOLVER_MODEL_NAME, CHAINSAW_KG1_NAME, REVOLVER_KG1_NAME], Some(PAGE_READONLY), sh2pc)? else {
        bail!("Failed to find read-only data");
    };
    let colt_anim_address = colt_anim_address as usize;
    let address_set_msg_address = address_set_msg_address as usize;
    let demo_anim_address = demo_anim_address as usize;
    let anim_source_file_address = anim_source_file_address as usize;
    let handgun_model_name_address = handgun_model_name_address as usize;
    let revolver_model_name_address = revolver_model_name_address as usize;
    let chainsaw_kg1_name_address = chainsaw_kg1_name_address as usize;
    let revolver_kg1_name_address = revolver_kg1_name_address as usize;
    log::debug!(
        "Found item menu texture path at {:#08X}, colt animation path at {:#08X}, address set msg at {:#08X}, demo anim address at {:#08X}, anim source file address at {:#08X}, handgun model name at {:#08X}, revolver model name at {:#08X}, chainsaw kg1 name at {:#08X}, revolver kg1 name at {:#08X}",
        tex_address as usize, colt_anim_address, address_set_msg_address, demo_anim_address, anim_source_file_address, handgun_model_name_address, revolver_model_name_address, chainsaw_kg1_name_address, revolver_kg1_name_address,
    );

    let mut menu_data: [u8; 16] = [0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 1, 0, 0, 0];
    menu_data[..4].copy_from_slice(&(tex_address as usize).to_le_bytes());
    // we already rely on our icon coords game constant being a binary match for the exe's icon
    // coords, so let's just directly use it as our search data as well
    let icon_coords_ptr = game::ICON_COORDS.as_ptr() as *const u8;
    let icon_coords_buf = unsafe { std::slice::from_raw_parts(icon_coords_ptr, 12) };

    let [
        Some(menu_address),
        Some(icon_coord_address),
        Some(colt_anim_file_address),
        Some(demo_anim_file_address),
        Some(handgun_model_file_address),
        Some(revolver_model_file_address),
        Some(chainsaw_kg1_file_address),
        Some(revolver_kg1_file_address),
    ] = searcher.find_bytes(
        &[
            &menu_data, icon_coords_buf, &colt_anim_address.to_le_bytes(), &demo_anim_address.to_le_bytes(), &handgun_model_name_address.to_le_bytes(), &revolver_model_name_address.to_le_bytes(), &chainsaw_kg1_name_address.to_le_bytes(), &revolver_kg1_name_address.to_le_bytes(),
        ],
        Some(PAGE_READWRITE | PAGE_WRITECOPY),
        sh2pc,
    )? else {
        bail!("Failed to find .data values");
    };
    log::debug!(
        "Found menu data at {:#08X}, icon coords at {:#08X}, Colt anim file at {:#08X}, demo anim file at {:#08X}, handgun model file at {:#08X}, revolver model file at {:#08X}, chainsaw kg1 file at {:#08X}, revolver kg1 file at {:#08X}",
        menu_address as usize,
        icon_coord_address as usize,
        colt_anim_file_address as usize,
        demo_anim_file_address as usize,
        handgun_model_file_address as usize,
        revolver_model_file_address as usize,
        chainsaw_kg1_file_address as usize,
        revolver_kg1_file_address as usize,
    );

    // Maria vs James texture check
    let mut tex_ref_data: [u8; 7] = [0x50, 0x68, 0, 0, 0, 0, 0xE8];
    tex_ref_data[2..6].copy_from_slice(&(menu_address as usize).to_le_bytes());
    // reference to Colt anim when allocating buffers
    let colt_anim_data = patch::push(colt_anim_file_address as usize);
    // message about failing to set addresses shortly after calling SetCharacterAddresses
    let address_set_msg_data = patch::push(address_set_msg_address);
    // animation referenced near a reference to the player pointer
    let demo_anim_data = patch::push(demo_anim_file_address as usize);
    // reference to handgun model used to determine weapon model buffer size
    let handgun_model_data = patch::push(handgun_model_file_address as usize);
    // reference to chainsaw shadow used to determine weapon shadow buffer size
    let chainsaw_kg1_data = patch::push(chainsaw_kg1_file_address as usize);

    let source_bytes = anim_source_file_address.to_le_bytes();
    let anim_source_file_data = [
        0x68, 0x2B, 0x08, 0x00, 0x00, // push 2091
        0x68, source_bytes[0], source_bytes[1], source_bytes[2], source_bytes[3], // push <filename>
    ];

    let [
        Some(tex_ref_call_address),
        Some(colt_anim_push_address),
        Some(address_set_msg_push_address),
        Some(demo_anim_push_address),
        Some(anim_source_file_push_address),
        Some(handgun_model_push_address),
        Some(chainsaw_kg1_push_address),
        Some(james_icon_draw_loop_address),
        Some(maria_icon_draw_loop_address),
        Some(weapon_assert_address),
        Some(weapon_assert_address2),
        Some(james_anim_address1),
        Some(james_anim_address2),
        Some(animation_offset_func),
        Some(animation_read_func),
        Some(draw_message_func),
        Some(hit_animation_func),
        Some(james_action_sounds_address),
        Some(maria_action_sounds_address),
        Some(grunt_sound_call_address),
        Some(sound_parameter_select_address),
        Some(rotate_bone_transform_address),
        Some(difficulty_selection_address),
        Some(darken_background_address),
        Some(init_inventory_address),
        Some(after_description_call_address),
    ] = searcher.find_bytes(
        &[
            &tex_ref_data,
            &colt_anim_data,
            &address_set_msg_data,
            &demo_anim_data,
            &anim_source_file_data,
            &handgun_model_data,
            &chainsaw_kg1_data,
            &JAMES_ICON_DRAW_LOOP,
            &MARIA_ICON_DRAW_LOOP,
            &MARIA_WEAPON_ASSERT,
            &MARIA_WEAPON_ASSERT2,
            &JAMES_ANIMATION_SIZE1,
            &JAMES_ANIMATION_SIZE2,
            &ANIMATION_OFFSET_FUNC,
            &ANIMATION_READ_FUNC,
            &DRAW_MESSAGE_FUNC,
            &HIT_ANIMATION_FUNC,
            &JAMES_ACTION_SOUNDS,
            &MARIA_ACTION_SOUNDS,
            &GRUNT_SOUND_CALL,
            &SOUND_PARAMETER_SELECT,
            &ROTATE_BONE_TRANSFORM,
            &DIFFICULTY_SELECTION,
            &DRAW_DARKENED_BACKGROUND,
            &INIT_INVENTORY,
            &AFTER_DESCRIPTION_CALL,
        ],
        Some(PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE),
        sh2pc,
    )? else {
        bail!("Failed to find code addresses");
    };
    log::debug!(
        "Found tex ref data at {:#08X}, colt anim push at {:#08X}, address set msg push at {:#08X}, demo anim push at {:#08X}, anim source push at {:#08X}, James icon draw loop at {:#08X}, Maria icon draw loop at {:#08X}, weapon assert at {:#08X}, weapon assert 2 at {:#08X}, \
        James anim1 at {:#08X}, James anim2 at {:#08X}, anim offset at {:#08X}, anim read at {:#08X}, draw msg call at {:#08X}, hit animation func at {:#08X}, James action sounds at {:#08X}, Maria action sounds at {:#08X}, melee grunt sound call at {:#08X}, sound param select at {:#08X}, \
        handgun model push at {:#08X}, chainsaw kg1 push at {:#08X}, rotate bone transform at {:#08X}, difficulty selection at {:#08X}, darkened background at {:#08X}, init inventory at {:#08X}, after description call at {:#08X}",
        tex_ref_call_address as usize,
        colt_anim_push_address as usize,
        address_set_msg_push_address as usize,
        demo_anim_push_address as usize,
        anim_source_file_push_address as usize,
        james_icon_draw_loop_address as usize,
        maria_icon_draw_loop_address as usize,
        weapon_assert_address as usize,
        weapon_assert_address2 as usize,
        james_anim_address1 as usize,
        james_anim_address2 as usize,
        animation_offset_func as usize,
        animation_read_func as usize,
        draw_message_func as usize,
        hit_animation_func as usize,
        james_action_sounds_address as usize,
        maria_action_sounds_address as usize,
        grunt_sound_call_address as usize,
        sound_parameter_select_address as usize,
        handgun_model_push_address as usize,
        chainsaw_kg1_push_address as usize,
        rotate_bone_transform_address as usize,
        difficulty_selection_address as usize,
        darken_background_address as usize,
        init_inventory_address as usize,
        after_description_call_address as usize,
    );

    unsafe {
        // sanity checks
        let tex_ref_check_address = tex_ref_call_address.offset(-27);
        patch::assert_byte(tex_ref_check_address, 0x75)?; // jnz

        let colt_anim_check_address = colt_anim_push_address.offset(5);
        patch::assert_byte(colt_anim_check_address, 0xE8)?; // call

        let character_files_check_address = colt_anim_push_address.offset(-217);
        patch::assert_byte(character_files_check_address, 0xB8)?; // mov

        let character_files_end_check_address = character_files_check_address.offset(14);
        patch::assert_byte(character_files_end_check_address, 0x3D)?; // cmp

        let address_set_msg_check_address = address_set_msg_push_address.offset(-12);
        patch::assert_byte(address_set_msg_check_address, 0xE8)?; // call

        let demo_anim_check_address = demo_anim_push_address.offset(27);
        patch::assert_byte(demo_anim_check_address, 0xA1)?; // mov

        let anim_frame_size_check_address = anim_source_file_push_address.offset(-256);
        patch::assert_byte(anim_frame_size_check_address, 0xE8)?; // call

        let james_action_sounds_switch = james_action_sounds_address.offset(4);
        patch::assert_byte(james_action_sounds_switch, 0x0F)?; // ja

        let maria_action_sounds_switch = maria_action_sounds_address.offset(7);
        patch::assert_byte(maria_action_sounds_switch, 0x0F)?; // ja

        let handgun_model_push_address2 = handgun_model_push_address.offset(410);
        patch::assert_byte(handgun_model_push_address2, 0x68)?; // push

        let rotate_bone_func_address = rotate_bone_transform_address.offset(-42);
        patch::assert_byte(rotate_bone_func_address, 0x83)?; // sub

        //let difficulty_select_call_address = difficulty_selection_address.offset(-7);
        let difficulty_select_call_address = difficulty_selection_address.offset(-26);
        patch::assert_byte(difficulty_select_call_address, 0xE8)?; // call

        let darkened_background_entry_point = darken_background_address.offset(-49);
        patch::assert_byte(darkened_background_entry_point, 0x51)?; // push

        let add_inventory_call_address = init_inventory_address.offset(12);
        patch::assert_byte(add_inventory_call_address, 0xE8)?; // call

        let inc_item_count_address = init_inventory_address.offset(-51);
        patch::assert_byte(inc_item_count_address, 0xE8)?; // call

        let init_inventory_entry_point = init_inventory_address.offset(-85);
        patch::assert_byte(init_inventory_entry_point, 0x6A)?; // push

        let description_call_address = after_description_call_address.offset(-5);
        patch::assert_byte(description_call_address, 0xE8)?; // call

        let request_file_size_address = patch::get_call_target(colt_anim_check_address) as usize;
        let set_character_addresses_address = patch::get_call_target(address_set_msg_check_address) as usize;
        let get_character_frame_size_address = patch::get_call_target(anim_frame_size_check_address) as usize;
        let james_sounds_switch_default = patch::get_conditional_jump_target(james_action_sounds_switch);
        let maria_sounds_switch_default = patch::get_conditional_jump_target(maria_action_sounds_switch);
        let difficulty_select_original_call = patch::get_call_target(difficulty_select_call_address) as usize;
        let add_item_to_inventory = patch::get_call_target(add_inventory_call_address) as usize;
        let inc_item_count = patch::get_call_target(inc_item_count_address) as usize;
        let description_func = patch::get_call_target(description_call_address) as usize;
        // make sure the addresses look reasonable
        if !searcher.find_addresses_exec(
            &[
                request_file_size_address,
                set_character_addresses_address,
                get_character_frame_size_address,
                james_sounds_switch_default as usize,
                maria_sounds_switch_default as usize,
                difficulty_select_original_call,
                add_item_to_inventory,
                inc_item_count,
                description_func,
            ],
            sh2pc)?.iter().all(|f| *f) {
            bail!("One or more of RequestFileSize() @ {:#08X}, SetCharacterAddresses() @ {:#08X}, GetCharacterFrameSize @ {:#08X}, James sound switch default {:#08X}, Maria sound switch default {:#08X} difficulty select call {:#08X}, add inventory {:#08X}, inc item count {:#08X}, description func {:#08X} don't look right",
                request_file_size_address, set_character_addresses_address, get_character_frame_size_address, james_sounds_switch_default as usize, maria_sounds_switch_default as usize, difficulty_select_original_call, add_item_to_inventory, inc_item_count, description_func);
        };

        let get_character_buffers_call_address = (set_character_addresses_address + 0x13) as *const c_void;
        patch::assert_byte(get_character_buffers_call_address, 0xE8)?; // call

        let new_game_plus_flag_call = (add_item_to_inventory + 64) as *const c_void;
        patch::assert_byte(new_game_plus_flag_call, 0xE8)?; // call

        let get_character_buffers_address = patch::get_call_target(get_character_buffers_call_address) as usize;
        let new_game_plus_flag_func = patch::get_call_target(new_game_plus_flag_call) as usize;
        // make sure the addresses look reasonable
        let [true, true] = searcher.find_addresses_exec(&[get_character_buffers_address, new_game_plus_flag_func], sh2pc)? else {
            bail!("GetCharacterBuffers() address {:#08X} or SetNewGamePlusFlag() address {:#08X} doesn't look right", get_character_buffers_address, new_game_plus_flag_func);
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
        let equipped_item_id_address = std::ptr::read_unaligned(weapon_assert_address.offset(-43) as *const *mut i8);
        let player_character_flag_address = std::ptr::read_unaligned(weapon_assert_address.offset(-75) as *const *const u8);
        let character_files_address = std::ptr::read_unaligned(character_files_check_address.offset(1) as *const *mut game::CharacterFiles);
        let character_files_end_address = std::ptr::read_unaligned(character_files_end_check_address.offset(1) as *const *mut game::CharacterFiles);
        let player_ptr_address = std::ptr::read_unaligned(demo_anim_check_address.offset(1) as *const *mut *mut game::Character);
        let sound_param_data_address = std::ptr::read_unaligned(sound_parameter_select_address.offset(-4) as *const *mut u8);
        let inventory_address = std::ptr::read_unaligned(init_inventory_address.offset(8) as *const *mut game::Inventory);
        // make sure the addresses look reasonable
        if !searcher.find_addresses_write(
            &[equipped_item_id_address as usize, player_character_flag_address as usize, character_files_address as usize, character_files_end_address as usize, player_ptr_address as usize, sound_param_data_address as usize, inventory_address as usize]
            , sh2pc)?.iter().all(|&a| a) {
            bail!("One or more of the following addresses don't look right: equipped item ID address {:#08X}, player character flag address {:#08X}, character files address {:#08X}, character files end address {:#08X}, player pointer address {:#08X}, sound param data address {:#08X}, inventory address {:#08X}",
                equipped_item_id_address as usize, player_character_flag_address as usize,character_files_address as usize, character_files_end_address as usize, player_ptr_address as usize, sound_param_data_address as usize, inventory_address as usize,
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

        // initialize static data
        GLOBAL.init(equipped_item_id_address, player_character_flag_address, request_file_size_address,
            get_character_buffers_address, character_files_address, character_files_end_address,
            player_ptr_address, get_character_frame_size_address, weapon_data_address, grunt_sound_call,
            sound_param_data_address, draw_message_func as usize, inc_item_count, add_item_to_inventory,
            inventory_address, new_game_plus_flag_func).expect("initialization should not fail");
        CONTROL_PANEL.set_draw_message_ptr(draw_message_func);
        CONFIG_INTERFACE.set_funcs(draw_message_func as usize, darkened_background_entry_point as usize);

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
        patch::patch(maria_weapon_assert_address, &CHECK_JAMES_WEAPON_LIST)?;
        patch::patch(weapon_player_check_address2, &[0x90, 0x90])?; // nop out jump to always use James path
        patch::patch(maria_weapon_assert_address2, &CHECK_JAMES_WEAPON_LIST2)?;

        let zero_memory_address = patch::get_call_target(load_weapon_address);
        patch::set_trampoline(&mut GLOBAL.load_weapon_thunk, 1, override_animation_paths as usize)?;
        let load_weapon_call = patch::call(load_weapon_address as usize, &raw const GLOBAL.load_weapon_thunk as usize);
        patch::set_trampoline(&mut GLOBAL.load_weapon_thunk, 7, zero_memory_address as usize)?;
        patch::patch(load_weapon_address, &load_weapon_call)?;

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
        log::info!("Patching weapon sound logic at addresses {:#08X}, {:#08X}, {:#08X}, {:#08X}", james_action_sounds_switch as usize, maria_action_sounds_switch as usize, james_sounds_switch_default as usize, maria_sounds_switch_default as usize);

        patch::set_trampoline_conditional(&mut GLOBAL.james_action_sound_thunk, 0, james_sounds_switch_default as usize)?;
        patch::set_trampoline(&mut GLOBAL.james_action_sound_thunk, 16, james_sound_check as usize)?;
        let james_sounds_switch2_default = patch::get_conditional_jump_target(james_sounds_switch_default.offset(16));
        patch::set_trampoline(&mut GLOBAL.james_action_sound_thunk, 57, james_sounds_switch2_default as usize)?;
        let james_sounds_original = james_action_sounds_switch.offset(6);
        patch::set_trampoline(&mut GLOBAL.james_action_sound_thunk, 63, james_sounds_original as usize)?;
        let james_sound_check_jump = patch::jmp(james_action_sounds_switch as usize, &raw const GLOBAL.james_action_sound_thunk as usize);
        patch::patch(james_action_sounds_switch, &james_sound_check_jump)?;

        patch::set_trampoline_conditional(&mut GLOBAL.maria_action_sound_thunk, 0, maria_sounds_switch_default as usize)?;
        patch::set_trampoline(&mut GLOBAL.maria_action_sound_thunk, 16, maria_sound_check as usize)?;
        let maria_sounds_switch2_default = patch::get_conditional_jump_target(maria_sounds_switch_default.offset(6));
        patch::set_trampoline(&mut GLOBAL.maria_action_sound_thunk, 52, maria_sounds_switch2_default as usize)?;
        let maria_sounds_original = maria_action_sounds_switch.offset(6);
        patch::set_trampoline(&mut GLOBAL.maria_action_sound_thunk, 58, maria_sounds_original as usize)?;
        let maria_sound_check_jump = patch::jmp(maria_action_sounds_switch as usize, &raw const GLOBAL.maria_action_sound_thunk as usize);
        patch::patch(maria_action_sounds_switch, &maria_sound_check_jump)?;

        // patch weapon transform logic
        log::info!("Patching equipped weapon transform logic at address {:#08X}", rotate_bone_func_address as usize);

        patch::set_trampoline(&mut GLOBAL.rotate_bone_transform_thunk, 20, equipped_weapon_transform_override as usize)?;
        patch::set_trampoline(&mut GLOBAL.rotate_bone_transform_thunk, 32, rotate_bone_func_address.offset(5) as usize)?;
        let rotate_bone_transform_jump = patch::jmp(rotate_bone_func_address as usize, &raw const GLOBAL.rotate_bone_transform_thunk as usize);
        patch::patch(rotate_bone_func_address, &rotate_bone_transform_jump)?;

        // patch UI for configuration
        log::info!("Patching configuration UI at address {:#08X}", difficulty_select_call_address as usize);
        patch::set_trampoline(&mut GLOBAL.difficulty_select_thunk, 1, difficulty_select_hook as usize)?;
        patch::set_trampoline(&mut GLOBAL.difficulty_select_thunk, 15, difficulty_select_original_call)?;
        let difficulty_select_call = patch::call(difficulty_select_call_address as usize, &raw const GLOBAL.difficulty_select_thunk as usize);
        patch::patch(difficulty_select_call_address, &difficulty_select_call)?;

        // patch adding items to player inventory
        log::info!("Patching inventory logic at address {:#08X}", init_inventory_entry_point as usize);
        let init_inventory_jump = patch::jmp(init_inventory_entry_point as usize, init_inventory_hook as usize);
        patch::patch(init_inventory_entry_point, &init_inventory_jump)?;

        // patch item pickup logic
        log::info!("Patching item pickup logic at addresses {:#08X}, {:#08X}", add_item_to_inventory, description_func);

        patch::set_trampoline(&mut GLOBAL.add_item_thunk, 0, item_pickup_inventory_hook as usize)?;
        let item_pickup_inv_call = patch::call(add_item_to_inventory, &raw const GLOBAL.add_item_thunk as usize);
        patch::patch(add_item_to_inventory as *const c_void, &item_pickup_inv_call)?;

        patch::set_trampoline(&mut GLOBAL.item_description_thunk, 9, item_pickup_text_hook as usize)?;
        let item_pickup_text_call = patch::call(description_func, &raw const GLOBAL.item_description_thunk as usize);
        // our patch overlaps two instructions totaling 6 bytes, so insert a nop at the end
        let call_padded = [item_pickup_text_call[0], item_pickup_text_call[1], item_pickup_text_call[2], item_pickup_text_call[3], item_pickup_text_call[4], 0x90];
        patch::patch(description_func as *const c_void, &call_padded)?;
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
            let logger = log::logger();
            logger.flush();
            false
        }
    }
    .into()
}

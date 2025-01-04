#![allow(static_mut_refs)]

use std::ffi::c_void;
use std::fs::File;
use std::panic;
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

// search strings to find the areas we want to patch
const ICON_TEX_NAME: &[u8] = b"data/pic/etc/itemmenu2.tex";
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

    pub const fn is_enabled(&self) -> bool {
        self.is_enabled
    }

    pub const fn get_settings(&self) -> Option<(bool, usize, game::DebugField, usize)> {
        if self.is_enabled {
            Some((self.is_james, self.debug_bone_index, self.debug_field, self.max_copy_index))
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

    pub fn update_settings(&mut self) -> Option<(bool, usize, game::DebugField, usize)> {
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

#[repr(C)]
struct JamesAnimationContainer(pub [game::AnimationRecord; 41]);

impl JamesAnimationContainer {
    const fn new() -> Self {
        Self([
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
            game::AnimationRecord::new(),
        ])
    }

    fn init(&mut self, skeleton: &[i8]) {
        for i in 0..self.0.len() {
            let next_index = i + 1;
            if next_index < self.0.len() {
                self.0[i].next = &raw mut self.0[next_index];
            } else {
                self.0[i].next = std::ptr::null_mut();
            }

            let parent_index = skeleton[i];
            if parent_index >= 0 {
                let parent_index = parent_index as usize;
                self.0[i].parent = &raw mut self.0[parent_index];
            } else {
                self.0[i].parent = std::ptr::null_mut();
            }
        }
    }

    unsafe fn copy_to_maria(&self, mut maria_animation: *mut game::AnimationRecord) {
        let max_copy_index = match CONTROL_PANEL.get_settings() {
            Some((_, _, game::DebugField::None, max_copy_index)) => max_copy_index,
            Some((is_james, bone_index, debug_field, max_copy_index)) => {
                let record = if is_james {
                    &self.0[bone_index]
                } else {
                    maria_animation.offset(bone_index as isize).as_ref().expect("animation pointer should not be null")
                };

                let debug_text = record.get_debug_string(debug_field);
                CONTROL_PANEL.display(&debug_text);

                max_copy_index
            }
            None => game::MARIA_NUM_BONES - 1,
        };

        for (maria_index, &james_index) in game::MARIA_TO_JAMES_SKELETON_MAP.iter().enumerate() {
            if james_index < 0 || maria_index > max_copy_index {
                let target_animation = maria_animation.as_mut().expect("animation pointer should not be null");
                target_animation.copy_from_parent();
            } else {
                self.0[james_index as usize].copy_to(maria_animation);
            }

            maria_animation = maria_animation.offset(1);
        }
    }
}

struct PersistentData {
    pub equipped_item_id: *mut u8,
    pub james_anim_offset_thunk: [u8; 16],
    pub maria_anim_offset_thunk: [u8; 16],
    pub anim_read_thunk: [u8; 21],
    pub after_anim_read_thunk: [u8; 14],
    pub after_maria_anim_read_thunk: [u8; 17],
    pub animation_temp1: JamesAnimationContainer,
    pub animation_temp2: JamesAnimationContainer,
    pub original_animation1: *mut game::AnimationRecord,
    pub original_animation2: *mut game::AnimationRecord,
}

impl PersistentData {
    const fn new() -> Self {
        Self {
            equipped_item_id: std::ptr::null_mut(),
            james_anim_offset_thunk: [
                0x53, // push ebx
                0x51, // push ecx
                0x52, // push edx
                0x56, // push esi
                0x57, // push edi
                0xE8, 0, 0, 0, 0, // call <target>
                0x5F, // pop edi
                0x5E, // pop esi
                0x5A, // pop edx
                0x59, // pop ecx
                0x5B, // pop ebx
                0xC3, // ret
            ],
            maria_anim_offset_thunk: [
                0x53, // push ebx
                0x51, // push ecx
                0x52, // push edx
                0x56, // push esi
                0x57, // push edi
                0xE8, 0, 0, 0, 0, // call <target>
                0x5F, // pop edi
                0x5E, // pop esi
                0x5A, // pop edx
                0x59, // pop ecx
                0x5B, // pop ebx
                0xC3, // ret
            ],
            anim_read_thunk: [
                0x53, // push ebx
                0x51, // push ecx
                0x52, // push edx
                0x57, // push edi
                0x56, // push esi ; esi last because this will be an argument to the function
                0xE8, 0, 0, 0, 0, // call <target>
                0x5E, // pop esi
                0x5F, // pop edi
                0x5A, // pop edx
                0x59, // pop ecx
                0x5B, // pop ebx
                0x05, 0x00, 0xFF, 0xFF, 0xFF, // add eax, 0xFFFFFF00
                0xC3, // ret
            ],
            after_anim_read_thunk: [
                0x60, // pushad
                0x56, // push esi
                0xE8, 0, 0, 0, 0, // call <target>
                0x5E, // pop esi
                0x61, // popad
                0xE9, 0, 0, 0, 0, // jmp <return>
            ],
            after_maria_anim_read_thunk: [
                0x60, // pushad
                0x56, // push esi
                0xE8, 0, 0, 0, 0, // call <target>
                0x5E, // pop esi
                0x61, // popad
                0x83, 0xC4, 0x20, // add esp, 0x20
                0xE9, 0, 0, 0, 0, // jmp <return>
            ],
            animation_temp1: JamesAnimationContainer::new(),
            animation_temp2: JamesAnimationContainer::new(),
            original_animation1: std::ptr::null_mut(),
            original_animation2: std::ptr::null_mut(),
        }
    }

    fn init(&mut self, skeleton: &[i8]) {
        self.animation_temp1.init(skeleton);
        self.animation_temp2.init(skeleton);
    }

    unsafe fn patch_animations_before_read(&mut self, animation1_ptr: *mut *mut game::AnimationRecord, animation2_ptr: *mut *mut game::AnimationRecord) {
        self.original_animation1 = *animation1_ptr;
        *animation1_ptr = &raw mut self.animation_temp1.0[0];
        self.original_animation2 = *animation2_ptr;
        // the animations can be (are always?) the same, so handle that case
        if self.original_animation1 == self.original_animation2 {
            *animation2_ptr = &raw mut self.animation_temp1.0[0];
        } else {
            *animation2_ptr = &raw mut self.animation_temp2.0[0];
        }
    }

    unsafe fn patch_animations_after_read(&mut self, animation_ptr1: *mut *mut game::AnimationRecord, animation_ptr2: *mut *mut game::AnimationRecord) {
        if self.original_animation1.is_null() || self.original_animation2.is_null() {
            return;
        }

        self.animation_temp1.copy_to_maria(self.original_animation1);
        if self.original_animation1 != self.original_animation2 {
            self.animation_temp2.copy_to_maria(self.original_animation2);
        }

        *animation_ptr1 = self.original_animation1;
        self.original_animation1 = std::ptr::null_mut();
        *animation_ptr2 = self.original_animation2;
        self.original_animation2 = std::ptr::null_mut();
    }
}

static mut GLOBAL: PersistentData = PersistentData::new();
static mut CONTROL_PANEL: ControlPanel = ControlPanel::new();

const fn is_maria_animation(equipped_item_id: u8, is_james: bool) -> bool {
    // 10 = Colt, 17 = Cleaver, 0 = none
    equipped_item_id == 10 || equipped_item_id == 17 || (equipped_item_id == 0 && !is_james)
}

const fn get_animation_offset(equipped_item_id: u8, is_james: bool) -> usize {
    // FIXME: this might actually break Maria in the main scenario. need to reference the variable
    //  for the actual player character
    if is_maria_animation(equipped_item_id, is_james) {
        game::MARIA_ANIMATION_OFFSET
    } else {
        game::JAMES_ANIMATION_OFFSET
    }
}

unsafe extern "C" fn get_james_animation_offset() -> usize {
    get_animation_offset(*GLOBAL.equipped_item_id, true)
}

unsafe extern "C" fn get_maria_animation_offset() -> usize {
    get_animation_offset(*GLOBAL.equipped_item_id, false)
}

const unsafe fn get_character_info(character: *mut u8) -> (i16, *mut *mut game::AnimationRecord, *mut *mut game::AnimationRecord) {
    let character_id = *(character.offset(0x10) as *const i16);
    let animation1_ptr = character.offset(0x1A0) as *mut *mut game::AnimationRecord;
    let animation2_ptr = character.offset(0x220) as *mut *mut game::AnimationRecord;
    (character_id, animation1_ptr, animation2_ptr)
}

unsafe extern "C" fn patch_animations_before_read(character: *mut u8) -> i32 {
    // watch for control panel interactions
    CONTROL_PANEL.update_settings();

    let (character_id, animation1_ptr, animation2_ptr) = get_character_info(character);
    // TODO: support James
    if character_id != game::MARIA_ID {
        return character_id as i32;
    }

    let is_maria_animation = is_maria_animation(*GLOBAL.equipped_item_id, false);
    if is_maria_animation {
        return character_id as i32;
    }

    // this is a James animation. override Maria's animation lists with ours.
    GLOBAL.patch_animations_before_read(animation1_ptr, animation2_ptr);
    game::JAMES_IDS[0] as i32
}

unsafe extern "C" fn patch_animations_after_read_maria(character: *mut u8) {
    let (character_id, animation1_ptr, _) = get_character_info(character);

    // we're not doing any mapping if we get here, but let's still update the control panel display
    let debug_text = match (character_id, CONTROL_PANEL.get_settings()) {
        (_, Some((_, _, game::DebugField::None, _))) => String::new(),
        (game::MARIA_ID, Some((false, bone_index, debug_field, _))) => {
            let record = (*animation1_ptr).offset(bone_index as isize).as_ref().expect("animation pointer should not be null");
            record.get_debug_string(debug_field)
        }
        _ => String::new(),
    };

    CONTROL_PANEL.display(&debug_text);
}

unsafe extern "C" fn patch_animations_after_read(character: *mut u8) {
    let (character_id, animation1_ptr, animation2_ptr) = get_character_info(character);

    // TODO: support James
    // if we don't have original animation pointers, we didn't do anything
    if character_id != game::MARIA_ID || GLOBAL.original_animation1.is_null() || GLOBAL.original_animation2.is_null() {
        return;
    }

    // update the original animations with the data from the temporary animations
    GLOBAL.patch_animations_after_read(animation1_ptr, animation2_ptr);
}

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

    let [Some(tex_address)] = searcher.find_bytes(&[ICON_TEX_NAME], Some(PAGE_READONLY), sh2pc)? else {
        bail!("Failed to find item icon texture name");
    };
    log::debug!(
        "Found item menu texture path at {:#08X}",
        tex_address as usize,
    );

    let mut menu_data: [u8; 16] = [0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 1, 0, 0, 0];
    menu_data[..4].copy_from_slice(&(tex_address as usize).to_le_bytes());
    // we already rely on our icon coords game constant being a binary match for the exe's icon
    // coords, so let's just directly use it as our search data as well
    let icon_coords_ptr = game::ICON_COORDS.as_ptr() as *const u8;
    let icon_coords_buf = unsafe { std::slice::from_raw_parts(icon_coords_ptr, 12) };

    let [Some(menu_address), Some(icon_coord_address)] = searcher.find_bytes(
        &[&menu_data, icon_coords_buf],
        Some(PAGE_READWRITE | PAGE_WRITECOPY),
        sh2pc,
    )? else {
        bail!("Failed to find .data values");
    };
    log::debug!(
        "Found menu data at {:#08X}, icon coords at {:#08X}",
        menu_address as usize,
        icon_coord_address as usize,
    );

    // Maria vs James texture check
    let mut tex_ref_data: [u8; 7] = [0x50, 0x68, 0, 0, 0, 0, 0xE8];
    tex_ref_data[2..6].copy_from_slice(&(menu_address as usize).to_le_bytes());
    let [
        Some(tex_ref_call_address),
        Some(james_icon_draw_loop_address),
        Some(maria_icon_draw_loop_address),
        Some(weapon_assert_address),
        Some(weapon_assert_address2),
        Some(james_anim_address1),
        Some(james_anim_address2),
        Some(animation_offset_func),
        Some(animation_read_func),
        Some(draw_message_func),
    ] = searcher.find_bytes(
        &[
            &tex_ref_data,
            &JAMES_ICON_DRAW_LOOP,
            &MARIA_ICON_DRAW_LOOP,
            &MARIA_WEAPON_ASSERT,
            &MARIA_WEAPON_ASSERT2,
            &JAMES_ANIMATION_SIZE1,
            &JAMES_ANIMATION_SIZE2,
            &ANIMATION_OFFSET_FUNC,
            &ANIMATION_READ_FUNC,
            &DRAW_MESSAGE_FUNC,
        ],
        Some(PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE),
        sh2pc,
    )? else {
        bail!("Failed to find code addresses");
    };
    log::debug!(
        "Found tex ref data at {:#08X}, James icon draw loop at {:#08X}, Maria icon draw loop at {:#08X}, weapon assert at {:#08X}, weapon assert 2 at {:#08X}, James anim1 at {:#08X}, James anim2 at {:#08X}, anim offset at {:#08X}, anim read at {:#08X}, draw msg call at {:#08X}",
        tex_ref_call_address as usize,
        james_icon_draw_loop_address as usize,
        maria_icon_draw_loop_address as usize,
        weapon_assert_address as usize,
        weapon_assert_address2 as usize,
        james_anim_address1 as usize,
        james_anim_address2 as usize,
        animation_offset_func as usize,
        animation_read_func as usize,
        draw_message_func as usize,
    );

    unsafe {
        // sanity checks
        let tex_ref_check_address = tex_ref_call_address.offset(-27);
        patch::assert_byte(tex_ref_check_address, 0x75)?; // jnz

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

        let weapon_player_check_address2 = weapon_assert_address.offset(357);
        patch::assert_byte(weapon_player_check_address2, 0x75)?; // jnz

        let maria_weapon_assert_address = weapon_assert_address.offset(3);
        // no point asserting since this is still within our search string

        let maria_weapon_assert_address2 = weapon_assert_address2.offset(3);
        // no point asserting since this is still within our search string

        // get pointer to equipped item ID
        let equipped_item_id_address = std::ptr::read_unaligned(weapon_assert_address.offset(-43) as *const *mut u8);
        // make sure the address looks reasonable
        if !searcher.find_addresses(&[equipped_item_id_address as usize], Some(PAGE_READWRITE | PAGE_WRITECOPY), sh2pc)?[0] {
            bail!("Equipped item ID address {:#08X} doesn't look right", equipped_item_id_address as usize);
        }
        GLOBAL.equipped_item_id = equipped_item_id_address;

        let james_animation_offset_address = animation_offset_func.offset(0x30);
        patch::assert_byte(james_animation_offset_address, 0xB8)?; // mov

        let maria_animation_offset_address = animation_offset_func.offset(0x78);
        patch::assert_byte(maria_animation_offset_address, 0xB8)?; // mov

        // prepare to rearrange weapon data entries
        let weapon_data_ptr_address = weapon_assert_address.offset(169);
        patch::assert_byte(weapon_data_ptr_address, 0xA1)?;

        let weapon_data_address = usize::from_le_bytes(
            std::slice::from_raw_parts(
                weapon_data_ptr_address.offset(1) as *const u8,
                size_of::<usize>(),
            )
            .try_into()?,
        ) as *mut u8;
        patch::assert_byte(weapon_data_address, 0)?;

        let james_weapon_end_address = weapon_data_address.offset(180);
        patch::assert_byte(james_weapon_end_address, 0xFF)?;

        let maria_weapon_cleaver_address = weapon_data_address.offset(240);
        patch::assert_byte(maria_weapon_cleaver_address, 17)?;

        let maria_weapon_end_address = weapon_data_address.offset(260);
        patch::assert_byte(maria_weapon_end_address, 0xFF)?;

        // animation mapping
        let anim_before_read_address = animation_read_func.offset(9);
        patch::assert_byte(anim_before_read_address, 0x05)?; // add

        let anim_after_read_address1 = animation_read_func.offset(122);
        patch::assert_byte(anim_after_read_address1, 0x0F)?; // jz

        let anim_after_read_address2 = animation_read_func.offset(144);
        patch::assert_byte(anim_after_read_address2, 0xE9)?; // jmp

        let anim_after_maria_read_address = animation_read_func.offset(222);
        patch::assert_byte(anim_after_maria_read_address, 0x83)?; // add

        let anim_after_maria_return_address = animation_read_func.offset(284);
        patch::assert_byte(anim_after_maria_return_address, 0x0F)?; // movsx

        // messages
        patch::assert_byte(draw_message_func, 0x8B)?; // mov

        // initialize static data
        GLOBAL.init(&game::JAMES_SKELETON);
        CONTROL_PANEL.set_draw_message_ptr(draw_message_func);

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

        // increase memory for James' weapon animations
        log::info!("Applying James animation patch at addresses {:#08X}, {:#08X}", james_anim_address1 as usize, james_anim_address2 as usize);
        let size_bytes = game::MARIA_ANIMATION_SIZE.to_le_bytes();
        patch::patch(james_anim_address1.offset(2), &size_bytes)?;
        patch::patch(james_anim_address2.offset(2), &size_bytes)?;

        // merge James and Maria's weapon lists into a single contiguous list
        log::info!("Merging weapon lists");

        let james_weapon_end =
            std::slice::from_raw_parts_mut(james_weapon_end_address, game::WEAPON_INFO_SIZE);
        let maria_weapon_end =
            std::slice::from_raw_parts(maria_weapon_end_address, game::WEAPON_INFO_SIZE);
        let maria_weapon_cleaver =
            std::slice::from_raw_parts_mut(maria_weapon_cleaver_address, game::WEAPON_INFO_SIZE);

        james_weapon_end.copy_from_slice(maria_weapon_cleaver); // replace James' end marker with the cleaver
        maria_weapon_cleaver.copy_from_slice(maria_weapon_end); // replace the cleaver with the end marker

        // we now have every weapon in one big list, but we'll still start Maria at the old start of her list
        // so she gets the proper animation for no weapon

        // now we patch the logic
        log::info!(
            "Patching weapon selection logic at addresses {:#08X}, {:#08X}, {:#08X}",
            maria_weapon_assert_address as usize,
            weapon_player_check_address2 as usize,
            maria_weapon_assert_address2 as usize
        );
        patch::patch(maria_weapon_assert_address, &CHECK_JAMES_WEAPON_LIST)?;
        patch::patch(weapon_player_check_address2, &[0x90, 0x90])?; // nop out jump to always use James path
        patch::patch(maria_weapon_assert_address2, &CHECK_JAMES_WEAPON_LIST2)?;

        // select correct animation offset based on equipped weapon
        log::info!("Patching animation offset logic at addresses {:#08X}, {:#08X}", james_animation_offset_address as usize, maria_animation_offset_address as usize);

        patch::set_trampoline(&mut GLOBAL.james_anim_offset_thunk, 5, get_james_animation_offset as usize)?;
        let james_animation_offset_call = patch::call(james_animation_offset_address as usize, &raw const GLOBAL.james_anim_offset_thunk as usize);
        patch::patch(james_animation_offset_address, &james_animation_offset_call)?;

        patch::set_trampoline(&mut GLOBAL.maria_anim_offset_thunk, 5, get_maria_animation_offset as usize)?;
        let maria_animation_offset_call = patch::call(maria_animation_offset_address as usize, &raw const GLOBAL.maria_anim_offset_thunk as usize);
        patch::patch(maria_animation_offset_address, &maria_animation_offset_call)?;

        // animation skeleton mapping
        log::info!("Patching animation read logic at addresses {:#08X}, {:#08X}, {:#08X}, {:#08X}", anim_before_read_address as usize, anim_after_read_address1 as usize, anim_after_read_address2 as usize, anim_after_maria_read_address as usize);

        // patch before reading the animation so we can switch to the James or Maria path as appropriate
        patch::set_trampoline(&mut GLOBAL.anim_read_thunk, 5, patch_animations_before_read as usize)?;
        let anim_before_read_call = patch::call(anim_before_read_address as usize, &raw const GLOBAL.anim_read_thunk as usize);
        patch::patch(anim_before_read_address, &anim_before_read_call)?;

        // when exiting the James path, we need to perform the appropriate mapping of James transformations to Maria transformations
        patch::set_trampoline(&mut GLOBAL.after_anim_read_thunk, 2, patch_animations_after_read as usize)?;
        let original_jump_target = patch::get_call_target(anim_after_read_address2);
        patch::set_trampoline(&mut GLOBAL.after_anim_read_thunk, 9, original_jump_target as usize)?;
        let anim_after_read_jump2 = patch::jmp(anim_after_read_address2 as usize, &raw const GLOBAL.after_anim_read_thunk as usize);
        patch::patch(anim_after_read_address2, &anim_after_read_jump2)?;

        // there's also an earlier, conditional exit of this path
        let anim_after_read_jump1 = patch::jz(anim_after_read_address1 as usize, &raw const GLOBAL.after_anim_read_thunk as usize);
        patch::patch(anim_after_read_address1, &anim_after_read_jump1)?;

        // we still patch in the case where Maria's playing her own animation so we can update the debug display
        patch::set_trampoline(&mut GLOBAL.after_maria_anim_read_thunk, 2, patch_animations_after_read_maria as usize)?;
        patch::set_trampoline(&mut GLOBAL.after_maria_anim_read_thunk, 12, anim_after_maria_return_address as usize)?;
        let anim_after_maria_read_jump = patch::jmp(anim_after_maria_read_address as usize, &raw const GLOBAL.after_maria_anim_read_thunk as usize);
        patch::patch(anim_after_maria_read_address, &anim_after_maria_read_jump)?;
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
    }
    .into()
}

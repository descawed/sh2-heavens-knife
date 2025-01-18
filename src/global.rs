use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

use crate::game;

#[derive(Debug)]
struct WeaponAnimationFiles {
    handgun: game::FileInfo,
    shotgun: game::FileInfo,
    rifle: game::FileInfo,
    hyper_spray: game::FileInfo,
    wooden_plank: game::FileInfo,
    steel_pipe: game::FileInfo,
    chainsaw: game::FileInfo,
    great_knife: game::FileInfo,
    revolver: game::FileInfo,
    cleaver: game::FileInfo,
}

pub struct PersistentData {
    equipped_item_id: *mut i8,
    pub james_anim_offset_thunk: [u8; 16],
    pub maria_anim_offset_thunk: [u8; 16],
    pub anim_read_thunk: [u8; 21],
    pub after_anim_read_thunk: [u8; 14],
    pub after_maria_anim_read_thunk: [u8; 17],
    pub anim_description_change_thunk: [u8; 16],
    pub load_weapon_thunk: [u8; 12],
    pub load_weapon_thunk2: [u8; 12],
    pub james_action_sound_thunk: [u8; 68],
    pub maria_action_sound_thunk: [u8; 63],
    pub rotate_bone_transform_thunk: [u8; 37],
    pub difficulty_select_thunk: [u8; 20],
    pub item_description_thunk: [u8; 24],
    pub add_item_thunk: [u8; 11],
    pub original_animation1: *mut game::AnimationRecord,
    pub original_animation2: *mut game::AnimationRecord,
    player_character_flag: *const u8,
    request_file_size: Option<unsafe extern "C" fn(file: *const game::FileInfo) -> usize>,
    get_character_buffers: Option<unsafe extern "C" fn(character_id: i32) -> *mut game::CharacterBuffers>,
    get_character_frame_size: Option<unsafe extern "C" fn(character_id: i32) -> usize>,
    draw_message_ptr: Option<unsafe extern "C" fn(*const u8)>,
    inc_item_count: Option<unsafe extern "C" fn()>,
    add_item_to_inventory: Option<unsafe extern "C" fn(item_id: i32)>,
    set_new_game_plus_item_flag: Option<unsafe extern "C" fn(flag: u32)>,
    character_files: *mut game::CharacterFiles,
    character_files_end: *mut game::CharacterFiles,
    player_ptr: *mut *mut game::Character,
    james_weapon_animations: WeaponAnimationFiles,
    maria_weapon_animations: WeaponAnimationFiles,
    weapon_info: *mut game::WeaponInfo,
    unk_grunt_sound_value: Option<unsafe extern "C" fn() -> i32>,
    sound_param_data: *mut u8,
    inventory: *mut game::Inventory,
    item_messages: [game::MessageFile; game::NUM_LANGUAGES],
    enable_item_override: bool,
}

impl PersistentData {
    pub const fn new() -> Self {
        use crate::game::FileInfo;

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
            anim_description_change_thunk: [
                0x52, // push edx ; character
                0x8B, 0x54, 0x24, 0x28, // mov edx, [esp+40]
                0x52, // push edx ; animation description
                0x51, // push ecx ; animation
                0xE8, 0, 0, 0, 0, // call <target>
                0x59, // pop ecx
                0x5A, // pop edx
                0x5A, // pop edx
                0xC3, // ret
            ],
            load_weapon_thunk: [
                0x60, // pushad
                0xE8, 0, 0, 0, 0, // call <target>
                0x61, // popad
                0xE9, 0, 0, 0, 0, // jmp <return>
            ],
            load_weapon_thunk2: [
                0x60, // pushad
                0xE8, 0, 0, 0, 0, // call <target>
                0x61, // popad
                0xE9, 0, 0, 0, 0, // jmp <return>
            ],
            james_action_sound_thunk: [
                0x0F, 0x87, 0, 0, 0, 0, // ja <default>
                0x60, // pushad ; from edi, the last register pushed, we'll get the animation description
                0x83, 0xC0, 0x02, // add eax, 2 ; prior code subtracts 2 from the animation ID
                0x50, // push eax
                0x8D, 0x44, 0x24, 0x38, // lea eax, [esp+56]
                0x50, // push eax ; sound parameters
                0xE8, 0, 0, 0, 0, // call <target>
                0x83, 0xC4, 0x08, // add esp, 8
                0x85, 0xC0, // test eax, eax
                0x74, 0x22, // jnz no_match
                0x5F, // pop edi
                0x5E, // pop esi
                0x5D, // pop ebp
                0x83, 0xC4, 0x04, // add esp, 4 ; skip esp
                0x5B, // pop ebx
                0x5A, // pop edx
                0x89, 0xC1, // mov ecx, eax
                0x25, 0xFF, 0xFF, 0x00, 0x00, // and eax, 0xFFFF
                0x89, 0xC6, // mov esi, eax
                0xC1, 0xE9, 0x10, // shr ecx, 16
                0x89, 0xCD, // mov ebp, ecx
                0x59, // pop ecx
                0x58, // pop eax
                0xBB, 0x04, 0x00, 0x00, 0x00, // mov ebx, 4 ; loop bound
                0xE9, 0, 0, 0, 0, // jmp <play_sound>
                0x61, // no_match: popad
                0xE9, 0, 0, 0, 0, // jmp <original>
            ],
            maria_action_sound_thunk: [
                0x0F, 0x87, 0, 0, 0, 0, // ja <default>
                0x60, // pushad ; from edi, the last register pushed, we'll get the animation description
                0x83, 0xC0, 0x03, // add eax, 3 ; prior code subtracts 3 from the animation ID
                0x50, // push eax
                0x8D, 0x44, 0x24, 0x34, // lea eax, [esp+52]
                0x50, // push eax ; sound parameters
                0xE8, 0, 0, 0, 0, // call <target>
                0x83, 0xC4, 0x08, // add esp, 8
                0x85, 0xC0, // test eax, eax
                0x74, 0x1D, // jnz no_match
                0x5F, // pop edi
                0x5E, // pop esi
                0x5D, // pop ebp
                0x83, 0xC4, 0x04, // add esp, 4 ; skip esp
                0x5B, // pop ebx
                0x5A, // pop edx
                0x89, 0xC1, // mov ecx, eax
                0x25, 0xFF, 0xFF, 0x00, 0x00, // and eax, 0xFFFF
                0x89, 0xC6, // mov esi, eax
                0xC1, 0xE9, 0x10, // shr ecx, 16
                0x89, 0xCD, // mov ebp, ecx
                0x59, // pop ecx
                0x58, // pop eax
                0xE9, 0, 0, 0, 0, // jmp <play_sound>
                0x61, // no_match: popad
                0xE9, 0, 0, 0, 0, // jmp <original>
            ],
            rotate_bone_transform_thunk: [
                0x83, 0xEC, 0x50, // sub esp, 0x50
                0x53, // push ebx
                0x55, // push ebp
                0x8B, 0x5C, 0x24, 0x5C, // mov ebx, [esp+0x5c] ; animation
                0x8B, 0x6C, 0x24, 0x60, // mov ebp, [esp+0x60] ; record
                0x8B, 0x44, 0x24, 0x64, // mov eax, [esp+0x64] ; rotation
                0x50, // push eax
                0x55, // push ebp
                0x53, // push ebx
                0xE8, 0, 0, 0, 0, // call <target>
                0x83, 0xC4, 0x0C, // add esp, 12
                0x89, 0x44, 0x24, 0x60, // mov [esp+0x60], eax
                0xE9, 0, 0, 0, 0, // jmp <original>
            ],
            /*difficulty_select_thunk: [
                0x60, // pushad
                0xE8, 0, 0, 0, 0, // call <target>
                0x85, 0xC0, // test eax, eax
                0x61, // popad
                0x74, 0x03, // jz original
                0x31, 0xC0, // xor eax, eax
                0xC3, // ret
                0xE9, 0, 0, 0, 0, // original: jmp <original>
            ],*/
            difficulty_select_thunk: [
                0x60, // pushad
                0xE8, 0, 0, 0, 0, // call <target>
                0x85, 0xC0, // test eax, eax
                0x61, // popad
                0x74, 0x04, // jz original
                0x83, 0xC4, 0x10, // add esp, 16
                0xC3, // ret
                0xE9, 0, 0, 0, 0, // original: jmp <original>
            ],
            item_description_thunk: [
                0x8D, 0x44, 0x24, 0x0C,  // lea eax, [esp+12] ; pointer to message ID argument
                0x50, // push eax
                0x83, 0xE8, 0x04, // sub eax, 4 ; pointer to message file argument
                0x50, // push eax
                0xE8, 0, 0, 0, 0, // call <target>
                0x83, 0xC4, 0x08, // add esp, 8
                0x8B, 0x44, 0x24, 0x08, // mov eax, [esp+8]
                0x85, 0xC0, // test eax, eax
                0xC3, // ret
            ],
            add_item_thunk: [
                0xE8, 0, 0, 0, 0, // call <target>
                0x59, // pop ecx
                0x56, // push esi
                0x89, 0xC6, // mov esi, eax
                0xFF, 0xE1, // jmp ecx
            ],
            original_animation1: std::ptr::null_mut(),
            original_animation2: std::ptr::null_mut(),
            player_character_flag: std::ptr::null(),
            request_file_size: None,
            get_character_buffers: None,
            get_character_frame_size: None,
            draw_message_ptr: None,
            inc_item_count: None,
            add_item_to_inventory: None,
            set_new_game_plus_item_flag: None,
            character_files: std::ptr::null_mut(),
            character_files_end: std::ptr::null_mut(),
            player_ptr: std::ptr::null_mut(),
            james_weapon_animations: WeaponAnimationFiles {
                handgun: FileInfo::new(c"data/chr/jms/jms_wphand.anm"),
                shotgun: FileInfo::new(c"data/chr/jms/jms_wpshot.anm"),
                rifle: FileInfo::new(c"data/chr/jms/jms_wprifl.anm"),
                hyper_spray: FileInfo::new(c"data/chr/jms/jms_wpsp.anm"),
                wooden_plank: FileInfo::new(c"data/chr/jms/jms_wpkaku.anm"),
                steel_pipe: FileInfo::new(c"data/chr/jms/jms_wppipe.anm"),
                chainsaw: FileInfo::new(c"data/chr/jms/jms_wpcsaw.anm"),
                great_knife: FileInfo::new(c"data/chr/jms/jms_wpnata.anm"),
                revolver: FileInfo::new(c"data/chr/jms/jms_wpcolt.anm"),
                cleaver: FileInfo::new(c"data/chr/jms/jms_wpknif.anm"),
            },
            maria_weapon_animations: WeaponAnimationFiles {
                handgun: FileInfo::new(c"data/chr2/mar/xmar_wphand.anm"),
                shotgun: FileInfo::new(c"data/chr2/mar/xmar_wpshot.anm"),
                rifle: FileInfo::new(c"data/chr2/mar/xmar_wprifl.anm"),
                hyper_spray: FileInfo::new(c"data/chr2/mar/xmar_wpsp.anm"),
                wooden_plank: FileInfo::new(c"data/chr2/mar/xmar_wpkaku.anm"),
                steel_pipe: FileInfo::new(c"data/chr2/mar/xmar_wppipe.anm"),
                chainsaw: FileInfo::new(c"data/chr2/mar/xmar_wpcsaw.anm"),
                great_knife: FileInfo::new(c"data/chr2/mar/xmar_wpnata.anm"),
                revolver: FileInfo::new(c"data/chr2/mar/xmar_wpcolt.anm"),
                cleaver: FileInfo::new(c"data/chr2/mar/xmar_wpknif.anm"),
            },
            weapon_info: std::ptr::null_mut(),
            unk_grunt_sound_value: None,
            sound_param_data: std::ptr::null_mut(),
            inventory: std::ptr::null_mut(),
            item_messages: [const { game::MessageFile::new() }; game::NUM_LANGUAGES],
            enable_item_override: true,
        }
    }

    pub fn init(&mut self, equipped_item_id: *mut i8, player_character_flag: *const u8, request_file_size: usize, get_character_buffers: usize,
            character_files: *mut game::CharacterFiles, character_files_end: *mut game::CharacterFiles, player_ptr: *mut *mut game::Character,
            get_character_frame_size: usize, weapon_info: *mut game::WeaponInfo, grunt_sound_selector: usize, sound_param_data: *mut u8,
            draw_message_ptr: usize, inc_item_count: usize, add_item_to_inventory: usize, inventory: *mut game::Inventory,
            set_new_game_plus_item_flag: usize) -> Result<()> {
        self.equipped_item_id = equipped_item_id;
        self.player_character_flag = player_character_flag;
        self.request_file_size = Some(unsafe { std::mem::transmute(request_file_size) });
        self.get_character_buffers = Some(unsafe { std::mem::transmute(get_character_buffers) });
        self.get_character_frame_size = Some(unsafe { std::mem::transmute(get_character_frame_size) });
        self.draw_message_ptr = Some(unsafe { std::mem::transmute(draw_message_ptr) });
        self.inc_item_count = Some(unsafe { std::mem::transmute(inc_item_count) });
        self.add_item_to_inventory = Some(unsafe { std::mem::transmute(add_item_to_inventory) });
        self.set_new_game_plus_item_flag = Some(unsafe { std::mem::transmute(set_new_game_plus_item_flag) });
        self.character_files = character_files;
        self.character_files_end = character_files_end;
        self.player_ptr = player_ptr;
        self.weapon_info = weapon_info;
        self.unk_grunt_sound_value = Some(unsafe { std::mem::transmute(grunt_sound_selector) });
        self.sound_param_data = sound_param_data;
        self.inventory = inventory;

        self.load_item_messages()
    }

    fn load_message_file(name: &str, language: char) -> Result<game::MessageFile> {
        let mut string = format!("sh2e/etc/message/{name}_msg_{language}.mes");
        let mut path = Path::new(&string);
        if !path.exists() {
            string = format!("data/etc/message/{name}_msg_{language}.mes");
            path = Path::new(&string);
        }
        game::MessageFile::from_file(path).context(format!("Failed to load message file {}", string))
    }

    fn load_messages<const N: usize>(name: &str, language: char, message_ids: [usize; N]) -> Result<[Vec<u8>; N]> {
        let file = Self::load_message_file(name, language)?;
        let mut messages = [const { Vec::new() }; N];
        for (i, message_id) in message_ids.iter().enumerate() {
            messages[i] = file.get(*message_id).to_vec();
        }
        Ok(messages)
    }

    fn pickup_message(prefix: &str, item_name: &str) -> game::Message {
        let mut message = game::Message::new();
        message.set_message(|builder| {
            builder.add_text(prefix);
            if !prefix.ends_with(' ') {
                builder.add_text(" ");
            }
            builder.add_control_code(game::ControlCode::Green);
            builder.add_text(item_name);
            builder.add_control_code(game::ControlCode::White);
            builder.add_text(".");
            builder.set_post_code(0x9000);
        });
        message
    }

    fn load_item_messages(&mut self) -> Result<()> {
        for (message_file, language) in self.item_messages.iter_mut().zip(game::LANGUAGES.chars()) {
            log::debug!("Loading item messages for language {}", language);
            let [handgun_bullets, shotgun_shells, rifle_shells, revolver_bullets] = Self::load_messages("common", language, [9, 10, 11, 23])?;

            let [handgun] = Self::load_messages("stage_apart_e3fw", language, [0])?;
            message_file.add_message(&handgun);
            message_file.add_message(&handgun_bullets);

            let [shotgun] = Self::load_messages("stage_hospital_2f_f", language, [13])?;
            message_file.add_message(&shotgun);
            message_file.add_message(&shotgun_shells);

            let [rifle] = Self::load_messages("stage_prison_n", language, [11])?;
            message_file.add_message(&rifle);
            message_file.add_message(&rifle_shells);

            // the revolver and wooden plank don't have messages because they're obtained in
            // cutscenes. I'll try my hand at the German versions, but everyone else gets English
            // for now.
            message_file.add_message(if language == 'g' {
                Self::pickup_message("Ich habe einen", "Revolver")
            } else {
                Self::pickup_message("I got a", "revolver")
            }.as_slice());
            message_file.add_message(&revolver_bullets);

            let [hyper_spray] = Self::load_messages("stage_toilet", language, [3])?;
            message_file.add_message(&hyper_spray);

            message_file.add_message(if language == 'g' {
                Self::pickup_message("Ich habe ein", "Brett")
            } else {
                Self::pickup_message("I got a", "wooden plank")
            }.as_slice());

            let [steel_pipe] = Self::load_messages("stage_town_west", language, [71])?;
            message_file.add_message(&steel_pipe);

            let [great_knife] = Self::load_messages("stage_labyrinth_w", language, [38])?;
            message_file.add_message(&great_knife);

            let [chainsaw] = Self::load_messages("stage_forest", language, [4])?;
            message_file.add_message(&chainsaw);

            let [cleaver] = Self::load_messages("stage_x_heaven", language, [12])?;
            message_file.add_message(&cleaver);
        }

        log::debug!("Loaded item messages");
        Ok(())
    }

    pub unsafe fn get_item_id_for_message(&self, msg: *const u8) -> Option<(i8, usize)> {
        for i in 0..game::NUM_WEAPON_AMMO_ITEMS {
            let item_id = (i as i8) + game::ITEM_ID_HANDGUN;
            if matches!(item_id, game::ITEM_ID_REVOLVER | game::ITEM_ID_WOODEN_PLANK) {
                // we generated these messages ourselves, so there's no chance the game is
                // trying to display them
                continue;
            }

            // to avoid having to find the address of the current language, we'll just check all
            // languages
            for (language, file) in self.item_messages.iter().enumerate() {
                let message = file.get(i);
                // we don't know where the end of the game buffer is, so we'll check one byte at a
                // time to reduce the chance of overflowing
                let mut is_match = true;
                let mut data_ptr = msg;
                for byte in message {
                    if *data_ptr != *byte {
                        is_match = false;
                        break;
                    }
                    data_ptr = data_ptr.offset(1);
                }

                if is_match {
                    return Some((item_id, language));
                }
            }
        }

        None
    }

    pub fn get_message_for_item(&self, item_id: i8, language: usize) -> Option<(*const u8, i32)> {
        if item_id < game::ITEM_ID_HANDGUN || item_id > game::ITEM_ID_CLEAVER {
            return None;
        }

        let file = self.item_messages.get(language)?;
        Some((file.data(), (item_id - game::ITEM_ID_HANDGUN) as i32))
    }

    pub unsafe fn set_weapon_animations(&mut self) {
        let weapon_info = std::slice::from_raw_parts_mut(self.weapon_info, game::NUM_WEAPON_INFOS);
        let is_player_maria = self.is_player_maria();
        let animations = if is_player_maria {
            &mut self.maria_weapon_animations
        } else {
            &mut self.james_weapon_animations
        };

        // skip James' no-weapon animation
        weapon_info[1].animation = &raw mut animations.handgun;
        weapon_info[2].animation = &raw mut animations.shotgun;
        weapon_info[3].animation = &raw mut animations.rifle;
        weapon_info[4].animation = &raw mut animations.hyper_spray;
        weapon_info[5].animation = &raw mut animations.wooden_plank;
        weapon_info[6].animation = &raw mut animations.steel_pipe;
        weapon_info[7].animation = &raw mut animations.chainsaw;
        weapon_info[8].animation = &raw mut animations.great_knife;
        // normally index 9 is the end of James' weapons, but we copied the cleaver here to unify
        // the weapon lists
        weapon_info[9].animation = &raw mut animations.cleaver;
        // skip Maria's no-weapon animation
        weapon_info[11].animation = &raw mut animations.revolver;
    }

    pub const unsafe fn is_player_maria(&self) -> bool {
        *self.player_character_flag == 1
    }

    pub const unsafe fn equipped_item_id(&self) -> i8 {
        *self.equipped_item_id
    }

    pub const unsafe fn set_equipped_item(&self, item_id: i8) {
        *self.equipped_item_id = item_id;
    }

    pub const unsafe fn is_player_id(id: i16) -> bool {
        id == game::MARIA_ID || id == game::JAMES_IDS[0] || id == game::JAMES_IDS[1]
    }

    pub const unsafe fn player(&self) -> *mut game::Character {
        if self.player_ptr.is_null() {
            return std::ptr::null_mut();
        }

        let player = *self.player_ptr;
        let Some(player_ref) = player.as_ref() else {
            return std::ptr::null_mut();
        };

        // as a sanity check, make sure our "player" actually has a player character's ID
        if !Self::is_player_id(player_ref.id) {
            return std::ptr::null_mut();
        }

        player
    }

    pub unsafe fn request_file_size(&self, file: *const game::FileInfo) -> usize {
        self.request_file_size.unwrap()(file)
    }

    pub unsafe fn get_character_buffers(&self, character_id: i32) -> *mut game::CharacterBuffers {
        self.get_character_buffers.unwrap()(character_id)
    }

    pub unsafe fn get_character_frame_size(&self, character_id: i32) -> usize {
        self.get_character_frame_size.unwrap()(character_id)
    }

    pub unsafe fn get_character_files(&self, character_id: i16) -> *mut game::CharacterFiles {
        let mut file_ptr = self.character_files;
        while file_ptr < self.character_files_end {
            let files = file_ptr.as_ref().expect("character files pointer should not be null");
            if files.character_id == character_id {
                return file_ptr;
            }

            file_ptr = file_ptr.offset(1);
        }

        std::ptr::null_mut()
    }

    pub unsafe fn get_character_files_by_animation_buffer(&self, animation_buffer: *mut u8) -> *mut game::CharacterFiles {
        // any unused character file slot or object without an animation will have null buffers,
        // so we don't want to return bogus results for those
        if animation_buffer.is_null() {
            return std::ptr::null_mut();
        }

        let mut file_ptr = self.character_files;
        while file_ptr < self.character_files_end {
            let files = file_ptr.as_ref().expect("character files pointer should not be null");
            if files.animation.buffer == animation_buffer {
                return file_ptr;
            }

            file_ptr = file_ptr.offset(1);
        }

        std::ptr::null_mut()
    }

    pub unsafe fn get_maria_files(&self) -> *mut game::CharacterFiles {
        self.get_character_files(game::MARIA_ID)
    }

    pub unsafe fn get_james_files(&self) -> *mut game::CharacterFiles {
        let files = self.get_character_files(game::JAMES_IDS[0]);
        if !files.is_null() {
            return files;
        }

        self.get_character_files(game::JAMES_IDS[1])
    }

    pub unsafe fn get_player_files(&self) -> *mut game::CharacterFiles {
        // the game can put a James ID on Maria's files when running a James animation and vice
        // versa, so we'll check for all player IDs regardless of which character the player is,
        // but we'll check for the expected character first
        if self.is_player_maria() {
            let files = self.get_maria_files();
            if !files.is_null() {
                return files;
            }

            self.get_james_files()
        } else {
            let files = self.get_james_files();
            if !files.is_null() {
                return files;
            }

            self.get_maria_files()
        }
    }

    pub unsafe fn is_james_animation_buffer(&self, animation_buffer: *mut u8) -> bool {
        self.get_character_files_by_animation_buffer(animation_buffer).as_ref().map(|buf| unsafe { buf.is_using_james_animation() }).unwrap_or(false)
    }

    pub unsafe fn unk_grunt_sound_value(&self) -> i32 {
        self.unk_grunt_sound_value.unwrap()()
    }

    pub unsafe fn sound_param_data(&self) -> &mut [u8] {
        std::slice::from_raw_parts_mut(self.sound_param_data, 10)
    }

    pub unsafe fn set_new_game_plus_item_flag(&self, flag: u32) {
        self.set_new_game_plus_item_flag.unwrap()(flag);
    }

    pub unsafe fn print(&self, data: *const u8) {
        self.draw_message_ptr.unwrap()(data);
    }

    pub unsafe fn print_message(&self, msg: &game::Message) {
        self.print(msg.data());
    }

    pub unsafe fn inc_item_count(&self) {
        self.inc_item_count.unwrap()();
    }

    pub unsafe fn add_item_to_inventory(&self, item_id: i8) {
        self.add_item_to_inventory.unwrap()(item_id as i32);
    }

    pub unsafe fn inventory(&self) -> &mut game::Inventory {
        self.inventory.as_mut().expect("inventory pointer should not be null")
    }

    pub fn disable_item_override(&mut self) {
        self.enable_item_override = false;
    }

    pub fn enable_item_override(&mut self) {
        self.enable_item_override = true;
    }

    pub const fn is_item_override_enabled(&self) -> bool {
        self.enable_item_override
    }
}
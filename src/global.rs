use std::path::Path;

use anyhow::{Context, Result};

use crate::game;

pub struct PersistentData {
    pub load_weapon_thunk: [u8; 12],
    pub james_action_sound_thunk: [u8; 68],
    pub maria_action_sound_thunk: [u8; 63],
    pub rotate_bone_transform_thunk: [u8; 37],
    pub item_description_thunk: [u8; 24],
    pub add_item_thunk: [u8; 16],
    pub menu_input_loop_thunk: [u8; 26],
    pub pause_menu_draw_thunk: [u8; 13],
    pub main_menu_thunk: [u8; 22],
    pub maria_sound_return_thunk: [u8; 14],
    player_character_flag: *const u8,
    inc_item_count: Option<unsafe extern "C" fn()>,
    add_item_to_inventory: Option<unsafe extern "C" fn(item_id: i32)>,
    set_new_game_plus_item_flag: Option<unsafe extern "C" fn(flag: u32)>,
    unk_grunt_sound_value: Option<unsafe extern "C" fn() -> i32>,
    is_flashlight_on: Option<unsafe extern "C" fn() -> bool>,
    default_animation_files: [*mut game::FileInfo; 10],
    alternate_animation_files: [game::FileInfo; 10],
    weapon_info: *mut game::WeaponInfo,
    sound_param_data: *mut u8,
    inventory: *mut game::Inventory,
    main_menu_state: *mut i32,
    flashlight_vector: *mut f32,
    item_messages: [game::MessageFile; game::NUM_LANGUAGES],
    enable_item_override: bool,
}

impl PersistentData {
    pub const fn new() -> Self {
        use crate::game::FileInfo;

        Self {
            load_weapon_thunk: [
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
                0x85, 0xC0, // test eax, eax
                0x75, 0x01, // jnz continue
                0xC3, // ret
                0x56, // continue: push esi
                0x89, 0xC6, // mov esi, eax
                0xFF, 0xE1, // jmp ecx
            ],
            menu_input_loop_thunk: [
                0x77, 0x0F, // ja default
                0x60, // pushad
                0x50, // push eax
                0xE8, 0, 0, 0, 0, // call <target>
                0x83, 0xC4, 0x04, // add esp, 4
                0x85, 0xC0, // test eax, eax
                0x61, // popad
                0x0F, 0x84, 0, 0, 0, 0, // jz <return>
                0xE9, 0, 0, 0, 0, // default: jmp <default>
            ],
            pause_menu_draw_thunk: [
                0xE8, 0, 0, 0, 0, // call <original>
                0xE8, 0, 0, 0, 0, // call <target>
                0x01, 0xC4, // add esp, eax ; if we want to skip drawing of the menu, we'll return 4
                0xC3, // ret
            ],
            main_menu_thunk: [
                0xE8, 0, 0, 0, 0, // call <original>
                0x60, // pushad
                0xE8, 0, 0, 0, 0, // call <target>
                0x85, 0xC0, // test eax, eax
                0x61, // popad
                0x75, 0x05, // jnz return
                0x83, 0xC4, 0x04, // add esp, 4
                0x31, 0xC0, // xor eax, eax
                0xC3, // return: ret
            ],
            maria_sound_return_thunk: [
                0x53, // push ebx
                0x55, // push ebp
                0x56, // push esi
                0x57, // push edi
                0xBB, 0x04, 0x00, 0x00, 0x00, // mov ebx, 4
                0xE9, 0, 0, 0, 0, // call <target>
            ],
            player_character_flag: std::ptr::null(),
            inc_item_count: None,
            add_item_to_inventory: None,
            set_new_game_plus_item_flag: None,
            unk_grunt_sound_value: None,
            is_flashlight_on: None,
            default_animation_files: [std::ptr::null_mut(); 10],
            alternate_animation_files: [
                FileInfo::new(c"data/chr2/mar/xmar_wphand.anm"),
                FileInfo::new(c"data/chr2/mar/xmar_wpshot.anm"),
                FileInfo::new(c"data/chr2/mar/xmar_wprifl.anm"),
                FileInfo::new(c"data/chr2/mar/xmar_wpsp.anm"),
                FileInfo::new(c"data/chr2/mar/xmar_wpkaku.anm"),
                FileInfo::new(c"data/chr2/mar/xmar_wppipe.anm"),
                FileInfo::new(c"data/chr2/mar/xmar_wpcsaw.anm"),
                FileInfo::new(c"data/chr2/mar/xmar_wpnata.anm"),
                // we order the cleaver before the revolver when we unify the weapon lists
                FileInfo::new(c"data/chr/jms/jms_wpknif.anm"),
                FileInfo::new(c"data/chr/jms/jms_wpcolt.anm"),
            ],
            weapon_info: std::ptr::null_mut(),
            sound_param_data: std::ptr::null_mut(),
            inventory: std::ptr::null_mut(),
            main_menu_state: std::ptr::null_mut(),
            flashlight_vector: std::ptr::null_mut(),
            item_messages: [const { game::MessageFile::new() }; game::NUM_LANGUAGES],
            enable_item_override: true,
        }
    }

    pub fn init(&mut self, player_character_flag: *const u8,
            weapon_info: *mut game::WeaponInfo, grunt_sound_selector: usize, sound_param_data: *mut u8,
            inc_item_count: usize, add_item_to_inventory: usize, inventory: *mut game::Inventory,
            set_new_game_plus_item_flag: usize, main_menu_state: *mut i32,
            is_flashlight_on: usize, flashlight_vector: *mut f32) -> Result<()> {
        self.player_character_flag = player_character_flag;
        self.inc_item_count = Some(unsafe { std::mem::transmute(inc_item_count) });
        self.add_item_to_inventory = Some(unsafe { std::mem::transmute(add_item_to_inventory) });
        self.set_new_game_plus_item_flag = Some(unsafe { std::mem::transmute(set_new_game_plus_item_flag) });
        self.unk_grunt_sound_value = Some(unsafe { std::mem::transmute(grunt_sound_selector) });
        self.is_flashlight_on = Some(unsafe { std::mem::transmute(is_flashlight_on) });
        self.weapon_info = weapon_info;
        self.sound_param_data = sound_param_data;
        self.inventory = inventory;
        self.main_menu_state = main_menu_state;
        self.flashlight_vector = flashlight_vector;

        unsafe {
            self.init_weapon_animations();
        }
        self.load_item_messages()
    }

    unsafe fn init_weapon_animations(&mut self) {
        let james_weapon_end = self.weapon_info.offset(9);
        let maria_weapon_cleaver = self.weapon_info.offset(12);
        let maria_weapon_end = self.weapon_info.offset(13);

        james_weapon_end.copy_from_nonoverlapping(maria_weapon_cleaver, 1); // replace James' end marker with the cleaver
        maria_weapon_cleaver.copy_from_nonoverlapping(maria_weapon_end, 1); // replace the cleaver with the end marker

        // we now have every weapon in one big list, but we'll still start Maria at the old start of her list
        // so she gets the proper animation for no weapon

        // now record the default animation files
        let weapon_info = self.weapon_info();
        self.default_animation_files = [
            weapon_info[1].animation,
            weapon_info[2].animation,
            weapon_info[3].animation,
            weapon_info[4].animation,
            weapon_info[5].animation,
            weapon_info[6].animation,
            weapon_info[7].animation,
            weapon_info[8].animation,
            weapon_info[9].animation,
            // skip over Maria's no-weapon animation
            weapon_info[11].animation,
        ];
    }

    fn load_message_file(name: &str, language: char) -> Result<game::MessageFile> {
        let mut string = format!("sh2e/etc/message/{name}_msg_{language}.mes");
        let mut path = Path::new(&string);
        if !path.exists() {
            string = format!("data/etc/message/{name}_msg_{language}.mes");
            path = Path::new(&string);
        }
        game::MessageFile::from_file(path).context(format!("Failed to load message file {string}"))
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
            builder.text(prefix);
            if !prefix.ends_with(' ') {
                builder.text(" ");
            }
            builder.control(game::ControlCode::Green);
            builder.text(item_name);
            builder.control(game::ControlCode::White);
            builder.text(".");
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
            // cutscenes. I've attempted to cobble together the verbiage for other languages from
            // pickup text for other items.
            if language == 'j' {
                message_file.add_message(&[0x03, 0xFF, 0x4C, 0x02, 0x3E, 0x02, 0x4D, 0x02, 0x32, 0x02, 0xFA, 0x00, 0x00, 0xFF, 0x01, 0x02, 0xEF, 0x07, 0xDA, 0x01, 0xAF, 0x0B, 0xFB, 0x01, 0xCE, 0x01, 0xFF, 0xFF, 0x00, 0x90]);
            } else {
                message_file.add_message(match language {
                    'f' => Self::pickup_message("J'ai un", "revolver"),
                    'g' => Self::pickup_message("Ich habe einen", "Revolver"),
                    'i' => Self::pickup_message("Ho preso un", "revolver"),
                    's' => Self::pickup_message("Tengo un", "revólver"),
                    _ => Self::pickup_message("I got a", "revolver"),
                }.as_slice());
            }
            message_file.add_message(&revolver_bullets);

            let [hyper_spray] = Self::load_messages("stage_toilet", language, [3])?;
            message_file.add_message(&hyper_spray);

            if language == 'j' {
                message_file.add_message(&[0x03, 0xFF, 0xBF, 0x0D, 0x29, 0x07, 0x00, 0xFF, 0x01, 0x02, 0xEF, 0x07, 0xDA, 0x01, 0xAF, 0x0B, 0xFB, 0x01, 0xCE, 0x01, 0xFF, 0xFF, 0x00, 0x90]);
            } else {
                message_file.add_message(match language {
                    'f' => Self::pickup_message("J'ai une", "planche de bois"),
                    'g' => Self::pickup_message("Ich habe ein", "Brett"),
                    'i' => Self::pickup_message("Ho preso una", "asse di legno"),
                    's' => Self::pickup_message("Tengo un", "tablón de madera"),
                    _ => Self::pickup_message("I got a", "wooden plank"),
                }.as_slice());
            }

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

    pub unsafe fn weapon_info(&self) -> &'static mut [game::WeaponInfo] {
        std::slice::from_raw_parts_mut(self.weapon_info, game::NUM_WEAPON_INFOS)
    }

    pub fn set_weapon_animations(&mut self) {
        let weapon_info = unsafe { self.weapon_info() };
        let is_player_maria = unsafe { self.is_player_maria() };

        if is_player_maria {
            // for Maria, we need to use our alternate animation files for all of James' weapons,
            // but we'll use the default animations for her own two weapons
            for i in 0..8 {
                weapon_info[i + 1].animation = &raw mut self.alternate_animation_files[i];
            }
            weapon_info[9].animation = self.default_animation_files[8];
            weapon_info[11].animation = self.default_animation_files[9];
        } else {
            // for James, we use the default animations for all of his weapons, but our alternate
            // animations for Maria's two weapons at the end
            for i in 0..8 {
                weapon_info[i + 1].animation = self.default_animation_files[i];
            }
            weapon_info[9].animation = &raw mut self.alternate_animation_files[8];
            weapon_info[11].animation = &raw mut self.alternate_animation_files[9];
        }
    }

    pub unsafe fn get_maria_weapon_offset(&self) -> isize {
        let equipped_item = self.equipped_item_id() as i16;
        let weapon_info = self.weapon_info();
        let maria_weapon_info = self.weapon_info.offset(10) as *const game::WeaponInfo;

        // the first entry is James' no-weapon entry, so we skip that for maria
        for info in &weapon_info[1..] {
            if info.item_id == -1 {
                break;
            }

            if info.item_id == equipped_item {
                return (&raw const *info).byte_offset_from(maria_weapon_info);
            }
        }

        log::error!("Failed to find weapon info for Maria's equipped item: {}", equipped_item);
        0
    }

    pub const unsafe fn is_player_maria(&self) -> bool {
        *self.player_character_flag == 1
    }

    pub const unsafe fn equipped_item_id(&self) -> i8 {
        (*self.inventory).equipped_item
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

    pub unsafe fn get_main_menu_state(&self) -> i32 {
        *self.main_menu_state
    }

    pub unsafe fn is_flashlight_on(&self) -> bool {
        self.is_flashlight_on.unwrap()()
    }

    pub unsafe fn flashlight_vector(&self) -> &'static mut [f32] {
        std::slice::from_raw_parts_mut(self.flashlight_vector, 3)
    }
}
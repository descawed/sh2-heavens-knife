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
    pub original_animation1: *mut game::AnimationRecord,
    pub original_animation2: *mut game::AnimationRecord,
    player_character_flag: *const u8,
    request_file_size: Option<unsafe extern "C" fn(file: *const game::FileInfo) -> usize>,
    get_character_buffers: Option<unsafe extern "C" fn(character_id: i32) -> *mut game::CharacterBuffers>,
    get_character_frame_size: Option<unsafe extern "C" fn(character_id: i32) -> usize>,
    draw_message_ptr: Option<unsafe extern "C" fn(*const u8)>,
    character_files: *mut game::CharacterFiles,
    character_files_end: *mut game::CharacterFiles,
    player_ptr: *mut *mut game::Character,
    james_weapon_animations: WeaponAnimationFiles,
    maria_weapon_animations: WeaponAnimationFiles,
    weapon_info: *mut game::WeaponInfo,
    unk_grunt_sound_value: Option<unsafe extern "C" fn() -> i32>,
    sound_param_data: *mut u8,
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
            original_animation1: std::ptr::null_mut(),
            original_animation2: std::ptr::null_mut(),
            player_character_flag: std::ptr::null(),
            request_file_size: None,
            get_character_buffers: None,
            get_character_frame_size: None,
            draw_message_ptr: None,
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
        }
    }

    pub fn init(&mut self, equipped_item_id: *mut i8, player_character_flag: *const u8, request_file_size: usize, get_character_buffers: usize,
            character_files: *mut game::CharacterFiles, character_files_end: *mut game::CharacterFiles, player_ptr: *mut *mut game::Character,
            get_character_frame_size: usize, weapon_info: *mut game::WeaponInfo, grunt_sound_selector: usize, sound_param_data: *mut u8,
            draw_message_ptr: usize) {
        self.equipped_item_id = equipped_item_id;
        self.player_character_flag = player_character_flag;
        self.request_file_size = Some(unsafe { std::mem::transmute(request_file_size) });
        self.get_character_buffers = Some(unsafe { std::mem::transmute(get_character_buffers) });
        self.get_character_frame_size = Some(unsafe { std::mem::transmute(get_character_frame_size) });
        self.draw_message_ptr = Some(unsafe { std::mem::transmute(draw_message_ptr) });
        self.character_files = character_files;
        self.character_files_end = character_files_end;
        self.player_ptr = player_ptr;
        self.weapon_info = weapon_info;
        self.unk_grunt_sound_value = Some(unsafe { std::mem::transmute(grunt_sound_selector) });
        self.sound_param_data = sound_param_data;
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

    pub unsafe fn print(&self, data: *const u8) {
        self.draw_message_ptr.unwrap()(data);
    }

    pub unsafe fn print_message(&self, msg: &game::Message) {
        self.print(msg.data());
    }
}
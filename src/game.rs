use std::ffi::{c_void, CStr};

use nalgebra::Unit;

mod msg;
pub use msg::*;

mod d3d;
pub use d3d::*;

#[repr(C)]
#[derive(Debug)]
pub struct IconCoords(pub u16, pub u16, pub u16); // x, y, edge

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DebugField {
    None,
    TransformMatrix,
    RotationMatrix,
    TranslationStartVector,
    TranslationEndVector,
    RotationAxis,
    Status,
}

impl DebugField {
    pub const fn get_name(&self) -> &'static str {
        match self {
            DebugField::None => "None",
            DebugField::TransformMatrix => "Transform",
            DebugField::RotationMatrix => "Rotation",
            DebugField::TranslationStartVector => "Translation Start",
            DebugField::TranslationEndVector => "Translation End",
            DebugField::RotationAxis => "Rotation Axis",
            DebugField::Status => "Status",
        }
    }

    pub const fn next(self) -> Self {
        match self {
            DebugField::None => DebugField::TransformMatrix,
            DebugField::TransformMatrix => DebugField::RotationMatrix,
            DebugField::RotationMatrix => DebugField::TranslationStartVector,
            DebugField::TranslationStartVector => DebugField::TranslationEndVector,
            DebugField::TranslationEndVector => DebugField::RotationAxis,
            DebugField::RotationAxis => DebugField::Status,
            DebugField::Status => DebugField::None,
        }
    }

    pub const fn prev(self) -> Self {
        match self {
            DebugField::None => DebugField::Status,
            DebugField::TransformMatrix => DebugField::None,
            DebugField::RotationMatrix => DebugField::TransformMatrix,
            DebugField::TranslationStartVector => DebugField::RotationMatrix,
            DebugField::TranslationEndVector => DebugField::TranslationStartVector,
            DebugField::RotationAxis => DebugField::TranslationEndVector,
            DebugField::Status => DebugField::RotationAxis,
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct AnimationRecord {
    pub next: *mut AnimationRecord,
    pub parent: *mut AnimationRecord,
    pub transform: D3DXMATRIX,
    pub translation_start: D3DXVECTOR4,
    pub rotation_end: D3DXMATRIX,
    pub translation_end: D3DXVECTOR4,
    pub rotation_axis: D3DXVECTOR4,
    pub rotation_angle: f32,
    pub rotation_axis_squared: D3DXVECTOR3,
    pub rotation_axis_cross_terms: D3DXVECTOR4,
    pub is_record_present: bool,
    pub unk_d9: u8,
    pub flag_from_header: u8,
    pub unk_db: u8,
    pub disabled: bool,
    pub pad_db: [u8; 3],
}

impl AnimationRecord {
    pub const fn new() -> Self {
        Self {
            next: std::ptr::null_mut(),
            parent: std::ptr::null_mut(),
            transform: D3DXMATRIX::new(),
            translation_start: D3DXVECTOR4::new(),
            rotation_end: D3DXMATRIX::new(),
            translation_end: D3DXVECTOR4::new(),
            rotation_axis: D3DXVECTOR4::new(),
            rotation_angle: 0.0,
            rotation_axis_squared: D3DXVECTOR3::new(),
            rotation_axis_cross_terms: D3DXVECTOR4::new(),
            is_record_present: false,
            unk_d9: 0,
            flag_from_header: 0,
            unk_db: 0,
            disabled: false,
            pad_db: [0; 3],
        }
    }

    pub fn get_debug_string(&self, field: DebugField) -> String {
        match field {
            DebugField::None => String::new(),
            DebugField::TransformMatrix => format!("{}", self.transform),
            DebugField::RotationMatrix => format!("{}", self.rotation_end),
            DebugField::TranslationStartVector => format!("{}", self.translation_start),
            DebugField::TranslationEndVector => format!("{}", self.translation_end),
            DebugField::RotationAxis => format!("{}, angle = {}", self.rotation_axis, self.rotation_angle),
            DebugField::Status => format!("next: {:#08X}, parent: {:#08X}, present: {}, disabled: {}", self.next as usize, self.parent as usize, self.is_record_present, self.disabled),
        }
    }

    pub const fn is_root(&self) -> bool {
        self.parent.is_null()
    }

    pub const fn parent(&self) -> Option<&AnimationRecord> {
        unsafe { self.parent.as_ref() }
    }

    pub const fn next(&self) -> Option<&AnimationRecord> {
        unsafe { self.next.as_ref() }
    }

    pub const fn next_mut(&self) -> Option<&mut AnimationRecord> {
        unsafe { self.next.as_mut() }
    }

    pub fn len(&self) -> usize {
        1 + match self.next() {
            Some(next) => next.len(),
            None => 0,
        }
    }

    pub const unsafe fn copy_to(&self, dest: *mut AnimationRecord) {
        // only want to copy the body, not the links
        let offset = std::mem::offset_of!(Self, transform);
        let size = size_of::<Self>() - offset;

        let offset = offset as isize;
        let src = (self as *const Self as *const u8).offset(offset);
        let dest = (dest as *mut u8).offset(offset);

        std::ptr::copy_nonoverlapping(src, dest, size);
    }

    pub unsafe fn copy_from_parent(&mut self) {
        let Some(parent) = self.parent.as_ref() else {
            return;
        };
        self.transform = parent.transform.clone();
        self.rotation_end = parent.rotation_end.clone();
        self.translation_start = parent.translation_start.clone();
        self.translation_end = parent.translation_end.clone();
        self.rotation_axis = parent.rotation_axis.clone();
        self.rotation_angle = parent.rotation_angle;
        self.rotation_axis_squared = parent.rotation_axis_squared.clone();
        self.rotation_axis_cross_terms = parent.rotation_axis_cross_terms.clone();
    }

    pub fn set_transform_components_basic(&mut self, rotation: &Mat4, translation: &Vec3) {
        self.rotation_end = rotation.into();
        self.translation_start = translation.insert_fixed_rows::<1>(3, 0.0).into();
        self.translation_end = self.translation_start.clone();
        self.rotation_angle = 0.0;
        self.rotation_axis = D3DXVECTOR4 { x: 0.0, y: 0.0, z: 1.0, w: 0.0 };
        self.rotation_axis_squared = D3DXVECTOR3 { x: 0.0, y: 0.0, z: 1.0 };
        self.rotation_axis_cross_terms = D3DXVECTOR4::new();
    }

    pub fn recalculate_transform(&mut self, t: f32, additional_rotation: Mat4, use_sibling_translation_for_root: bool) {
        let has_additional_rotation = !additional_rotation.is_identity(1e-6);

        let static_rotation = self.rotation_end.mat4();

        let rotation_axis = Unit::new_normalize(self.rotation_axis.vec3());
        let rotation_angle = self.rotation_angle * t;
        let dynamic_rotation = Mat4::from_axis_angle(&rotation_axis, rotation_angle);

        let rotation = static_rotation * dynamic_rotation;

        let translation_start = self.translation_start.vec3();
        let translation_end = self.translation_end.vec3();
        let translation = translation_start + (translation_end - translation_start) * t;

        self.transform = match self.parent() {
            Some(parent) => {
                let parent_transform = parent.transform.mat4();

                let mut final_transform = parent_transform * rotation;
                if has_additional_rotation {
                    final_transform = additional_rotation * final_transform;
                }
                final_transform.append_translation_mut(&parent_transform.transform_vector(&translation));

                final_transform.into()
            }
            None => {
                let mut final_transform = rotation;
                if has_additional_rotation {
                    final_transform = additional_rotation * final_transform;
                }

                if use_sibling_translation_for_root {
                    if let Some(sibling) = self.next() {
                        let sibling_transform = sibling.transform.mat4();
                        final_transform.set_column(3, &sibling_transform.column(3));
                    }
                } else {
                    final_transform.append_translation_mut(&translation);
                }

                final_transform.into()
            }
        };

        // now we need to recalculate any children that were using the old transform
        let this = &raw mut *self;
        let mut next = self.next_mut();
        while let Some(child) = next {
            if child.parent == this {
                child.recalculate_transform(t, additional_rotation, use_sibling_translation_for_root);
            }
            next = child.next_mut();
        }
    }
}

impl Default for AnimationRecord {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Sound3dParameters {
    pub unk00: f32,
    pub start_frame: i8,
    pub unk05: i8,
    pub unk06: u16,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub path: *const std::ffi::c_char,
    pub size: isize,
    pub offset: usize,
    pub flags: u32,
}

impl FileInfo {
    pub const fn new(path: &'static CStr) -> Self {
        Self {
            path: path.as_ptr(),
            size: -1,
            offset: 0,
            flags: 1,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct WeaponInfo {
    pub item_id: i16,
    pub object_id: i16,
    pub animation: *mut FileInfo,
    pub model1: *mut FileInfo,
    pub model2: *mut FileInfo,
    pub kg1: *mut FileInfo,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct CharacterBuffers {
    pub character_id: i32,
    pub unk04: u32,
    pub model_buffer1: *mut u8,
    pub model_buffer2: *mut u8,
    pub model_data_ptr: *mut u8,
    pub animation_buffer: *mut u8,
    pub cls_buffer: *mut u8,
    pub kg1_buffer: *mut u8,
    pub unk20: [u8; 116],
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct LoadedFile {
    pub file_info: *const FileInfo,
    pub buffer: *mut u8,
    pub size: usize,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeaponType {
    None = 0,
    Handgun = 1,
    Shotgun = 2,
    Rifle = 3,
    HyperSpray = 4,
    WoodenPlank = 5,
    SteelPipe = 6,
    Chainsaw = 7,
    GreatKnife = 8,
    Revolver = 9,
    Cleaver = 10,
}

impl WeaponType {
    pub const fn from_item_id(item_id: u8) -> Self {
        match item_id {
            4 => Self::Handgun,
            6 => Self::Shotgun,
            8 => Self::Rifle,
            10 => Self::Revolver,
            12 => Self::HyperSpray,
            13 => Self::WoodenPlank,
            14 => Self::SteelPipe,
            15 => Self::GreatKnife,
            16 => Self::Chainsaw,
            17 => Self::Cleaver,
            _ => Self::None,
        }
    }

    pub const fn does_bone_animate(&self, bone_index: usize) -> bool {
        match self {
            Self::Handgun => bone_index == 27 || bone_index == 28, // shoulders
            Self::Rifle => bone_index >= 8 && bone_index <= 10, // head/neck
            Self::Revolver => bone_index == 21 || bone_index == 23, // shoulders
            _ => false,
        }
    }
}

const JAMES_FILE_PATH: &[u8] = b"data/chr/jms/";
const MARIA_FILE_PATH: &[u8] = b"data/chr2/mar/";

#[repr(C)]
#[derive(Debug, Clone)]
pub struct CharacterFiles {
    pub unk00: u8,
    pub unk01: u8,
    pub character_id: i16,
    pub model: LoadedFile,
    pub animation: LoadedFile,
    pub kg1: LoadedFile,
    pub cls: LoadedFile,
}

impl CharacterFiles {
    unsafe fn animation_path_contains(&self, search: &[u8]) -> bool {
        let Some(animation_file) = self.animation.file_info.as_ref() else {
            return false;
        };

        let animation_path = CStr::from_ptr(animation_file.path);
        animation_path.to_bytes().windows(search.len()).any(|window| window == search)
    }

    pub unsafe fn is_using_james_animation(&self) -> bool {
        self.animation_path_contains(JAMES_FILE_PATH)
    }

    pub unsafe fn is_using_maria_animation(&self) -> bool {
        self.animation_path_contains(MARIA_FILE_PATH)
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct AnimationDescription {
    pub id: u16,
    pub num_frames: u16,
    pub unk04: i16,
    pub frame_index_start: u16,
    pub frame_index_end: u16,
    pub unk0a: u16,
}

impl AnimationDescription {
    pub fn set_start_index(&mut self, index: usize) {
        self.frame_index_start = index as u16;
        self.frame_index_end = (self.frame_index_start + self.num_frames) - 1;
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Animation {
    pub records: *mut AnimationRecord,
    pub data_start: *const u8,
    pub data_cursor: *const u8,
    pub original_data_start: *const u8,
    pub original_data_cursor: *const u8,
    pub frame_size: usize,
    pub anim_steps_elapsed: i32,
    pub frame_steps_elapsed1: u32,
    pub frame_steps_elapsed2: u32,
    pub unk24: i16,
    pub unk26: u16,
    pub unk28: i16,
    pub unk2a: i16,
    pub current_frame_index: u16,
    pub next_frame_index: u16,
    pub unk30: u8, // think this flags whether this animation is for a weapon
    pub state: i8,
    pub unk32: u16,
    pub description1: *const AnimationDescription,
    pub description2: *const AnimationDescription,
    pub look_rotation: D3DXVECTOR4,
    pub equipped_weapon_rotation: D3DXVECTOR4,
    pub rot_vec5c: D3DXVECTOR4,
    pub rot_vec6c: D3DXVECTOR4,
    pub unk7c: f32,
}

impl Animation {
    pub const fn is_playing_hit_reaction(&self) -> bool {
        self.next_frame_index as usize >= WEAPON_ANIM_NUM_FRAMES
    }

    pub const fn frame_progress(&self) -> f32 {
        (4096 - self.frame_steps_elapsed1) as f32 / 4096.0
    }

    pub fn root_rotation(&self) -> Mat4 {
        Mat4::from_euler_angles(self.rot_vec5c.x, self.rot_vec5c.y + self.rot_vec6c.y, 0.0)
    }

    pub fn num_records(&self) -> usize {
        self.record(0).map(AnimationRecord::len).unwrap_or(0)
    }

    pub fn recalculate_bone_transform(&mut self, bone_index: usize, is_james: bool, equipped_weapon: WeaponType) {
        let record = unsafe { self.records.offset(bone_index as isize).as_mut() }.unwrap();

        let mut additional_rotation = Mat4::identity();
        let mut use_sibling_translation = false;

        if record.is_root() {
            // there's additional animation calculation behavior associated with this condition that we
            // don't handle, because, as far as I can tell, unk30 is never set for players. but we will
            // at least check for it and warn.
            if self.unk30 == 1 {
                log::warn!("Ignoring unk30 flag for root animation record {}", bone_index);
            }

            if bone_index == 0 {
                additional_rotation = self.root_rotation() * additional_rotation;
                use_sibling_translation = true;
            }
        } else {
            // apply look rotation if this is the appropriate head/neck bone
            if (is_james && bone_index == 8) || (!is_james && bone_index == 6) {
                additional_rotation = self.look_rotation.rotation_matrix() * additional_rotation;
            }

            // apply equipped weapon rotation as appropriate
            // FIXME: this assumes that we don't need to check the player character because each
            //  weapon is associated with only a single animation, but that won't be true if I
            //  patch the revolver/handgun animations
            if equipped_weapon.does_bone_animate(bone_index) {
                additional_rotation = self.equipped_weapon_rotation.rotation_matrix() * additional_rotation;
            }
        }

        record.recalculate_transform(self.frame_progress(), additional_rotation, use_sibling_translation);
    }

    pub const fn record(&self, bone_index: usize) -> Option<&AnimationRecord> {
        unsafe { self.records.offset(bone_index as isize).as_ref() }
    }

    pub const fn record_mut(&self, bone_index: usize) -> Option<&mut AnimationRecord> {
        unsafe { self.records.offset(bone_index as isize).as_mut() }
    }

    pub fn dump_transforms(&self) {
        for i in 0..self.num_records() {
            let record = self.record(i).unwrap();
            match record.parent() {
                Some(parent) => {
                    let parent_transform = parent.transform.mat4();
                    let this_transform = record.transform.mat4();

                    let rel_mat = get_transform(&parent_transform, &this_transform);
                    let (rel_rot, rel_trans) = get_split_transform(&parent_transform, &this_transform);

                    log::debug!("Bone {}: transform = {}, parent transform = {}, relative transform = {}, relative rotation = {}, relative translation = {}", i, this_transform, parent_transform, rel_mat, rel_rot, rel_trans);
                }
                None => {
                    log::debug!("Root bone {}: transform = {}", i, record.transform.mat4());
                }
            }
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct HitInformation {
    pub vec00: D3DXVECTOR4,
    pub vec10: D3DXVECTOR4,
    pub attack_id: u16,
    pub unk22: u16,
    pub unk24: u32,
    pub damage_received: f32,
    pub unk_hit_value2c: f32,
    pub hit_received_type: u32,
    pub unk30: [u8; 16],
    pub unk44: *const c_void,
    pub current_health: f32,
    pub max_health: f32,
    pub current_health_percent: f32,
    pub flags54: u32,
    pub unk58: [u8; 20],
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Character {
    pub float000: f32,
    pub flags004: u32,
    pub unk008: u32,
    pub unk00c: u32,
    pub id: i16,
    pub id_counter: u16,
    pub unk014: u32,
    pub unk018: u32,
    pub position: D3DXVECTOR4,
    pub rotation: D3DXVECTOR4,
    pub unk03c: D3DXVECTOR4,
    pub unk04c: D3DXVECTOR4,
    pub transform: D3DXMATRIX,
    pub animation_records: *mut AnimationRecord,
    pub unk0a0: f32,
    pub unk0a4: f32,
    pub unk0a8: u32,
    pub unk0ac: u32,
    pub unk0b0: u32,
    pub unk0b4: f32,
    pub vec0b8: D3DXVECTOR4,
    pub unk0c8: f32,
    pub prev_position: D3DXVECTOR4,
    pub prev_rotation: D3DXVECTOR4,
    pub unk0ec: u32,
    pub unk0f0: u32,
    pub hit_information: HitInformation,
    pub unk160: [u8; 40],
    pub unk188: *const c_void,
    pub unk18c: u32,
    pub prev: *mut Character,
    pub next: *mut Character,
    pub weapon_index: i8,
    pub unk199: [u8; 3],
    pub unk19c: u32,
    pub animation1: Animation,
    pub animation2: Animation,
    pub unk2a0: *const c_void,
    pub model_buffer2: *mut u8,
    pub model_buffer3: *mut u8,
    pub model_buffer4: *mut u8,
    pub unk2b0: u32,
    pub unk2b4: u32,
    pub model_buffer1: *mut u8,
    pub animation_buffer: *mut u8,
    pub cls_buffer: *mut u8,
    pub unk2c4: [u8; 8],
}

impl Character {
    pub const fn is_playing_hit_reaction(&self) -> bool {
        self.animation1.is_playing_hit_reaction() || self.animation2.is_playing_hit_reaction()
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct Inventory {
    pub flags: [u32; 3],
    pub counts: [u16; 13], // only tracks counts for items where the count is significant
    pub unk26: u8,
    pub unk27: u8,
    pub unk28: u8,
    pub equipped_item: i8,
    pub unk2a: u16,
    pub unk2c: f32,
    pub unk30: u16,
    pub unk32: u16,
    pub unk34: u16,
    pub unk36: u16,
    pub active_weapon_item: i8,
    pub unk39: u8,
    pub unk3a: u16,
}

impl Inventory {
    pub const fn add_item(&mut self, item_id: i8) {
        if item_id > 0 {
            self.flags[(item_id as usize) >> 5] |= 1 << (item_id & 0x1F);
        }
    }

    pub const fn set_item_count(&mut self, item_id: i8, count: u16) {
        if item_id > 0 {
            let index = item_id as usize;
            if index < self.counts.len() {
                self.counts[index] = count;
            }
        }
    }

    pub const fn clear(&mut self) {
        self.flags = [0; 3];
        self.counts = [0; 13];
        self.unk26 = 0;
        self.unk27 = 0;
        self.unk28 = 0;
        self.equipped_item = 0;
        self.unk2a = 0;
        self.unk2c = 0.0;
        self.unk30 = 0;
        self.unk32 = 0;
        self.unk34 = 0;
        self.unk36 = 0;
        self.active_weapon_item = 0;
        self.unk39 = 0;
        self.unk3a = 0;
    }
}

pub const LANGUAGES: &str = "jefgis";
pub const NUM_LANGUAGES: usize = LANGUAGES.len();

pub const JAMES_SKELETON: [i8; 41] = [
    -1,
    -1,
    0,
    2,
    1,
    1,
    4,
    5,
    3,
    3,
    3,
    3,
    3,
    6,
    7,
    8,
    11,
    12,
    9,
    10,
    15,
    15,
    15,
    16,
    17,
    13,
    14,
    9,
    10,
    25,
    26,
    27,
    28,
    31,
    32,
    34,
    33,
    33,
    34,
    34,
    33,
];

pub const JAMES_NUM_BONES: usize = JAMES_SKELETON.len();

pub const MARIA_SKELETON: [i8; 36] = [
    -1,
    -1,
    0,
    1,
    2,
    1,
    4,
    3,
    5,
    6,
    7,
    4,
    4,
    3,
    3,
    8,
    4,
    4,
    5,
    5,
    10,
    11,
    15,
    16,
    20,
    21,
    22,
    23,
    25,
    27,
    28,
    28,
    29,
    29,
    30,
    32,
];

// value = James, index = Maria
pub const MARIA_TO_JAMES_SKELETON_MAP: [isize; 36] = [
    0,  // 0
    1,  // 1
    2,  // 2
    4,  // 3
    3,  // 4
    5,  // 5
    8,  // 6
    6,  // 7
    7,  // 8
    15, // 9
    13, // 10
    9,  // 11
    -1, // 12
    -1, // 13
    -1, // 14
    14, // 15
    10, // 16
    -1, // 17
    -1, // 18
    -1, // 19
    25, // 20
    27, // 21
    26, // 22
    28, // 23
    29, // 24
    31, // 25
    30, // 26
    32, // 27
    33, // 28
    34, // 29
    40, // 30
    -1, // 31
    35, // 32
    -1, // 33
    36, // 34
    39, // 35
];

pub const MARIA_NUM_BONES: usize = MARIA_TO_JAMES_SKELETON_MAP.len();

pub const NUM_ITEMS: usize = 90;
pub const NUM_WEAPON_INFOS: usize = 14;
pub const MARIA_ANIMATION_FRAME_SIZE: usize = 464;
pub const JAMES_ANIMATION_FRAME_SIZE: usize = 528;

pub const JAMES_IDS: [i16; 2] = [256, 257];
pub const MARIA_ID: i16 = 270; // this ID is specifically for Maria as the player, not as an NPC

pub const JAMES_WEAPON_ANIM_SIZE: usize = 540672;
pub const MARIA_WEAPON_ANIM_SIZE: usize = 579536;
pub const WEAPON_ANIM_NUM_FRAMES: usize = 1024;

pub const MARIA_NUM_HIT_REACTIONS: usize = 11;
pub const MARIA_ANIM_HIT_REACTIONS_START_OFFSET: usize = WEAPON_ANIM_NUM_FRAMES * MARIA_ANIMATION_FRAME_SIZE;
pub const MARIA_HIT_REACTIONS_ANIM_SIZE: usize = MARIA_WEAPON_ANIM_SIZE - MARIA_ANIM_HIT_REACTIONS_START_OFFSET;

pub const MARIA_MIN_FRAMES_FOR_JAMES_ANIM: usize = JAMES_WEAPON_ANIM_SIZE.div_ceil(MARIA_ANIMATION_FRAME_SIZE);
pub const MARIA_BYTES_FOR_JAMES_ANIM: usize = MARIA_MIN_FRAMES_FOR_JAMES_ANIM * MARIA_ANIMATION_FRAME_SIZE;
pub const MARIA_ANIM_BUFFER_BYTES_NEEDED: usize = MARIA_BYTES_FOR_JAMES_ANIM + MARIA_HIT_REACTIONS_ANIM_SIZE;

pub const HANDGUN_RELOAD_SOUND_ID: u32 = 11029;
pub const SHOTGUN_SOUND_ID1: u32 = 11068;
pub const SHOTGUN_SOUND_ID2: u32 = 11053;
pub const RIFLE_RELOAD_SOUND_ID: u32 = 11050;
pub const HYPER_SPRAY_RELOAD_SOUND_ID: u32 = 11055;
pub const CLEAVER_ATTACK_SOUND_ID: u32 = 17034;
pub const GREAT_KNIFE_ATTACK_SOUND_ID: u32 = 11039;
pub const GREAT_KNIFE_DRAG_SOUND_ID: u32 = 11067;
pub const DEFAULT_MELEE_ATTACK_SOUND_ID: u32 = 11027;
pub const JAMES_GRUNT_SOUND_ID: u32 = 11018;
pub const MARIA_GRUNT_SOUND_ID: u32 = 17030;

/*
  weaponItemIds[0] = -1;                             // none
  weaponItemIds[1] = 4;                              // handgun
  weaponItemIds[2] = 6;                              // shotgun
  weaponItemIds[3] = 8;                              // rifle
  weaponItemIds[4] = 12;                             // hyper spray
  weaponItemIds[5] = 13;                             // wooden plank
  weaponItemIds[6] = 14;                             // steel pipe
  weaponItemIds[7] = 16;                             // chainsaw
  weaponItemIds[8] = 15;                             // great knife
  weaponItemIds[9] = 10;                             // revolver
  weaponItemIds[10] = 17;                            // cleaver
 */
pub const ITEM_ID_NONE: i8 = -1;
pub const ITEM_ID_NOTHING: i8 = 0;
pub const ITEM_ID_HEALTH_DRINK: i8 = 1;
pub const ITEM_ID_FIRST_AID_KIT: i8 = 2;
pub const ITEM_ID_AMPOULE: i8 = 3;
pub const ITEM_ID_HANDGUN: i8 = 4;
pub const ITEM_ID_HANDGUN_BULLETS: i8 = 5;
pub const ITEM_ID_SHOTGUN: i8 = 6;
pub const ITEM_ID_SHOTGUN_SHELLS: i8 = 7;
pub const ITEM_ID_RIFLE: i8 = 8;
pub const ITEM_ID_RIFLE_SHELLS: i8 = 9;
pub const ITEM_ID_REVOLVER: i8 = 10;
pub const ITEM_ID_REVOLVER_BULLETS: i8 = 11;
pub const ITEM_ID_HYPER_SPRAY: i8 = 12;
pub const ITEM_ID_WOODEN_PLANK: i8 = 13;
pub const ITEM_ID_STEEL_PIPE: i8 = 14;
pub const ITEM_ID_GREAT_KNIFE: i8 = 15;
pub const ITEM_ID_CHAINSAW: i8 = 16;
pub const ITEM_ID_CLEAVER: i8 = 17;
pub const ITEM_ID_PHOTO_OF_MARY: i8 = 20;
pub const ITEM_ID_LETTER_FROM_MARY: i8 = 21;
pub const ITEM_ID_WHITE_LIQUID: i8 = 85;
pub const NUM_WEAPON_AMMO_ITEMS: usize = (ITEM_ID_CLEAVER - ITEM_ID_HANDGUN + 1) as usize;
pub const MAX_ITEM_COUNT: u16 = 999;

// the last 4 item slots referenced by icon stuff appear to be unused
pub const NUM_USABLE_ITEMS: usize = 86;

pub const ITEM_NAMES: [&'static str; NUM_USABLE_ITEMS] = [
    "Nothing",
    "Health drink",
    "First-aid kit",
    "Ampoule",
    "Handgun",
    "Handgun bullets",
    "Shotgun",
    "Shotgun shells",
    "Hunting rifle",
    "Rifle shells",
    "Revolver",
    "Revolver bullets",
    "Hyper spray",
    "Wooden plank",
    "Steel pipe",
    "Great knife",
    "Chainsaw",
    "Chinese cleaver",
    "Flashlight",
    "Radio",
    "Photo of Mary",
    "Letter from Mary",
    "Laura's Letter",
    "Videotape",
    "Angela's knife",
    "Dog key",
    "Apartment gate key",
    "Key to room 202",
    "Clock key",
    "Courtyard key",
    "Fire escape key",
    "Lyne house key",
    "Apartment stairway key",
    "Examination room key",
    "Roof key",
    "\"Purple Bull\" key",
    "\"Lapis Eye\" key",
    "Elevator key",
    "Basement storeroom key",
    "Hospital lobby key",
    "Old bronze key",
    "Spiral-writing key",
    "Key of the Persecuted",
    "Key to hotel room 312",
    "Key to hotel room 204",
    "Employee elevator key",
    "Bar key",
    "\"Fish\" key",
    "Hotel stairway key",
    "Canned juice",
    "Coin [Snake]",
    "Coin [Old Man]",
    "Coin [Prisoner]",
    "Piece of hair",
    "Bent needle",
    "Dry cell battery",
    "Copper ring",
    "Lead ring",
    "Wrench",
    "Tablet of \"The Oppressor\"",
    "Tablet of \"Gluttonous Pig\"",
    "Tablet of \"The Seductress\"",
    "Horseshoe",
    "Lighter",
    "Wax doll",
    "Wire cutter",
    "Thinner",
    "\"Little Mermaid\" music box",
    "\"Cinderella\" music box",
    "\"Snow White\" music box",
    "Can opener",
    "Light bulb",
    "Rust-colored egg",
    "Scarlet egg",
    "Book: \"Lost Memories\"",
    "Book: \"Crimson Ceremony\"",
    "White chrism",
    "Obsidian goblet",
    "Blue Gem",
    "White Board",
    "Black Board",
    "Red Board",
    "Acacia key",
    "Matches",
    "Birthday card and present",
    "White liquid",
];

pub const fn item_name(item_id: i8) -> &'static str {
    ITEM_NAMES[item_id as usize]
}

pub const ICON_COORDS: [IconCoords; NUM_ITEMS] = [
    IconCoords(20, 0, 97),
    IconCoords(123, 0, 225),
    IconCoords(236, 0, 338),
    IconCoords(363, 0, 436),
    IconCoords(460, 0, 564),
    IconCoords(570, 0, 680),
    IconCoords(700, 0, 770),
    IconCoords(790, 0, 868),
    IconCoords(900, 0, 954),
    IconCoords(973, 0, 999),
    IconCoords(26, 128, 100),
    IconCoords(120, 128, 214),
    IconCoords(214, 128, 311),
    IconCoords(330, 128, 422),
    IconCoords(435, 128, 527),
    IconCoords(560, 128, 604),
    IconCoords(640, 128, 722),
    IconCoords(745, 128, 808),
    IconCoords(825, 128, 900),
    IconCoords(937, 128, 981),
    IconCoords(24, 256, 96),
    IconCoords(118, 256, 185),
    IconCoords(208, 256, 286),
    IconCoords(298, 256, 386),
    IconCoords(397, 256, 480),
    IconCoords(490, 256, 578),
    IconCoords(586, 256, 690),
    IconCoords(696, 256, 787),
    IconCoords(794, 256, 900),
    IconCoords(922, 256, 992),
    IconCoords(12, 384, 112),
    IconCoords(137, 384, 196),
    IconCoords(220, 384, 304),
    IconCoords(323, 384, 414),
    IconCoords(424, 384, 515),
    IconCoords(535, 384, 616),
    IconCoords(633, 384, 728),
    IconCoords(738, 384, 826),
    IconCoords(840, 384, 935),
    IconCoords(943, 384, 999),
    IconCoords(26, 512, 104),
    IconCoords(120, 512, 215),
    IconCoords(224, 512, 318),
    IconCoords(330, 512, 420),
    IconCoords(425, 512, 517),
    IconCoords(520, 512, 613),
    IconCoords(618, 512, 708),
    IconCoords(712, 512, 822),
    IconCoords(828, 512, 918),
    IconCoords(928, 512, 999),
    IconCoords(12, 640, 101),
    IconCoords(122, 640, 195),
    IconCoords(218, 640, 307),
    IconCoords(323, 640, 390),
    IconCoords(425, 640, 500),
    IconCoords(526, 640, 599),
    IconCoords(616, 640, 708),
    IconCoords(716, 640, 815),
    IconCoords(836, 640, 904),
    IconCoords(938, 640, 980),
    IconCoords(28, 768, 96),
    IconCoords(121, 768, 195),
    IconCoords(216, 768, 292),
    IconCoords(312, 768, 376),
    IconCoords(394, 768, 475),
    IconCoords(506, 768, 565),
    IconCoords(590, 768, 690),
    IconCoords(712, 768, 805),
    IconCoords(824, 768, 904),
    IconCoords(916, 768, 1001),
    IconCoords(24, 896, 100),
    IconCoords(138, 896, 180),
    IconCoords(214, 896, 264),
    IconCoords(300, 896, 404),
    IconCoords(424, 896, 500),
    IconCoords(522, 896, 598),
    IconCoords(618, 896, 708),
    IconCoords(724, 896, 820),
    IconCoords(843, 896, 898),
    IconCoords(920, 896, 999),
    // Maria items
    IconCoords(10, 1024, 92),
    IconCoords(121, 1024, 189),
    IconCoords(210, 1024, 295),
    IconCoords(310, 1024, 400),
    IconCoords(424, 1024, 495),
    IconCoords(14, 1152, 81),
    IconCoords(117, 1152, 184),
    IconCoords(210, 1152, 295),
    IconCoords(320, 1152, 388),
    IconCoords(938, 640, 980),
];

pub const ICON_ITEM_IDS: [u32; NUM_ITEMS] = [
    12, 6, 8, 14, 15, 16, 4, 24, 13, 0, 5, 7, 9, 65, 20, 18, 70, 57, 56, 55, 51, 52, 50, 60, 61,
    59, 68, 67, 69, 64, 19, 66, 27, 44, 43, 48, 46, 38, 40, 0, 28, 29, 37, 30, 45, 33, 42, 47, 26,
    0, 39, 31, 32, 35, 36, 34, 41, 0, 71, 76, 63, 74, 75, 54, 53, 1, 49, 21, 3, 25, 77, 72, 73, 2,
    62, 58, 23, 22, 78, 0,
    // Maria items
    84, 11, 10, 17, 79, 81, 80, 83, 82, 85,
];

pub const ICON_FLOATS: [f32; NUM_ITEMS] = [
    1.0,
    1.399999976158142,
    1.600000023841858,
    2.0999999046325684,
    1.600000023841858,
    1.2999999523162842,
    1.2999999523162842,
    1.100000023841858,
    1.600000023841858,
    1.100000023841858,
    1.100000023841858,
    0.8999999761581421,
    1.100000023841858,
    1.100000023841858,
    0.8999999761581421,
    1.0,
    1.100000023841858,
    1.100000023841858,
    1.100000023841858,
    1.100000023841858,
    1.100000023841858,
    1.100000023841858,
    1.100000023841858,
    1.100000023841858,
    1.100000023841858,
    1.100000023841858,
    1.100000023841858,
    1.100000023841858,
    1.100000023841858,
    0.800000011920929,
    1.2000000476837158,
    1.100000023841858,
    1.100000023841858,
    1.2000000476837158,
    1.2000000476837158,
    1.100000023841858,
    1.2999999523162842,
    1.2000000476837158,
    1.100000023841858,
    1.100000023841858,
    1.100000023841858,
    1.2000000476837158,
    1.399999976158142,
    1.100000023841858,
    1.2999999523162842,
    1.2000000476837158,
    1.100000023841858,
    1.399999976158142,
    1.100000023841858,
    1.100000023841858,
    1.2999999523162842,
    1.100000023841858,
    1.100000023841858,
    1.100000023841858,
    1.100000023841858,
    1.2000000476837158,
    1.2999999523162842,
    1.100000023841858,
    0.800000011920929,
    1.100000023841858,
    1.100000023841858,
    1.2999999523162842,
    1.2999999523162842,
    1.100000023841858,
    1.399999976158142,
    0.8999999761581421,
    1.399999976158142,
    1.0,
    1.100000023841858,
    1.100000023841858,
    1.100000023841858,
    1.2999999523162842,
    1.2999999523162842,
    1.100000023841858,
    0.8999999761581421,
    1.100000023841858,
    1.100000023841858,
    1.100000023841858,
    1.0,
    1.0,
    // Maria items
    1.0,
    1.0,
    1.0,
    1.0,
    1.0,
    1.0,
    1.0,
    1.0,
    1.0,
    1.0,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn animation_size() {
        assert_eq!(size_of::<AnimationRecord>(), 0xE0);
    }

    #[test]
    fn description_size() {
        assert_eq!(size_of::<AnimationDescription>(), 12);
    }

    #[test]
    fn character_size() {
        assert_eq!(size_of::<Character>(), 0x2cc);
    }

    fn inventory_size() {
        assert_eq!(size_of::<Inventory>(), 0x3c);
    }

    #[test]
    fn animation_file_size() {
        assert_eq!(JAMES_WEAPON_ANIM_SIZE % JAMES_ANIMATION_FRAME_SIZE, 0);
        assert_eq!(MARIA_WEAPON_ANIM_SIZE % MARIA_ANIMATION_FRAME_SIZE, 0);
    }

    #[test]
    fn override_animation_size() {
        assert!(MARIA_BYTES_FOR_JAMES_ANIM + MARIA_HIT_REACTIONS_ANIM_SIZE > MARIA_WEAPON_ANIM_SIZE);
    }
}
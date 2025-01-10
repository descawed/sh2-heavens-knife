use std::ffi::{c_void, CStr};

mod msg;
pub use msg::*;

#[repr(C)]
#[derive(Debug)]
pub struct IconCoords(pub u16, pub u16, pub u16); // x, y, edge

#[repr(C)]
#[derive(Clone, Debug)]
pub struct D3DXMATRIX {
    pub _11: f32,
    pub _12: f32,
    pub _13: f32,
    pub _14: f32,
    pub _21: f32,
    pub _22: f32,
    pub _23: f32,
    pub _24: f32,
    pub _31: f32,
    pub _32: f32,
    pub _33: f32,
    pub _34: f32,
    pub _41: f32,
    pub _42: f32,
    pub _43: f32,
    pub _44: f32,
}

impl D3DXMATRIX {
    pub const fn new() -> Self {
        Self {
            _11: 0.0,
            _12: 0.0,
            _13: 0.0,
            _14: 0.0,
            _21: 0.0,
            _22: 0.0,
            _23: 0.0,
            _24: 0.0,
            _31: 0.0,
            _32: 0.0,
            _33: 0.0,
            _34: 0.0,
            _41: 0.0,
            _42: 0.0,
            _43: 0.0,
            _44: 0.0,
        }
    }

    pub const fn identity() -> Self {
        Self {
            _11: 1.0,
            _12: 0.0,
            _13: 0.0,
            _14: 0.0,
            _21: 0.0,
            _22: 1.0,
            _23: 0.0,
            _24: 0.0,
            _31: 0.0,
            _32: 0.0,
            _33: 1.0,
            _34: 0.0,
            _41: 0.0,
            _42: 0.0,
            _43: 0.0,
            _44: 1.0,
        }
    }
}

impl Default for D3DXMATRIX {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for D3DXMATRIX {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{:>10.4} {:>10.4} {:>10.4} {:>10.4}]\n[{:>10.4} {:>10.4} {:>10.4} {:>10.4}]\n[{:>10.4} {:>10.4} {:>10.4} {:>10.4}]\n[{:>10.4} {:>10.4} {:>10.4} {:>10.4}]",
            self._11, self._12, self._13, self._14, self._21, self._22, self._23, self._24, self._31,
            self._32, self._33, self._34, self._41, self._42, self._43, self._44
        )
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct D3DXVECTOR4 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
    pub w: f32,
}

impl D3DXVECTOR4 {
    pub const fn new() -> Self {
        Self {
            x: 0.0,
            y: 0.0,
            z: 0.0,
            w: 0.0,
        }
    }
}

impl Default for D3DXVECTOR4 {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for D3DXVECTOR4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:>10.4} {:>10.4} {:>10.4} {:>10.4}]", self.x, self.y, self.z, self.w)
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct D3DXVECTOR3 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

impl D3DXVECTOR3 {
    pub const fn new() -> Self {
        Self {
            x: 0.0,
            y: 0.0,
            z: 0.0,
        }
    }
}

impl Default for D3DXVECTOR3 {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for D3DXVECTOR3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:>10.4} {:>10.4} {:>10.4}]", self.x, self.y, self.z)
    }
}

#[derive(Debug, Copy, Clone)]
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

    pub const unsafe fn copy_to(&self, dest: *mut AnimationRecord) {
        // only want to copy the body, not the links
        let offset = std::mem::offset_of!(Self, transform);
        let size = size_of::<Self>() - offset;

        let offset = offset as isize;
        let src = (self as *const Self as *const u8).offset(offset);
        let dest = (dest as *mut u8).offset(offset);

        std::ptr::copy_nonoverlapping(src, dest, size);
    }

    pub const fn set_identity(&mut self) {
        self.transform = D3DXMATRIX::identity();
        self.translation_start = D3DXVECTOR4::new();
        self.rotation_end = D3DXMATRIX::identity();
        self.translation_end = D3DXVECTOR4::new();
        self.rotation_axis = D3DXVECTOR4::new();
        self.rotation_angle = 0.0;
        self.rotation_axis_squared = D3DXVECTOR3::new();
        self.rotation_axis_cross_terms = D3DXVECTOR4::new();
    }

    pub const fn set_zero(&mut self) {
        self.transform = D3DXMATRIX::new();
        self.translation_start = D3DXVECTOR4::new();
        self.rotation_end = D3DXMATRIX::new();
        self.translation_end = D3DXVECTOR4::new();
        self.rotation_axis = D3DXVECTOR4::new();
        self.rotation_angle = 0.0;
        self.rotation_axis_squared = D3DXVECTOR3::new();
        self.rotation_axis_cross_terms = D3DXVECTOR4::new();
    }

    pub unsafe fn copy_from_parent(&mut self) {
        if self.parent.is_null() {
            return;
        }

        let parent = &mut *self.parent;
        self.transform = parent.transform.clone();
        self.rotation_end = parent.rotation_end.clone();
        self.translation_end = parent.translation_end.clone();
        self.rotation_axis = parent.rotation_axis.clone();
        self.rotation_angle = parent.rotation_angle;
        self.rotation_axis_squared = parent.rotation_axis_squared.clone();
        self.rotation_axis_cross_terms = parent.rotation_axis_cross_terms.clone();
    }
}

impl Default for AnimationRecord {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub path: *const std::ffi::c_char,
    pub size: usize,
    pub offset: usize,
    pub flags: u32,
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
    pub unk30: u8,
    pub state: i8,
    pub unk32: u16,
    pub description1: *const AnimationDescription,
    pub description2: *const AnimationDescription,
    pub rot_vec3c: D3DXVECTOR4,
    pub rot_vec4c: D3DXVECTOR4,
    pub rot_vec5c: D3DXVECTOR4,
    pub rot_vec6c: D3DXVECTOR4,
    pub unk7c: f32,
}

impl Animation {
    pub const fn is_playing_hit_reaction(&self) -> bool {
        self.next_frame_index as usize >= WEAPON_ANIM_NUM_FRAMES
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

// this is a handy reference even if it's not actively used right now
/*pub const MARIA_SKELETON: [i8; 36] = [
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
];*/

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
pub const WEAPON_INFO_SIZE: usize = 20;
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
use std::ffi::CStr;

mod msg;
pub use msg::*;

mod d3d;
pub use d3d::*;

#[repr(C)]
#[derive(Debug)]
pub struct IconCoords(pub u16, pub u16, pub u16); // x, y, edge

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
pub struct AnimationDescription {
    pub id: u16,
    pub num_frames: u16,
    pub unk04: i16,
    pub frame_index_start: u16,
    pub frame_index_end: u16,
    pub unk0a: u16,
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

#[repr(C)]
#[derive(Debug, Clone)]
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
    pub const fn new() -> Self {
        Self {
            flags: [0; 3],
            counts: [0; 13],
            unk26: 0,
            unk27: 0,
            unk28: 0,
            equipped_item: ITEM_ID_NOTHING,
            unk2a: 0,
            unk2c: 0.0,
            unk30: 0,
            unk32: 0,
            unk34: 0,
            unk36: 0,
            active_weapon_item: ITEM_ID_NOTHING,
            unk39: 0,
            unk3a: 0,
        }
    }

    pub fn iter_items(&self) -> impl Iterator<Item = (i8, Option<u16>)> + use<'_> {
        let flags = self.flags();
        (1..NUM_USABLE_ITEMS).into_iter().filter_map(move |item_id| {
            (flags & (1 << item_id) != 0).then(|| {
                let count = if item_id < self.counts.len() {
                    self.counts[item_id]
                } else {
                    0
                };
                let item_id = item_id as i8;
                (item_id, item_has_count(item_id).then_some(count))
            })
        })
    }

    pub const fn equip_item(&mut self, item_id: i8) {
        self.equipped_item = item_id;
        if item_id > 0 {
            self.add_item(item_id);
        }
    }

    pub const fn toggle_equip(&mut self, item_id: i8) {
        if self.equipped_item == item_id || !can_equip_item(item_id) {
            self.equipped_item = ITEM_ID_NOTHING;
        } else {
            self.equip_item(item_id);
        }
    }

    pub const fn add_item(&mut self, item_id: i8) {
        if item_id > 0 {
            self.flags[(item_id as usize) >> 5] |= 1 << (item_id & 0x1F);
        }
    }

    pub const fn remove_item(&mut self, item_id: i8) {
        self.flags[(item_id as usize) >> 5] &= !(1 << (item_id & 0x1F));
        self.set_count(item_id, 0);
    }

    pub const fn toggle_item(&mut self, item_id: i8) {
        if self.has_item(item_id) {
            self.remove_item(item_id);
        } else {
            self.add_item(item_id);
        }
    }
    
    pub const fn has_item(&self, item_id: i8) -> bool {
        if item_id < 0 || item_id > ITEM_ID_MAX {
            return false;
        }
        
        self.flags[(item_id as usize) >> 5] & (1 << (item_id & 0x1F)) != 0
    }

    pub const fn get_count(&self, item_id: i8) -> u16 {
        if item_id < 0 || item_id > self.counts.len() as i8 {
            0
        } else {
            self.counts[item_id as usize]
        }
    }

    pub const fn set_count(&mut self, item_id: i8, count: u16) {
        if item_id > 0 {
            let index = item_id as usize;
            if index < self.counts.len() {
                self.counts[index] = count;
                if count > 0 {
                    self.add_item(item_id);
                }
            }
        }
    }

    pub const fn flags(&self) -> u128 {
        (self.flags[0] as u128) | ((self.flags[1] as u128) << 32) | ((self.flags[2] as u128) << 64)
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

    pub fn ensure_consistent(&mut self) {
        if !can_equip_item(self.equipped_item) {
            self.equipped_item = ITEM_ID_NOTHING;
        }

        for (i, count) in self.counts.iter_mut().enumerate() {
            let item_id = i as i8;
            if *count > get_item_max_count(item_id) {
                *count = get_item_max_count(item_id);
            }

            if *count == 0 && item_count_must_be_nonzero(item_id) {
                self.flags[(item_id as usize) >> 5] &= !(1 << (item_id & 0x1F));
            }
        }
    }
}

pub const LANGUAGES: &str = "jefgis";
pub const NUM_LANGUAGES: usize = LANGUAGES.len();

pub const NUM_ITEMS: usize = 90;
pub const NUM_WEAPON_INFOS: usize = 14;
pub const MARIA_ANIMATION_FRAME_SIZE: usize = 464;
pub const JAMES_ANIMATION_FRAME_SIZE: usize = 528;

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

pub const ITEM_ID_MIN_WEAPON: i8 = ITEM_ID_HANDGUN;
pub const ITEM_ID_MAX_WEAPON: i8 = ITEM_ID_CLEAVER;
pub const ITEM_ID_MIN: i8 = ITEM_ID_HEALTH_DRINK;
pub const ITEM_ID_MAX: i8 = ITEM_ID_WHITE_LIQUID;
pub const NUM_WEAPON_AMMO_ITEMS: usize = (ITEM_ID_CLEAVER - ITEM_ID_HANDGUN + 1) as usize;
pub const MAX_ITEM_COUNT: u16 = 999;

// the last 4 item slots referenced by icon stuff appear to be unused
pub const NUM_USABLE_ITEMS: usize = 86;

pub const ITEM_NAMES: [&'static str; NUM_USABLE_ITEMS] = [
    "Nothing",                      // 0
    "Health drink",                 // 1
    "First-aid kit",                // 2
    "Ampoule",                      // 3
    "Handgun",                      // 4
    "Handgun bullets",              // 5
    "Shotgun",                      // 6
    "Shotgun shells",               // 7
    "Hunting rifle",                // 8
    "Rifle shells",                 // 9
    "Revolver",                     // 10
    "Revolver bullets",             // 11
    "Hyper spray",                  // 12
    "Wooden plank",                 // 13
    "Steel pipe",                   // 14
    "Great knife",                  // 15
    "Chainsaw",                     // 16
    "Chinese cleaver",              // 17
    "Flashlight",                   // 18
    "Radio",                        // 19
    "Photo of Mary",                // 20
    "Letter from Mary",             // 21
    "Laura's Letter",               // 22
    "Videotape",                    // 23
    "Angela's knife",               // 24
    "Dog key",                      // 25
    "Apartment gate key",           // 26
    "Key to room 202",              // 27
    "Clock key",                    // 28
    "Courtyard key",                // 29
    "Fire escape key",              // 30
    "Lyne house key",               // 31
    "Apartment stairway key",       // 32
    "Examination room key",         // 33
    "Roof key",                     // 34
    "\"Purple Bull\" key",          // 35
    "\"Lapis Eye\" key",            // 36
    "Elevator key",                 // 37
    "Basement storeroom key",       // 38
    "Hospital lobby key",           // 39
    "Old bronze key",               // 40
    "Spiral-writing key",           // 41
    "Key of the Persecuted",        // 42
    "Key to hotel room 312",        // 43
    "Key to hotel room 204",        // 44
    "Employee elevator key",        // 45
    "Bar key",                      // 46
    "\"Fish\" key",                 // 47
    "Hotel stairway key",           // 48
    "Canned juice",                 // 49
    "Coin [Snake]",                 // 50
    "Coin [Old Man]",               // 51
    "Coin [Prisoner]",              // 52
    "Piece of hair",                // 53
    "Bent needle",                  // 54
    "Dry cell battery",             // 55
    "Copper ring",                  // 56
    "Lead ring",                    // 57
    "Wrench",                       // 58
    "Tablet of \"The Oppressor\"",  // 59
    "Tablet of \"Gluttonous Pig\"", // 60
    "Tablet of \"The Seductress\"", // 61
    "Horseshoe",                    // 62
    "Lighter",                      // 63
    "Wax doll",                     // 64
    "Wire cutter",                  // 65
    "Thinner",                      // 66
    "\"Little Mermaid\" music box", // 67
    "\"Cinderella\" music box",     // 68
    "\"Snow White\" music box",     // 69
    "Can opener",                   // 70
    "Light bulb",                   // 71
    "Rust-colored egg",             // 72
    "Scarlet egg",                  // 73
    "Book: \"Lost Memories\"",      // 74
    "Book: \"Crimson Ceremony\"",   // 75
    "White chrism",                 // 76
    "Obsidian goblet",              // 77
    "Blue Gem",                     // 78
    "White Board",                  // 79
    "Black Board",                  // 80
    "Red Board",                    // 81
    "Acacia key",                   // 82
    "Matches",                      // 83
    "Birthday card and present",    // 84
    "White liquid",                 // 85
];

pub const fn item_name(item_id: i8) -> &'static str {
    ITEM_NAMES[item_id as usize]
}

pub const fn item_has_count(item_id: i8) -> bool {
    matches!(item_id,
            ITEM_ID_HYPER_SPRAY | ITEM_ID_HANDGUN_BULLETS | ITEM_ID_SHOTGUN_SHELLS
            | ITEM_ID_RIFLE_SHELLS | ITEM_ID_REVOLVER_BULLETS | ITEM_ID_HEALTH_DRINK
            | ITEM_ID_FIRST_AID_KIT | ITEM_ID_AMPOULE | ITEM_ID_HANDGUN | ITEM_ID_SHOTGUN
            | ITEM_ID_RIFLE | ITEM_ID_REVOLVER
        )
}

pub const fn get_item_max_count(item_id: i8) -> u16 {
    match item_id {
        ITEM_ID_NONE | ITEM_ID_NOTHING => 0,
        ITEM_ID_HANDGUN | ITEM_ID_REVOLVER => 10,
        ITEM_ID_SHOTGUN => 6,
        ITEM_ID_RIFLE => 4,
        ITEM_ID_HYPER_SPRAY => 8,
        _ => MAX_ITEM_COUNT,
    }
}

pub const fn can_equip_item(item_id: i8) -> bool {
    matches!(item_id,
            ITEM_ID_NOTHING | ITEM_ID_HANDGUN | ITEM_ID_SHOTGUN | ITEM_ID_RIFLE
            | ITEM_ID_REVOLVER | ITEM_ID_WOODEN_PLANK | ITEM_ID_STEEL_PIPE
            | ITEM_ID_GREAT_KNIFE | ITEM_ID_CHAINSAW | ITEM_ID_CLEAVER
            | ITEM_ID_HYPER_SPRAY
        )
}

pub const fn item_count_must_be_nonzero(item_id: i8) -> bool {
    matches!(item_id,
            ITEM_ID_HYPER_SPRAY | ITEM_ID_HANDGUN_BULLETS
            | ITEM_ID_SHOTGUN_SHELLS | ITEM_ID_RIFLE_SHELLS | ITEM_ID_REVOLVER_BULLETS
            | ITEM_ID_HEALTH_DRINK | ITEM_ID_FIRST_AID_KIT | ITEM_ID_AMPOULE
        )
}

pub const fn get_weapon_index(item_id: i8) -> u8 {
    match item_id {
        ITEM_ID_HANDGUN => 1,
        ITEM_ID_SHOTGUN => 2,
        ITEM_ID_RIFLE => 3,
        ITEM_ID_HYPER_SPRAY => 4,
        ITEM_ID_WOODEN_PLANK => 5,
        ITEM_ID_STEEL_PIPE => 6,
        ITEM_ID_CHAINSAW => 7,
        ITEM_ID_GREAT_KNIFE => 8,
        ITEM_ID_REVOLVER => 9,
        ITEM_ID_CLEAVER => 10,
        _ => 0,
    }
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

    fn inventory_size() {
        assert_eq!(size_of::<Inventory>(), 0x3c);
    }

    #[test]
    fn remove_inventory_item() {
        let mut inventory = Inventory {
            flags: [32784, 0, 0],
            counts: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            unk26: 0,
            unk27: 0,
            unk28: 0,
            equipped_item: 10,
            unk2a: 0,
            unk2c: 0.0,
            unk30: 0,
            unk32: 0,
            unk34: 0,
            unk36: 0,
            active_weapon_item: 0,
            unk39: 0,
            unk3a: 0,
        };

        assert!(inventory.has_item(ITEM_ID_HANDGUN));
        inventory.remove_item(ITEM_ID_HANDGUN);
        assert!(!inventory.has_item(ITEM_ID_HANDGUN));
    }
}
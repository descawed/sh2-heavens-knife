use windows::Win32::UI::Input::KeyboardAndMouse::*;

use crate::game;
use crate::game::ControlCode;
use crate::input;

#[derive(Debug, Clone)]
pub struct Inventory {
    equipped_item: i8,
    item_flags: u128,
    item_counts: [u16; game::NUM_USABLE_ITEMS],
}

impl Inventory {
    pub const fn new() -> Self {
        // default to great knife mode
        Self {
            equipped_item: game::ITEM_ID_GREAT_KNIFE,
            item_flags: 1 << game::ITEM_ID_GREAT_KNIFE,
            item_counts: [0; game::NUM_USABLE_ITEMS],
        }
    }

    pub fn iter_items(&self) -> impl Iterator<Item = (i8, Option<u16>)> + use<'_> {
        (1..game::NUM_USABLE_ITEMS).into_iter().filter_map(move |item_id| {
            (self.item_flags & (1 << item_id) != 0).then(|| {
                let count = self.item_counts[item_id];
                let item_id = item_id as i8;
                (item_id, Self::has_count(item_id).then_some(count))
            })
        })
    }

    pub const fn equip_item(&mut self, item_id: i8) {
        self.equipped_item = item_id;
        if item_id > 0 {
            self.item_flags |= 1 << item_id;
        }
    }

    pub const fn toggle_equip(&mut self, item_id: i8) {
        if self.equipped_item == item_id || !Self::can_equip(item_id) {
            self.equipped_item = game::ITEM_ID_NOTHING;
        } else {
            self.equip_item(item_id);
        }
    }

    pub const fn can_equip(item_id: i8) -> bool {
        matches!(item_id,
            game::ITEM_ID_NOTHING | game::ITEM_ID_HANDGUN | game::ITEM_ID_SHOTGUN | game::ITEM_ID_RIFLE
            | game::ITEM_ID_REVOLVER | game::ITEM_ID_WOODEN_PLANK | game::ITEM_ID_STEEL_PIPE
            | game::ITEM_ID_GREAT_KNIFE | game::ITEM_ID_CHAINSAW | game::ITEM_ID_CLEAVER
            | game::ITEM_ID_HYPER_SPRAY
        )
    }

    pub const fn has_count(item_id: i8) -> bool {
        matches!(item_id,
            game::ITEM_ID_HYPER_SPRAY | game::ITEM_ID_HANDGUN_BULLETS
            | game::ITEM_ID_SHOTGUN_SHELLS | game::ITEM_ID_RIFLE_SHELLS | game::ITEM_ID_REVOLVER_BULLETS
            | game::ITEM_ID_HEALTH_DRINK | game::ITEM_ID_FIRST_AID_KIT | game::ITEM_ID_AMPOULE
            | game::ITEM_ID_HANDGUN | game::ITEM_ID_SHOTGUN | game::ITEM_ID_RIFLE
            | game::ITEM_ID_REVOLVER
        )
    }

    pub const fn must_be_nonzero(item_id: i8) -> bool {
        matches!(item_id,
            game::ITEM_ID_HYPER_SPRAY | game::ITEM_ID_HANDGUN_BULLETS
            | game::ITEM_ID_SHOTGUN_SHELLS | game::ITEM_ID_RIFLE_SHELLS | game::ITEM_ID_REVOLVER_BULLETS
            | game::ITEM_ID_HEALTH_DRINK | game::ITEM_ID_FIRST_AID_KIT | game::ITEM_ID_AMPOULE
        )
    }

    pub const fn item_name(item_id: i8) -> &'static str {
        game::ITEM_NAMES[item_id as usize]
    }

    pub const fn add_item(&mut self, item_id: i8) {
        self.item_flags |= 1 << item_id;
        let index = item_id as usize;
        match item_id {
            game::ITEM_ID_HEALTH_DRINK | game::ITEM_ID_FIRST_AID_KIT | game::ITEM_ID_AMPOULE | game::ITEM_ID_REVOLVER => {
                self.item_counts[index] += 1;
            }
            game::ITEM_ID_HANDGUN | game::ITEM_ID_HANDGUN_BULLETS | game::ITEM_ID_REVOLVER_BULLETS => {
                self.item_counts[index] += 10;
            }
            game::ITEM_ID_SHOTGUN | game::ITEM_ID_SHOTGUN_SHELLS => {
                self.item_counts[index] += 6;
            }
            game::ITEM_ID_RIFLE | game::ITEM_ID_RIFLE_SHELLS => {
                self.item_counts[index] += 4;
            }
            game::ITEM_ID_HYPER_SPRAY => {
                self.item_counts[index] += 8;
            }
            _ => (),
        }

        if self.item_counts[index] > game::MAX_ITEM_COUNT {
            self.item_counts[index] = game::MAX_ITEM_COUNT;
        }
    }

    pub const fn remove_item(&mut self, item_id: i8) {
        self.item_flags &= !(1 << item_id);
        self.item_counts[item_id as usize] = 0;
    }

    pub const fn toggle_item(&mut self, item_id: i8) {
        if self.has_item(item_id) {
            self.remove_item(item_id);
        } else {
            self.add_item(item_id);
        }
    }

    pub const fn has_item(&self, item_id: i8) -> bool {
        self.item_flags & (1 << item_id) != 0
    }

    pub const fn get_count(&self, item_id: i8) -> u16 {
        self.item_counts[item_id as usize]
    }

    pub const fn set_count(&mut self, item_id: i8, count: u16) {
        self.item_counts[item_id as usize] = if count > game::MAX_ITEM_COUNT {
            game::MAX_ITEM_COUNT
        } else {
            count
        };
        if count > 0 {
            self.item_flags |= 1 << item_id;
        } else if Self::must_be_nonzero(item_id) {
            self.item_flags &= !(1 << item_id);
        }
    }

    pub const fn get_max_count(item_id: i8) -> u16 {
        match item_id {
            game::ITEM_ID_HANDGUN | game::ITEM_ID_REVOLVER => 10,
            game::ITEM_ID_SHOTGUN => 6,
            game::ITEM_ID_RIFLE => 4,
            game::ITEM_ID_HYPER_SPRAY => 8,
            _ => game::MAX_ITEM_COUNT,
        }
    }

    pub const fn equipped_item(&self) -> i8 {
        self.equipped_item
    }
}

#[derive(Debug, Clone)]
pub struct ScenarioConfig {
    weapon_ammo_mapping: [i8; game::NUM_WEAPON_AMMO_ITEMS],
    starting_inventory: Inventory,
}

#[derive(Debug, Clone)]
pub struct Config {
    is_enabled: bool,
    james_weapon_ammo_mapping: [i8; game::NUM_WEAPON_AMMO_ITEMS],
    maria_weapon_ammo_mapping: [i8; game::NUM_WEAPON_AMMO_ITEMS],
    james_starting_inventory: Inventory,
    maria_starting_inventory: Inventory,
}

impl Config {
    pub const fn new() -> Self {
        let mut this = Self {
            is_enabled: false,
            james_weapon_ammo_mapping: [
                game::ITEM_ID_HANDGUN,
                game::ITEM_ID_HANDGUN_BULLETS,
                game::ITEM_ID_SHOTGUN,
                game::ITEM_ID_SHOTGUN_SHELLS,
                game::ITEM_ID_RIFLE,
                game::ITEM_ID_RIFLE_SHELLS,
                game::ITEM_ID_REVOLVER,
                game::ITEM_ID_REVOLVER_BULLETS,
                game::ITEM_ID_HYPER_SPRAY,
                game::ITEM_ID_WOODEN_PLANK,
                game::ITEM_ID_STEEL_PIPE,
                game::ITEM_ID_GREAT_KNIFE,
                game::ITEM_ID_CHAINSAW,
                game::ITEM_ID_CLEAVER,
            ],
            maria_weapon_ammo_mapping: [
                game::ITEM_ID_HANDGUN,
                game::ITEM_ID_HANDGUN_BULLETS,
                game::ITEM_ID_SHOTGUN,
                game::ITEM_ID_SHOTGUN_SHELLS,
                game::ITEM_ID_RIFLE,
                game::ITEM_ID_RIFLE_SHELLS,
                game::ITEM_ID_REVOLVER,
                game::ITEM_ID_REVOLVER_BULLETS,
                game::ITEM_ID_HYPER_SPRAY,
                game::ITEM_ID_WOODEN_PLANK,
                game::ITEM_ID_STEEL_PIPE,
                game::ITEM_ID_GREAT_KNIFE,
                game::ITEM_ID_CHAINSAW,
                game::ITEM_ID_CLEAVER,
            ],
            james_starting_inventory: Inventory::new(),
            maria_starting_inventory: Inventory::new(),
        };

        // Maria must start with the revolver equipped
        this.maria_starting_inventory.equipped_item = game::ITEM_ID_REVOLVER;
        // give James his normal starting items as well
        this.james_starting_inventory.add_item(game::ITEM_ID_PHOTO_OF_MARY);
        this.james_starting_inventory.add_item(game::ITEM_ID_LETTER_FROM_MARY);

        this
    }
}

const fn weapon_ammo_item_name(item_id: i8) -> &'static str {
    match item_id {
        game::ITEM_ID_NONE => "None",
        game::ITEM_ID_HANDGUN => "Handgun",
        game::ITEM_ID_HANDGUN_BULLETS => "Handgun bullets",
        game::ITEM_ID_SHOTGUN => "Shotgun",
        game::ITEM_ID_SHOTGUN_SHELLS => "Shotgun shells",
        game::ITEM_ID_RIFLE => "Rifle",
        game::ITEM_ID_RIFLE_SHELLS => "Rifle shells",
        game::ITEM_ID_REVOLVER => "Revolver",
        game::ITEM_ID_REVOLVER_BULLETS => "Revolver bullets",
        game::ITEM_ID_HYPER_SPRAY => "Hyper spray",
        game::ITEM_ID_WOODEN_PLANK => "Wooden plank",
        game::ITEM_ID_STEEL_PIPE => "Steel pipe",
        game::ITEM_ID_GREAT_KNIFE => "Great knife",
        game::ITEM_ID_CHAINSAW => "Chainsaw",
        game::ITEM_ID_CLEAVER => "Cleaver",
        _ => "Unknown",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MainMenuOption {
    Enable,
    InventoryEditor,
    ItemMapper,
    Exit,
}

impl MainMenuOption {
    pub const fn previous(&self) -> Self {
        match self {
            Self::Enable => Self::Exit,
            Self::InventoryEditor => Self::Enable,
            Self::ItemMapper => Self::InventoryEditor,
            Self::Exit => Self::ItemMapper,
        }
    }

    pub const fn next(&self) -> Self {
        match self {
            Self::Enable => Self::InventoryEditor,
            Self::InventoryEditor => Self::ItemMapper,
            Self::ItemMapper => Self::Exit,
            Self::Exit => Self::Enable,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ItemMapperOption {
    Handgun,
    HandgunBullets,
    Shotgun,
    ShotgunShells,
    Rifle,
    RifleShells,
    Revolver,
    RevolverBullets,
    HyperSpray,
    WoodenPlank,
    SteelPipe,
    GreatKnife,
    Chainsaw,
    Cleaver,
    Exit,
}

impl ItemMapperOption {
    pub const fn item_id(&self) -> i8 {
        match self {
            Self::Handgun => game::ITEM_ID_HANDGUN,
            Self::HandgunBullets => game::ITEM_ID_HANDGUN_BULLETS,
            Self::Shotgun => game::ITEM_ID_SHOTGUN,
            Self::ShotgunShells => game::ITEM_ID_SHOTGUN_SHELLS,
            Self::Rifle => game::ITEM_ID_RIFLE,
            Self::RifleShells => game::ITEM_ID_RIFLE_SHELLS,
            Self::Revolver => game::ITEM_ID_REVOLVER,
            Self::RevolverBullets => game::ITEM_ID_REVOLVER_BULLETS,
            Self::HyperSpray => game::ITEM_ID_HYPER_SPRAY,
            Self::WoodenPlank => game::ITEM_ID_WOODEN_PLANK,
            Self::SteelPipe => game::ITEM_ID_STEEL_PIPE,
            Self::GreatKnife => game::ITEM_ID_GREAT_KNIFE,
            Self::Chainsaw => game::ITEM_ID_CHAINSAW,
            Self::Cleaver => game::ITEM_ID_CLEAVER,
            Self::Exit => game::ITEM_ID_NONE,
        }
    }

    pub const fn from_item_id(item_id: i8) -> Self {
        match item_id {
            game::ITEM_ID_HANDGUN => Self::Handgun,
            game::ITEM_ID_HANDGUN_BULLETS => Self::HandgunBullets,
            game::ITEM_ID_SHOTGUN => Self::Shotgun,
            game::ITEM_ID_SHOTGUN_SHELLS => Self::ShotgunShells,
            game::ITEM_ID_RIFLE => Self::Rifle,
            game::ITEM_ID_RIFLE_SHELLS => Self::RifleShells,
            game::ITEM_ID_REVOLVER => Self::Revolver,
            game::ITEM_ID_REVOLVER_BULLETS => Self::RevolverBullets,
            game::ITEM_ID_HYPER_SPRAY => Self::HyperSpray,
            game::ITEM_ID_WOODEN_PLANK => Self::WoodenPlank,
            game::ITEM_ID_STEEL_PIPE => Self::SteelPipe,
            game::ITEM_ID_GREAT_KNIFE => Self::GreatKnife,
            game::ITEM_ID_CHAINSAW => Self::Chainsaw,
            game::ITEM_ID_CLEAVER => Self::Cleaver,
            _ => Self::Exit,
        }
    }

    pub const fn name(&self) -> &'static str {
        if matches!(self, Self::Exit) {
            "Exit"
        } else {
            weapon_ammo_item_name(self.item_id())
        }
    }

    pub const fn previous(&self) -> Self {
        match self {
            Self::Handgun => Self::Exit,
            Self::HandgunBullets => Self::Handgun,
            Self::Shotgun => Self::HandgunBullets,
            Self::ShotgunShells => Self::Shotgun,
            Self::Rifle => Self::ShotgunShells,
            Self::RifleShells => Self::Rifle,
            Self::Revolver => Self::RifleShells,
            Self::RevolverBullets => Self::Revolver,
            Self::HyperSpray => Self::RevolverBullets,
            Self::WoodenPlank => Self::HyperSpray,
            Self::SteelPipe => Self::WoodenPlank,
            Self::GreatKnife => Self::SteelPipe,
            Self::Chainsaw => Self::GreatKnife,
            Self::Cleaver => Self::Chainsaw,
            Self::Exit => Self::Cleaver,
        }
    }

    pub const fn next(&self) -> Self {
        match self {
            Self::Handgun => Self::HandgunBullets,
            Self::HandgunBullets => Self::Shotgun,
            Self::Shotgun => Self::ShotgunShells,
            Self::ShotgunShells => Self::Rifle,
            Self::Rifle => Self::RifleShells,
            Self::RifleShells => Self::Revolver,
            Self::Revolver => Self::RevolverBullets,
            Self::RevolverBullets => Self::HyperSpray,
            Self::HyperSpray => Self::WoodenPlank,
            Self::WoodenPlank => Self::SteelPipe,
            Self::SteelPipe => Self::GreatKnife,
            Self::GreatKnife => Self::Chainsaw,
            Self::Chainsaw => Self::Cleaver,
            Self::Cleaver => Self::Exit,
            Self::Exit => Self::Handgun,
        }
    }
}

const MAX_ITEMS_PER_PAGE: i8 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    StatusIndicator,
    MainMenu(MainMenuOption),
    InventoryEditor(i8, i8),
    ItemMapper(ItemMapperOption),
}

#[derive(Debug)]
pub struct UserInterface {
    config: Config,
    draw_message_ptr: Option<unsafe extern "C" fn(*const u8)>,
    darkened_background_ptr: Option<unsafe extern "C" fn()>,
    message: game::Message,
    state: State,
    keyboard: input::Keyboard,
}

impl UserInterface {
    pub const fn new(config: Config) -> Self {
        Self {
            config,
            draw_message_ptr: None,
            darkened_background_ptr: None,
            message: game::Message::new(),
            state: State::StatusIndicator,
            keyboard: input::Keyboard::new(),
        }
    }

    fn draw_toggle(is_enabled: bool, builder: &mut game::MessageBuilder) {
        if is_enabled {
            builder.add_control_code(ControlCode::Green);
            builder.add_text("ON");
        } else {
            builder.add_control_code(ControlCode::Red);
            builder.add_text("OFF");
        }
    }

    const fn adjust_start_item(start_item: i8, selected_item: i8) -> i8 {
        let num_usable_items = game::NUM_USABLE_ITEMS as i8;
        let num_items_remaining = num_usable_items - start_item;
        if num_items_remaining < MAX_ITEMS_PER_PAGE {
            // we're wrapping around the end of the list
            if start_item <= selected_item && selected_item < num_usable_items {
                // selected item is in the end portion of the view
                return start_item;
            }

            let wrap_items = MAX_ITEMS_PER_PAGE - num_items_remaining;
            if selected_item > 0 && selected_item <= wrap_items {
                // selected item is in the beginning portion of the view
                return start_item;
            }

            if selected_item < start_item {
                // need to move the view back
                selected_item
            } else if selected_item >= MAX_ITEMS_PER_PAGE {
                // move the view forward so that it no longer wraps
                (selected_item - MAX_ITEMS_PER_PAGE) + 1
            } else {
                // move the view forward while still wrapping
                num_usable_items + (selected_item - MAX_ITEMS_PER_PAGE)
            }
        } else if start_item <= selected_item && start_item + MAX_ITEMS_PER_PAGE > selected_item {
            start_item
        } else if selected_item < start_item {
            selected_item
        } else {
            (selected_item - MAX_ITEMS_PER_PAGE) + 1
        }
    }

    pub fn show(&mut self, is_james: bool) {
        use crate::game::ControlCode;

        self.keyboard.update().expect("keyboard state update should not fail");

        // handle input for state
        match self.state {
            State::StatusIndicator => {
                if self.keyboard.is_key_down_once(VK_F7) {
                    self.state = State::MainMenu(MainMenuOption::Enable);
                }
            }
            State::MainMenu(option) => {
                if self.keyboard.is_any_key_down_once(&[VK_F7, VK_ESCAPE]) {
                    self.state = State::StatusIndicator;
                } else if self.keyboard.is_any_key_down_once(&[VK_UP, VK_W]) {
                    self.state = State::MainMenu(option.previous());
                } else if self.keyboard.is_any_key_down_once(&[VK_DOWN, VK_S]) {
                    self.state = State::MainMenu(option.next());
                } else {
                    match option {
                        MainMenuOption::Enable => {
                            if self.keyboard.is_any_key_down_once(&[VK_RETURN, VK_SPACE, VK_LEFT, VK_RIGHT, VK_A, VK_D]) {
                                self.config.is_enabled = !self.config.is_enabled;
                            }
                        }
                        MainMenuOption::InventoryEditor => {
                            if self.keyboard.is_any_key_down_once(&[VK_RETURN, VK_SPACE]) {
                                self.state = State::InventoryEditor(game::ITEM_ID_HEALTH_DRINK, game::ITEM_ID_HEALTH_DRINK);
                            }
                        }
                        MainMenuOption::ItemMapper => {
                            if self.keyboard.is_any_key_down_once(&[VK_RETURN, VK_SPACE]) {
                                self.state = State::ItemMapper(ItemMapperOption::Handgun);
                            }
                        }
                        MainMenuOption::Exit => {
                            if self.keyboard.is_any_key_down_once(&[VK_RETURN, VK_SPACE]) {
                                self.state = State::StatusIndicator;
                            }
                        }
                    }
                }
            }
            State::InventoryEditor(start_item, mut selected_item) => {
                let inventory = if is_james {
                    &mut self.config.james_starting_inventory
                } else {
                    &mut self.config.maria_starting_inventory
                };

                if self.keyboard.is_key_down_once(VK_F7) {
                    self.state = State::StatusIndicator;
                } else if self.keyboard.is_key_down_once(VK_ESCAPE) {
                    self.state = State::MainMenu(MainMenuOption::InventoryEditor);
                } else {
                    if self.keyboard.is_any_key_down_once(&[VK_UP, VK_W]) {
                        selected_item -= 1;
                        if selected_item <= game::ITEM_ID_NOTHING {
                            selected_item = game::ITEM_ID_WHITE_LIQUID;
                        }
                    } else if self.keyboard.is_any_key_down_once(&[VK_DOWN, VK_S]) {
                        selected_item += 1;
                        if selected_item > game::ITEM_ID_WHITE_LIQUID {
                            selected_item = game::ITEM_ID_HEALTH_DRINK;
                        }
                    } else if self.keyboard.is_any_key_down_once(&[VK_LEFT, VK_A]) {
                        if Inventory::has_count(selected_item) {
                            let count = inventory.get_count(selected_item);
                            if count >= 1 {
                                inventory.set_count(selected_item, count - 1);
                            } else if !Inventory::must_be_nonzero(selected_item) && inventory.has_item(selected_item) {
                                inventory.remove_item(selected_item);
                            } else {
                                inventory.set_count(selected_item, Inventory::get_max_count(selected_item));
                            }
                        } else {
                            inventory.toggle_item(selected_item);
                        }
                    } else if self.keyboard.is_any_key_down_once(&[VK_RIGHT, VK_D]) {
                        if Inventory::has_count(selected_item) {
                            let count = inventory.get_count(selected_item);
                            if !inventory.has_item(selected_item) && !Inventory::must_be_nonzero(selected_item) {
                                inventory.add_item(selected_item);
                                inventory.set_count(selected_item, 0);
                            } else if count < Inventory::get_max_count(selected_item) {
                                inventory.set_count(selected_item, count + 1);
                            } else {
                                inventory.remove_item(selected_item);
                            }
                        } else {
                            inventory.toggle_item(selected_item);
                        }
                    } else if self.keyboard.is_key_down_once(VK_E) && is_james {
                        // can't change Maria's starting equipped weapon, otherwise the game crashes
                        inventory.toggle_equip(selected_item);
                    }

                    self.state = State::InventoryEditor(Self::adjust_start_item(start_item, selected_item), selected_item);
                }
            }
            State::ItemMapper(option) => {
                let mapping = if is_james {
                    &mut self.config.james_weapon_ammo_mapping
                } else {
                    &mut self.config.maria_weapon_ammo_mapping
                };

                if self.keyboard.is_key_down_once(VK_F7) {
                    self.state = State::StatusIndicator;
                } else if self.keyboard.is_key_down_once(VK_ESCAPE) {
                    self.state = State::MainMenu(MainMenuOption::ItemMapper);
                } else if self.keyboard.is_any_key_down_once(&[VK_UP, VK_W]) {
                    self.state = State::ItemMapper(option.previous());
                } else if self.keyboard.is_any_key_down_once(&[VK_DOWN, VK_S]) {
                    self.state = State::ItemMapper(option.next());
                } else if option == ItemMapperOption::Exit {
                    if self.keyboard.is_any_key_down_once(&[VK_RETURN, VK_SPACE]) {
                        self.state = State::MainMenu(MainMenuOption::ItemMapper);
                    }
                } else {
                    let index = (option.item_id() - game::ITEM_ID_HANDGUN) as usize;
                    let mut selected_mapping = mapping[index];
                    if self.keyboard.is_any_key_down_once(&[VK_LEFT, VK_A]) {
                        selected_mapping -= 1;
                        if selected_mapping <= game::ITEM_ID_NONE {
                            selected_mapping = game::ITEM_ID_CLEAVER;
                        } else if selected_mapping < game::ITEM_ID_HANDGUN {
                            selected_mapping = game::ITEM_ID_NONE;
                        }
                        mapping[index] = selected_mapping;
                    } else if self.keyboard.is_any_key_down_once(&[VK_RIGHT, VK_D]) {
                        selected_mapping += 1;
                        if selected_mapping > game::ITEM_ID_CLEAVER {
                            selected_mapping = game::ITEM_ID_NONE;
                        } else if selected_mapping < game::ITEM_ID_HANDGUN {
                            selected_mapping = game::ITEM_ID_HANDGUN;
                        }
                        mapping[index] = selected_mapping;
                    }
                }
            }
        }

        // draw for state
        match self.state {
            State::StatusIndicator => {
                self.message.set_message(|builder| {
                    // newlines to make sure the text is drawn under the difficulty selection
                    builder.add_text("\n\nHeaven's Knife: ");
                    Self::draw_toggle(self.config.is_enabled, builder);
                    builder.add_control_code(ControlCode::White);
                    builder.add_text(" (press F7 to configure)");
                });
            }
            State::MainMenu(option) => {
                self.message.set_message(|builder| {
                    if option == MainMenuOption::Enable {
                        builder.add_control_code(ControlCode::Blue);
                    }
                    builder.add_text("Heaven's Knife: ");
                    Self::draw_toggle(self.config.is_enabled, builder);
                    builder.add_control_code(ControlCode::White);
                    builder.add_control_code(ControlCode::LineBreak);

                    if option == MainMenuOption::InventoryEditor {
                        builder.add_control_code(ControlCode::Blue);
                    }
                    builder.add_text("Edit starting inventory");
                    builder.add_control_code(ControlCode::White);
                    builder.add_control_code(ControlCode::LineBreak);

                    if option == MainMenuOption::ItemMapper {
                        builder.add_control_code(ControlCode::Blue);
                    }
                    builder.add_text("Edit item mappings");
                    builder.add_control_code(ControlCode::White);
                    builder.add_control_code(ControlCode::LineBreak);

                    if option == MainMenuOption::Exit {
                        builder.add_control_code(ControlCode::Blue);
                    }
                    // newlines to push the text above the difficulty selection
                    builder.add_text("Exit\n\n\n\n\n");
                });

                //self.draw_darkened_background();
            }
            State::InventoryEditor(start_item, selected_item) => {
                let inventory = if is_james {
                    &self.config.james_starting_inventory
                } else {
                    &self.config.maria_starting_inventory
                };

                self.message.set_message(|builder| {
                    builder.add_text("Equipped: ");
                    if !is_james {
                        builder.add_control_code(ControlCode::GrayscaleGradient);
                    }
                    builder.add_text(Inventory::item_name(inventory.equipped_item));
                    builder.add_control_code(ControlCode::White);
                    builder.add_control_code(ControlCode::LineBreak);
                    builder.add_control_code(ControlCode::LineBreak);

                    let mut next_item = start_item;
                    for _ in 0..MAX_ITEMS_PER_PAGE {
                        if next_item == selected_item {
                            builder.add_control_code(ControlCode::Blue);
                        }

                        builder.add_text(Inventory::item_name(next_item));
                        builder.add_text(": ");

                        let has_item = inventory.has_item(next_item);
                        if has_item {
                            builder.add_control_code(ControlCode::Green);
                        } else {
                            builder.add_control_code(ControlCode::Red);
                        }

                        if has_item && Inventory::has_count(next_item) {
                            let count = inventory.get_count(next_item);
                            builder.add_text(&format!("{count}"));
                        } else {
                            builder.add_text(if has_item {
                                "Yes"
                            } else {
                                "No"
                            });
                        }

                        builder.add_control_code(ControlCode::White);
                        builder.add_control_code(ControlCode::LineBreak);

                        next_item += 1;
                        if next_item > game::ITEM_ID_WHITE_LIQUID {
                            next_item = game::ITEM_ID_HEALTH_DRINK;
                        }
                    }

                    builder.add_control_code(ControlCode::LineBreak);
                    builder.add_text(if is_james {
                        "Use E to equip, Esc to exit"
                    } else {
                        "Use Esc to exit"
                    });
                });
            }
            State::ItemMapper(selected_option) => {
                self.message.set_message(|builder| {
                    let mapping = if is_james {
                        &mut self.config.james_weapon_ammo_mapping
                    } else {
                        &mut self.config.maria_weapon_ammo_mapping
                    };

                    for (i, &mapped_item) in mapping.iter().enumerate() {
                        let option = ItemMapperOption::from_item_id((i as i8) + game::ITEM_ID_HANDGUN);
                        if option == selected_option {
                            builder.add_control_code(ControlCode::Blue);
                        }

                        builder.add_text(option.name());
                        builder.add_text(": ");
                        builder.add_text(weapon_ammo_item_name(mapped_item));

                        builder.add_control_code(ControlCode::White);
                        builder.add_control_code(ControlCode::LineBreak);
                    }

                    if selected_option == ItemMapperOption::Exit {
                        builder.add_control_code(ControlCode::Blue);
                    }
                    builder.add_text("Exit");
                });
            }
        }

        self.print_message(&self.message);
    }

    pub const fn has_focus(&self) -> bool {
        !matches!(self.state, State::StatusIndicator)
    }

    pub unsafe fn set_funcs(&mut self, draw_message_ptr: usize, darkened_background_ptr: usize) {
        self.draw_message_ptr = Some(std::mem::transmute(draw_message_ptr));
        self.darkened_background_ptr = Some(std::mem::transmute(darkened_background_ptr));
    }

    pub fn draw_darkened_background(&self) {
        unsafe { self.darkened_background_ptr.unwrap()() };
    }

    pub fn print(&self, data: *const u8) {
        unsafe { self.draw_message_ptr.unwrap()(data) };
    }

    pub fn print_str(&mut self, text: &str) {
        self.message.set_message_from_str(text);
        self.print(self.message.data());
    }

    pub fn print_message(&self, msg: &game::Message) {
        self.print(msg.data());
    }

    pub fn clear_message(&mut self) {
        // draw an empty string to clear the text on the screen, then call with a null pointer to
        // clear the reference to it
        self.print_str("");
        self.print(std::ptr::null());
    }

    pub const fn starting_inventory(&self, is_james: bool) -> Option<&Inventory> {
        if self.config.is_enabled {
            Some(if is_james {
                &self.config.james_starting_inventory
            } else {
                &self.config.maria_starting_inventory
            })
        } else {
            None
        }
    }

    pub fn map_item(&self, item_id: i8, is_james: bool) -> i8 {
        // we only do mapping for weapons and ammo
        if !self.config.is_enabled || item_id < game::ITEM_ID_HANDGUN || item_id > game::ITEM_ID_CLEAVER {
            return item_id;
        }

        let mapping = if is_james {
            &self.config.james_weapon_ammo_mapping
        } else {
            &self.config.maria_weapon_ammo_mapping
        };

        mapping[(item_id - game::ITEM_ID_HANDGUN) as usize]
    }

    pub const fn is_enabled(&self) -> bool {
        self.config.is_enabled
    }
}
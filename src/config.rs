use std::str::FromStr;

use anyhow::{anyhow, bail, Result};
use log::LevelFilter;
use toml::{Table, Value};
use windows::Win32::UI::Input::KeyboardAndMouse::*;
use crate::game;
use crate::game::ControlCode;
use crate::input;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupBehavior {
    Disabled,
    OffByDefault,
    RememberLastState,
    OnByDefault,
}

impl StartupBehavior {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::OffByDefault => "default_off",
            Self::RememberLastState => "remember_last",
            Self::OnByDefault => "default_on",
        }
    }

    pub const fn display_name(&self) -> &'static str {
        match self {
            Self::Disabled => "Disabled",
            Self::OffByDefault => "Off by default",
            Self::RememberLastState => "Remember last state",
            Self::OnByDefault => "On by default",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "disabled" => Some(Self::Disabled),
            "default_off" => Some(Self::OffByDefault),
            "remember_last" => Some(Self::RememberLastState),
            "default_on" => Some(Self::OnByDefault),
            _ => None,
        }
    }

    pub const fn previous(&self) -> Self {
        match self {
            Self::Disabled => Self::OffByDefault,
            Self::OffByDefault => Self::RememberLastState,
            Self::RememberLastState => Self::OnByDefault,
            Self::OnByDefault => Self::Disabled,
        }
    }

    pub const fn next(&self) -> Self {
        match self {
            Self::Disabled => Self::OffByDefault,
            Self::OffByDefault => Self::RememberLastState,
            Self::RememberLastState => Self::OnByDefault,
            Self::OnByDefault => Self::Disabled,
        }
    }
}

const fn previous_log_level(level: LevelFilter) -> LevelFilter {
    match level {
        LevelFilter::Trace => LevelFilter::Off,
        LevelFilter::Debug => LevelFilter::Trace,
        LevelFilter::Info => LevelFilter::Debug,
        LevelFilter::Warn => LevelFilter::Info,
        LevelFilter::Error => LevelFilter::Warn,
        LevelFilter::Off => LevelFilter::Error,
    }
}

const fn next_log_level(level: LevelFilter) -> LevelFilter {
    match level {
        LevelFilter::Trace => LevelFilter::Debug,
        LevelFilter::Debug => LevelFilter::Info,
        LevelFilter::Info => LevelFilter::Warn,
        LevelFilter::Warn => LevelFilter::Error,
        LevelFilter::Error => LevelFilter::Off,
        LevelFilter::Off => LevelFilter::Trace,
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    startup_behavior: StartupBehavior,
    was_enabled_on_last_run: bool,
    allow_in_game_inventory_editing: bool,
    log_level: LevelFilter,
    is_enabled: bool,
    james_weapon_ammo_mapping: [i8; game::NUM_WEAPON_AMMO_ITEMS],
    maria_weapon_ammo_mapping: [i8; game::NUM_WEAPON_AMMO_ITEMS],
    james_starting_inventory: game::Inventory,
    maria_starting_inventory: game::Inventory,
}

impl Config {
    pub const fn new() -> Self {
        let mut this = Self {
            startup_behavior: StartupBehavior::OffByDefault,
            was_enabled_on_last_run: false,
            allow_in_game_inventory_editing: true,
            log_level: LevelFilter::Info,
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
            james_starting_inventory: game::Inventory::new(),
            maria_starting_inventory: game::Inventory::new(),
        };

        // default to the great knife scenario
        this.james_starting_inventory.equip_item(game::ITEM_ID_GREAT_KNIFE);
        this.maria_starting_inventory.add_item(game::ITEM_ID_GREAT_KNIFE);

        // Maria must start with the revolver equipped
        this.maria_starting_inventory.equipped_item = game::ITEM_ID_REVOLVER;
        // give James his normal starting items as well
        this.james_starting_inventory.add_item(game::ITEM_ID_PHOTO_OF_MARY);
        this.james_starting_inventory.add_item(game::ITEM_ID_LETTER_FROM_MARY);

        this
    }

    fn parse_item_id(value: Option<&Value>) -> Option<i8> {
        match value.and_then(Value::as_integer) {
            Some(id) => {
                if id >= game::ITEM_ID_NONE as i64 && id <= game::ITEM_ID_MAX as i64 {
                    Some(id as i8)
                } else {
                    None
                }
            }
            None => None,
        }
    }

    fn parse_scenario_data(weapon_ammo_mapping: &mut [i8; game::NUM_WEAPON_AMMO_ITEMS], starting_inventory: &mut game::Inventory, table: Option<&Value>) -> Result<()> {
        let Some(table) = table.and_then(Value::as_table) else {
            bail!("Scenario config must be a table");
        };

        if let Some(mapping) = table.get("weapon_ammo_mapping").and_then(Value::as_array) {
            for (map_item_id, input_item_id) in weapon_ammo_mapping.iter_mut().zip(mapping.iter()) {
                let input_item_id = input_item_id.as_integer().ok_or_else(|| anyhow!("Weapon/ammo mapping item is not an integer"))? as i8;
                if input_item_id < game::ITEM_ID_MIN_WEAPON || input_item_id > game::ITEM_ID_MAX_WEAPON {
                    bail!("Weapon/ammo mapping item must be weapon or ammo, found {}", input_item_id);
                }
                *map_item_id = input_item_id;
            }
        }

        let Some(input_inventory) = table.get("starting_inventory").and_then(Value::as_table) else {
            return Ok(());
        };

        starting_inventory.equipped_item = Self::parse_item_id(input_inventory.get("equipped_item")).unwrap_or(game::ITEM_ID_NOTHING);

        if let Some(flags) = input_inventory.get("flags").and_then(Value::as_array) {
            for (inv_flag, input_flag) in starting_inventory.flags.iter_mut().zip(flags.iter()) {
                let input_flag = input_flag.as_integer().ok_or_else(|| anyhow!("Inventory item flag is not an integer"))? as u32;
                *inv_flag = input_flag;
            }
        }

        if let Some(counts) = input_inventory.get("counts").and_then(Value::as_array) {
            for (inv_count, input_count) in starting_inventory.counts.iter_mut().zip(counts.iter()) {
                let input_count = input_count.as_integer().ok_or_else(|| anyhow!("Inventory item count is not an integer"))? as u16;
                *inv_count = input_count;
            }
        }

        starting_inventory.ensure_consistent();

        Ok(())
    }

    pub fn from_text(text: &str) -> Result<Self> {
        let table = text.parse::<Table>()?;

        // create a default instance; we'll override any properties we have values for
        let mut config = Self::new();

        config.startup_behavior = table.get("startup").and_then(Value::as_str).and_then(StartupBehavior::from_str).unwrap_or(StartupBehavior::OffByDefault);
        config.was_enabled_on_last_run = table.get("was_enabled_on_last_run").and_then(Value::as_bool).unwrap_or(false);
        config.allow_in_game_inventory_editing = table.get("allow_in_game_inventory_editing").and_then(Value::as_bool).unwrap_or(true);
        config.log_level = table.get("log_level").and_then(Value::as_str).and_then(|s| LevelFilter::from_str(s).ok()).unwrap_or(LevelFilter::Info);

        config.is_enabled = config.startup_behavior == StartupBehavior::OnByDefault || (config.startup_behavior == StartupBehavior::RememberLastState && config.was_enabled_on_last_run);

        Self::parse_scenario_data(&mut config.james_weapon_ammo_mapping, &mut config.james_starting_inventory, table.get("james"))?;
        Self::parse_scenario_data(&mut config.maria_weapon_ammo_mapping, &mut config.maria_starting_inventory, table.get("maria"))?;

        Ok(config)
    }

    fn save_scenario_data(weapon_ammo_mapping: &[i8; game::NUM_WEAPON_AMMO_ITEMS], starting_inventory: &game::Inventory) -> Table {
        let mut table = Table::new();

        table.insert(String::from("weapon_ammo_mapping"), Value::from(weapon_ammo_mapping.to_vec()));

        let mut inventory = Table::new();

        inventory.insert(String::from("equipped_item"), Value::from(starting_inventory.equipped_item));
        inventory.insert(String::from("flags"), Value::from(starting_inventory.flags.to_vec()));
        inventory.insert(String::from("counts"), Value::from(starting_inventory.counts.iter().map(|c| *c as i32).collect::<Vec<_>>()));

        table.insert(String::from("starting_inventory"), Value::from(inventory));

        table
    }

    pub fn to_text(&self) -> String {
        let mut table = Table::new();

        table.insert(String::from("startup"), Value::from(self.startup_behavior.as_str()));
        table.insert(String::from("was_enabled_on_last_run"), Value::from(self.is_enabled));
        table.insert(String::from("allow_in_game_inventory_editing"), Value::from(self.allow_in_game_inventory_editing));
        table.insert(String::from("log_level"), Value::from(self.log_level.to_string()));

        table.insert(String::from("james"), Value::from(Self::save_scenario_data(&self.james_weapon_ammo_mapping, &self.james_starting_inventory)));
        table.insert(String::from("maria"), Value::from(Self::save_scenario_data(&self.maria_weapon_ammo_mapping, &self.maria_starting_inventory)));

        table.to_string()
    }

    pub const fn log_level(&self) -> LevelFilter {
        self.log_level
    }

    pub const fn is_disabled(&self) -> bool {
        matches!(self.startup_behavior, StartupBehavior::Disabled)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MainMenuOption {
    Enable,
    InventoryEditor,
    ItemMapper,
    Settings,
    Exit,
}

impl MainMenuOption {
    pub const fn previous(&self) -> Self {
        match self {
            Self::Enable => Self::Exit,
            Self::InventoryEditor => Self::Enable,
            Self::ItemMapper => Self::InventoryEditor,
            Self::Settings => Self::ItemMapper,
            Self::Exit => Self::Settings,
        }
    }

    pub const fn next(&self) -> Self {
        match self {
            Self::Enable => Self::InventoryEditor,
            Self::InventoryEditor => Self::ItemMapper,
            Self::ItemMapper => Self::Settings,
            Self::Settings => Self::Exit,
            Self::Exit => Self::Enable,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SettingsOption {
    Startup,
    LogLevel,
    AllowInGameInventoryEditing,
    Exit,
}

impl SettingsOption {
    pub const fn previous(&self) -> Self {
        match self {
            Self::Startup => Self::Exit,
            Self::LogLevel => Self::Startup,
            Self::AllowInGameInventoryEditing => Self::LogLevel,
            Self::Exit => Self::AllowInGameInventoryEditing,
        }
    }

    pub const fn next(&self) -> Self {
        match self {
            Self::Startup => Self::LogLevel,
            Self::LogLevel => Self::AllowInGameInventoryEditing,
            Self::AllowInGameInventoryEditing => Self::Exit,
            Self::Exit => Self::Startup,
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
            game::item_name(self.item_id())
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
    Settings(SettingsOption),
}

#[derive(Debug)]
pub struct UserInterface {
    config: Config,
    draw_message_ptr: Option<unsafe extern "C" fn(*const u8)>,
    draw_message_positioned_ptr: Option<unsafe extern "C" fn(*const u8, i32, i32)>,
    message: game::Message,
    state: State,
    keyboard: input::Keyboard,
    original_inventory_editor_setting: bool,
}

impl UserInterface {
    pub const fn new(config: Config) -> Self {
        let original_inventory_editor_setting = config.allow_in_game_inventory_editing;
        Self {
            config,
            draw_message_ptr: None,
            draw_message_positioned_ptr: None,
            message: game::Message::new(),
            state: State::StatusIndicator,
            keyboard: input::Keyboard::new(),
            original_inventory_editor_setting,
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

    pub fn reset_ui(&mut self) {
        self.state = State::StatusIndicator;
    }

    /// Show the configuration UI.
    ///
    /// # Arguments
    ///
    /// * `is_james` - Are we James? Controls which scenario's settings are shown.
    /// * `live_inventory` - If we're in-game, as opposed to on the main menu, use this to pass the
    ///                      player's current inventory.
    ///
    /// # Return value
    ///
    /// A boolean indicating whether the UI was just closed. This can be used a signal to trigger
    /// a save of the configuration.
    pub fn show(&mut self, is_james: bool, live_inventory: Option<&mut game::Inventory>) -> bool {
        use crate::game::ControlCode;

        self.keyboard.update().expect("keyboard state update should not fail");

        let is_maria_scenario_start = !is_james && live_inventory.is_none();
        // if we have live inventory, we're in-game, so we must be at the pause menu. otherwise,
        // we're at the difficulty selection screen prior to starting a new game.
        let is_in_game = live_inventory.is_some();
        let inventory = live_inventory.unwrap_or_else(|| if is_james {
            &mut self.config.james_starting_inventory
        } else {
            &mut self.config.maria_starting_inventory
        });

        let mut was_closed = false;

        let can_change_inventory_editor_setting = !is_in_game || self.original_inventory_editor_setting;

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
                    was_closed = true;
                } else if self.keyboard.is_any_key_down_once(&[VK_UP, VK_W]) {
                    let mut previous_option = option.previous();
                    if previous_option == MainMenuOption::InventoryEditor && !can_change_inventory_editor_setting {
                        previous_option = previous_option.previous();
                    }
                    self.state = State::MainMenu(previous_option);
                } else if self.keyboard.is_any_key_down_once(&[VK_DOWN, VK_S]) {
                    let mut next_option = option.next();
                    if next_option == MainMenuOption::InventoryEditor && !can_change_inventory_editor_setting {
                        next_option = next_option.next();
                    }
                    self.state = State::MainMenu(next_option);
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
                        MainMenuOption::Settings => {
                            if self.keyboard.is_any_key_down_once(&[VK_RETURN, VK_SPACE]) {
                                self.state = State::Settings(SettingsOption::Startup);
                                self.original_inventory_editor_setting = self.config.allow_in_game_inventory_editing;
                            }
                        }
                        MainMenuOption::Exit => {
                            if self.keyboard.is_any_key_down_once(&[VK_RETURN, VK_SPACE]) {
                                self.state = State::StatusIndicator;
                                was_closed = true;
                            }
                        }
                    }
                }
            }
            State::InventoryEditor(start_item, mut selected_item) => {
                if self.keyboard.is_key_down_once(VK_F7) {
                    self.state = State::StatusIndicator;
                    was_closed = true;
                } else if self.keyboard.is_key_down_once(VK_ESCAPE) {
                    self.state = State::MainMenu(MainMenuOption::InventoryEditor);
                } else {
                    if self.keyboard.is_any_key_down_once(&[VK_UP, VK_W]) {
                        selected_item -= 1;
                        if selected_item <= game::ITEM_ID_NOTHING {
                            selected_item = game::ITEM_ID_MAX;
                        }
                    } else if self.keyboard.is_any_key_down_once(&[VK_DOWN, VK_S]) {
                        selected_item += 1;
                        if selected_item > game::ITEM_ID_MAX {
                            selected_item = game::ITEM_ID_HEALTH_DRINK;
                        }
                    } else if self.keyboard.is_any_key_down_once(&[VK_LEFT, VK_A]) {
                        if game::item_has_count(selected_item) {
                            let count = inventory.get_count(selected_item);
                            if count >= 1 {
                                inventory.set_count(selected_item, count - 1);
                            } else if !game::item_count_must_be_nonzero(selected_item) && inventory.has_item(selected_item) {
                                inventory.remove_item(selected_item);
                            } else {
                                inventory.set_count(selected_item, game::get_item_max_count(selected_item));
                            }
                        } else {
                            inventory.toggle_item(selected_item);
                        }
                    } else if self.keyboard.is_any_key_down_once(&[VK_RIGHT, VK_D]) {
                        if game::item_has_count(selected_item) {
                            let count = inventory.get_count(selected_item);
                            if !inventory.has_item(selected_item) && !game::item_count_must_be_nonzero(selected_item) {
                                inventory.add_item(selected_item);
                                inventory.set_count(selected_item, 0);
                            } else if count < game::get_item_max_count(selected_item) {
                                inventory.set_count(selected_item, count + 1);
                            } else {
                                inventory.remove_item(selected_item);
                            }
                        } else {
                            inventory.toggle_item(selected_item);
                        }
                    } else if self.keyboard.is_key_down_once(VK_E) && !is_maria_scenario_start {
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
                    was_closed = true;
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
                    let index = (option.item_id() - game::ITEM_ID_MIN_WEAPON) as usize;
                    let mut selected_mapping = mapping[index];
                    if self.keyboard.is_any_key_down_once(&[VK_LEFT, VK_A]) {
                        selected_mapping -= 1;
                        if selected_mapping <= game::ITEM_ID_NONE {
                            selected_mapping = game::ITEM_ID_MAX_WEAPON;
                        } else if selected_mapping < game::ITEM_ID_MIN_WEAPON {
                            selected_mapping = game::ITEM_ID_NONE;
                        }
                        mapping[index] = selected_mapping;
                    } else if self.keyboard.is_any_key_down_once(&[VK_RIGHT, VK_D]) {
                        selected_mapping += 1;
                        if selected_mapping > game::ITEM_ID_MAX_WEAPON {
                            selected_mapping = game::ITEM_ID_NONE;
                        } else if selected_mapping < game::ITEM_ID_MIN_WEAPON {
                            selected_mapping = game::ITEM_ID_HANDGUN;
                        }
                        mapping[index] = selected_mapping;
                    }
                }
            }
            State::Settings(option) => {
                if self.keyboard.is_key_down_once(VK_F7) {
                    self.state = State::StatusIndicator;
                    was_closed = true;
                } else if self.keyboard.is_key_down_once(VK_ESCAPE) {
                    self.state = State::MainMenu(MainMenuOption::Settings);
                } else if self.keyboard.is_any_key_down_once(&[VK_UP, VK_W]) {
                    let mut previous_option = option.previous();
                    if previous_option == SettingsOption::AllowInGameInventoryEditing && !can_change_inventory_editor_setting {
                        previous_option = previous_option.previous();
                    }
                    self.state = State::Settings(previous_option);
                } else if self.keyboard.is_any_key_down_once(&[VK_DOWN, VK_S]) {
                    let mut next_option = option.next();
                    if next_option == SettingsOption::AllowInGameInventoryEditing && !can_change_inventory_editor_setting {
                        next_option = next_option.next();
                    }
                    self.state = State::Settings(next_option);
                } else {
                    match option {
                        SettingsOption::Startup => {
                            if self.keyboard.is_any_key_down_once(&[VK_LEFT, VK_A]) {
                                self.config.startup_behavior = self.config.startup_behavior.previous();
                            } else if self.keyboard.is_any_key_down_once(&[VK_RIGHT, VK_D]) {
                                self.config.startup_behavior = self.config.startup_behavior.next();
                            }
                        }
                        SettingsOption::LogLevel => {
                            if self.keyboard.is_any_key_down_once(&[VK_LEFT, VK_A]) {
                                self.config.log_level = previous_log_level(self.config.log_level);
                            } else if self.keyboard.is_any_key_down_once(&[VK_RIGHT, VK_D]) {
                                self.config.log_level = next_log_level(self.config.log_level);
                            }
                        }
                        SettingsOption::AllowInGameInventoryEditing => {
                            if can_change_inventory_editor_setting && self.keyboard.is_any_key_down_once(&[VK_RETURN, VK_SPACE, VK_LEFT, VK_RIGHT, VK_A, VK_D]) {
                                self.config.allow_in_game_inventory_editing = !self.config.allow_in_game_inventory_editing;
                            }
                        }
                        SettingsOption::Exit => {
                            if self.keyboard.is_any_key_down_once(&[VK_RETURN, VK_SPACE]) {
                                self.state = State::MainMenu(MainMenuOption::Settings);
                            }
                        }
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
                    } else if !can_change_inventory_editor_setting {
                        builder.add_control_code(ControlCode::GrayscaleGradient);
                    }
                    builder.add_text(if is_in_game {
                        "Edit inventory"
                    } else {
                        "Edit starting inventory"
                    });
                    builder.add_control_code(ControlCode::White);
                    builder.add_control_code(ControlCode::LineBreak);

                    if option == MainMenuOption::ItemMapper {
                        builder.add_control_code(ControlCode::Blue);
                    }
                    builder.add_text("Edit item mappings");
                    builder.add_control_code(ControlCode::White);
                    builder.add_control_code(ControlCode::LineBreak);

                    if option == MainMenuOption::Settings {
                        builder.add_control_code(ControlCode::Blue);
                    }
                    builder.add_text("Settings");
                    builder.add_control_code(ControlCode::White);
                    builder.add_control_code(ControlCode::LineBreak);

                    if option == MainMenuOption::Exit {
                        builder.add_control_code(ControlCode::Blue);
                    }
                    // newlines to push the text above the difficulty selection
                    builder.add_text("Exit\n\n\n\n");
                    builder.add_control_code(ControlCode::White);

                    builder.add_text("On exit, settings will be saved to the config file.");
                });
            }
            State::InventoryEditor(start_item, selected_item) => {
                self.message.set_message(|builder| {
                    builder.add_text("Equipped: ");
                    if is_maria_scenario_start {
                        builder.add_control_code(ControlCode::GrayscaleGradient);
                    }
                    builder.add_text(game::item_name(inventory.equipped_item));
                    builder.add_control_code(ControlCode::White);
                    builder.add_control_code(ControlCode::LineBreak);
                    builder.add_control_code(ControlCode::LineBreak);

                    let mut next_item = start_item;
                    for _ in 0..MAX_ITEMS_PER_PAGE {
                        if next_item == selected_item {
                            builder.add_control_code(ControlCode::Blue);
                        }

                        builder.add_text(game::item_name(next_item));
                        builder.add_text(": ");

                        let has_item = inventory.has_item(next_item);
                        if has_item {
                            builder.add_control_code(ControlCode::Green);
                        } else {
                            builder.add_control_code(ControlCode::Red);
                        }

                        if has_item && game::item_has_count(next_item) {
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
                    builder.add_text(if !is_maria_scenario_start {
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
                        builder.add_text(game::item_name(mapped_item));

                        builder.add_control_code(ControlCode::White);
                        builder.add_control_code(ControlCode::LineBreak);
                    }

                    if selected_option == ItemMapperOption::Exit {
                        builder.add_control_code(ControlCode::Blue);
                    }
                    builder.add_text("Exit");
                });
            }
            State::Settings(option) => {
                self.message.set_message(|builder| {
                    if option == SettingsOption::Startup {
                        builder.add_control_code(ControlCode::Blue);
                    }
                    builder.add_text("Mod startup: ");
                    builder.add_control_code(match self.config.startup_behavior {
                        StartupBehavior::Disabled => ControlCode::Red,
                        StartupBehavior::OffByDefault => ControlCode::Yellow,
                        StartupBehavior::RememberLastState => ControlCode::LightBlue,
                        StartupBehavior::OnByDefault => ControlCode::Green,
                    });
                    builder.add_text(self.config.startup_behavior.display_name());
                    builder.add_control_code(ControlCode::White);
                    builder.add_control_code(ControlCode::LineBreak);

                    if option == SettingsOption::LogLevel {
                        builder.add_control_code(ControlCode::Blue);
                    }
                    builder.add_text("Log level: ");
                    builder.add_control_code(match self.config.log_level {
                        LevelFilter::Off => ControlCode::GrayscaleGradient,
                        _ => ControlCode::White,
                    });
                    builder.add_text(&self.config.log_level.to_string());
                    builder.add_control_code(ControlCode::White);
                    builder.add_control_code(ControlCode::LineBreak);

                    if option == SettingsOption::AllowInGameInventoryEditing {
                        builder.add_control_code(ControlCode::Blue);
                    } else if !can_change_inventory_editor_setting {
                        builder.add_control_code(ControlCode::GrayscaleGradient);
                    }
                    builder.add_text("In-game inventory editor: ");
                    if self.config.allow_in_game_inventory_editing {
                        builder.add_control_code(ControlCode::Green);
                        builder.add_text("Enabled");
                    } else {
                        // we'll let this be gray as well if the setting can't be changed
                        if can_change_inventory_editor_setting {
                            builder.add_control_code(ControlCode::Red);
                        }
                        builder.add_text("Disabled");
                    }
                    builder.add_control_code(ControlCode::White);
                    builder.add_control_code(ControlCode::LineBreak);

                    if option == SettingsOption::Exit {
                        builder.add_control_code(ControlCode::Blue);
                    }
                    builder.add_text("Exit");
                    builder.add_control_code(ControlCode::White);
                    builder.add_control_code(ControlCode::LineBreak);

                    if option == SettingsOption::Startup && self.config.startup_behavior == StartupBehavior::Disabled {
                        builder.add_control_code(ControlCode::LineBreak);
                        builder.add_control_code(ControlCode::Yellow);
                        builder.add_text("WARNING: ");
                        builder.add_control_code(ControlCode::White);
                        builder.add_text("re-enabling the mod will require\nediting the config file by hand.");
                    } else if option == SettingsOption::AllowInGameInventoryEditing && !self.config.allow_in_game_inventory_editing {
                        builder.add_control_code(ControlCode::LineBreak);
                        builder.add_text("Cannot be re-enabled during gameplay.\nReturn to the new game menu to re-enable.");
                    } else {
                        // pad with blank lines to keep spacing the same
                        builder.add_text("\n\n");
                    }

                    builder.add_text("\n\n\n\n");
                });
            }
        }

        if is_in_game && self.state == State::StatusIndicator {
            self.print_message_positioned(&self.message, 260, 400);
        } else {
            self.print_message(&self.message);
        }

        was_closed
    }

    pub const fn has_focus(&self) -> bool {
        !matches!(self.state, State::StatusIndicator)
    }

    pub unsafe fn set_funcs(&mut self, draw_message_ptr: usize, draw_message_positioned_ptr: usize) {
        self.draw_message_ptr = Some(std::mem::transmute(draw_message_ptr));
        self.draw_message_positioned_ptr = Some(std::mem::transmute(draw_message_positioned_ptr));
    }

    pub fn print_positioned(&self, data: *const u8, x: i32, y: i32) {
        unsafe { self.draw_message_positioned_ptr.unwrap()(data, x, y) };
    }

    pub fn print_message_positioned(&self, msg: &game::Message, x: i32, y: i32) {
        self.print_positioned(msg.data(), x, y);
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

    pub const fn starting_inventory(&self, is_james: bool) -> Option<&game::Inventory> {
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

    pub fn set_config(&mut self, config: Config) {
        self.config = config;
    }

    pub fn save_config(&self) -> String {
        self.config.to_text()
    }
}
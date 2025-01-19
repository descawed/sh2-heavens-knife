use anyhow::{bail, Result};
use windows::Win32::Foundation::GetLastError;
use windows::Win32::UI::Input::KeyboardAndMouse::*;

#[derive(Debug)]
pub struct Keyboard {
    old_keys: [u8; 256],
    new_keys: [u8; 256],
}

impl Keyboard {
    pub const fn new() -> Self {
        Self {
            old_keys: [0; 256],
            new_keys: [0; 256],
        }
    }

    pub fn update(&mut self) -> Result<()> {
        self.old_keys = self.new_keys;
        unsafe {
            if GetKeyboardState(&mut self.new_keys).is_err() {
                let error = GetLastError().0;
                log::error!("GetKeyboardState failed: {:#08X}", error);
                bail!("GetKeyboardState failed: {:#08X}", error);
            }
        }

        Ok(())
    }

    pub const fn is_key_down(&self, key: VIRTUAL_KEY) -> bool {
        self.new_keys[key.0 as usize] & 0x80 != 0
    }

    pub const fn is_key_down_once(&self, key: VIRTUAL_KEY) -> bool {
        self.is_key_down(key) && self.old_keys[key.0 as usize] & 0x80 == 0
    }

    pub fn is_any_key_down_once(&self, keys: &[VIRTUAL_KEY]) -> bool {
        for key in keys {
            if self.is_key_down_once(*key) {
                return true;
            }
        }

        false
    }

    /*pub const fn is_key_toggled(&self, key: VIRTUAL_KEY) -> bool {
        self.new_keys[key.0 as usize] & 1 != 0
    }*/
}
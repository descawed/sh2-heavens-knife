use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use anyhow::Result;
use encoding_rs::WINDOWS_1252;

// the unused variants are useful for documentation purposes and may be used at some point in the
// future
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum ControlCode {
    SingleByteMode,
    PositionY(u16),
    PositionX(u16),
    MoveCursorLeft(u8),
    MoveCursorRight(u8),
    White,
    Blue,
    Red,
    Green,
    Yellow,
    LightBlue,
    Purple,
    BlueGreenGradient,
    DarkRed,
    Invisible,
    GrayscaleGradient,
    BrightRed,
    Pink,
    LineBreak,
    EndOfMessage,
}

impl ControlCode {
    const fn as_int(&self) -> u16 {
        match self {
            Self::SingleByteMode => 0x8000,
            Self::PositionY(y) => 0xF800 | (*y & 0x1FF),
            Self::PositionX(x) => 0xFA00 | (*x & 0x1FF),
            Self::MoveCursorLeft(offset) => 0xFC00 | (*offset as u16),
            Self::MoveCursorRight(offset) => 0xFD00 | (*offset as u16),
            Self::White => 0xFF00,
            Self::Blue => 0xFF01,
            Self::Red => 0xFF02,
            Self::Green => 0xFF03,
            Self::Yellow => 0xFF04,
            Self::LightBlue => 0xFF05,
            Self::Purple => 0xFF06,
            Self::BlueGreenGradient => 0xFF07,
            Self::DarkRed => 0xFF08,
            Self::Invisible => 0xFF09,
            Self::GrayscaleGradient => 0xFF0A,
            Self::BrightRed => 0xFF0B,
            Self::Pink => 0xFF0C,
            Self::LineBreak => 0xFFFD,
            Self::EndOfMessage => 0xFFFF,
        }
    }

    const fn sb_bytes(&self) -> [u8; 2] {
        let int = self.as_int();
        if int >= 0xE000 {
            int.to_be_bytes()
        } else {
            int.to_le_bytes()
        }
    }

    const fn db_bytes(&self) -> [u8; 2] {
        self.as_int().to_le_bytes()
    }

    const fn exits_single_byte_mode(&self) -> bool {
        let int = self.as_int();
        int > 0x8000 && (int < 0xFF00 || (int >= 0xFFE0 && int <= 0xFFE9))
    }
}

#[derive(Debug)]
pub struct MessageBuilder<'a> {
    data: &'a mut [u8],
    length: usize,
    post_code: u16,
    is_in_single_byte_mode: bool,
}

impl<'a> MessageBuilder<'a> {
    const fn new(data: &'a mut [u8]) -> Self {
        Self { data, length: 0, post_code: 0, is_in_single_byte_mode: false }
    }

    fn build(data: &'a mut [u8], setter: impl FnOnce(&mut Self)) -> usize {
        data.fill(0);

        let mut builder = Self::new(data);
        setter(&mut builder);
        builder.control(ControlCode::EndOfMessage);

        let mut length = builder.length;
        if (length & 1) != 0 {
            // length must be even because the file header gives the offset in 16-bit units.
            // padding must go between end-of-message code and post-message code
            builder.data.write(&[0]).unwrap();
            length += 1;
        }
        // post-message code; don't fully understand this yet
        builder.data.write(&builder.post_code.to_le_bytes()).unwrap();

        length + 2
    }

    pub fn text(&mut self, text: &str) {
        if !self.is_in_single_byte_mode {
            self.control(ControlCode::SingleByteMode);
        }

        let bytes = WINDOWS_1252.encode(text).0;
        for &c in bytes.iter() {
            if c == b'\n' {
                self.control(ControlCode::LineBreak);
            } else if c < b' ' {
                self.data.write(&[0]).unwrap();
                self.length += 1;
            } else {
                self.data.write(&[c - b' ']).unwrap();
                self.length += 1;
            }
        }
    }

    pub fn control(&mut self, code: ControlCode) {
        let bytes = if self.is_in_single_byte_mode {
            code.sb_bytes()
        } else {
            code.db_bytes()
        };
        self.data.write(&bytes).unwrap();
        self.length += bytes.len();

        if code.exits_single_byte_mode() {
            self.is_in_single_byte_mode = false;
        } else if matches!(code, ControlCode::SingleByteMode) {
            self.is_in_single_byte_mode = true;
        }
    }

    pub fn set_post_code(&mut self, code: u16) {
        self.post_code = code;
    }
}

pub const MESSAGE_MAX_LEN: usize = 0x1000;

#[derive(Debug)]
pub struct Message {
    data: [u8; MESSAGE_MAX_LEN],
    length: usize,
}

impl Message {
    pub const fn new() -> Self {
        Self {
            data: [0; MESSAGE_MAX_LEN],
            length: 0,
        }
    }

    pub fn set_message(&mut self, setter: impl FnOnce(&mut MessageBuilder)) {
        self.length = MessageBuilder::build(&mut self.data, setter);
    }

    pub fn set_message_from_str(&mut self, text: &str) {
        self.set_message(|builder| builder.text(text));
    }

    pub const fn data(&self) -> *const u8 {
        self.data.as_ptr()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.length]
    }
}

pub const MESSAGE_FILE_MAX_SIZE: usize = 0x7000;

#[derive(Debug)]
pub struct MessageFile {
    data: [u8; MESSAGE_FILE_MAX_SIZE],
    length: usize,
    messages: Vec<Vec<u8>>,
}

impl MessageFile {
    pub const fn new() -> Self {
        Self {
            data: [0; MESSAGE_FILE_MAX_SIZE],
            length: 0,
            messages: Vec::new(),
        }
    }

    const fn hdr(&self, i: usize) -> usize {
        (((self.data[i] as u16) | ((self.data[i + 1] as u16) << 8)) << 1) as usize
    }

    const fn for_hdr(i: usize) -> [u8; 2] {
        let i = i >> 1;
        [(i & 0xff) as u8, ((i >> 8) & 0xff) as u8]
    }

    pub fn from_raw(data: &[u8]) -> Self {
        let mut file = Self::new();
        file.data[..data.len()].copy_from_slice(data);
        file.length = data.len();

        let data_start = file.hdr(0) + 2;
        for i in (2..data_start).step_by(2) {
            let message_offset = file.hdr(i);
            let message_length = if i + 2 < data_start {
                file.hdr(i + 2)
            } else {
                file.length
            } - message_offset;

            file.messages.push(file.data[message_offset..message_offset + message_length].to_vec());
        }

        file
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(Self::from_raw(&data))
    }

    fn rebuild(&mut self) {
        self.data.fill(0);

        let header_size = 2 * (self.messages.len() + 1);
        let data_size = self.messages.iter().map(|m| m.len()).sum::<usize>();
        self.length = header_size + data_size;

        let mut cursor = &mut self.data[..];
        cursor.write(&Self::for_hdr(header_size - 2)).unwrap();

        let mut offset = header_size;
        for message in &self.messages {
            cursor.write(&Self::for_hdr(offset)).unwrap();
            offset += message.len();
        }

        for message in &self.messages {
            cursor.write(message).unwrap();
        }
    }

    pub fn add_message(&mut self, data: &[u8]) {
        self.messages.push(data.to_vec());
        self.rebuild();
    }

    pub const fn data(&self) -> *const u8 {
        self.data.as_ptr()
    }

    pub fn get(&self, i: usize) -> &[u8] {
        self.messages[i].as_slice()
    }
}
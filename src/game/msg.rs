use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use anyhow::Result;

const CHAR_MAP: &str = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

#[derive(Debug, Clone, Copy)]
pub enum ControlCode {
    White = 0,
    Blue = 1,
    Red = 2,
    Green = 3,
    Yellow = 4,
    LightBlue = 5,
    Purple = 6,
    BlueGreenGradient = 7,
    DarkRed = 8,
    Invisible = 9,
    GrayscaleGradient = 10,
    BrightRed = 11,
    Pink = 12,
    CenterVertically = 0xFA,
    LineBreak = 0xFD,
    EndOfMessage = 0xFF,
}

impl ControlCode {
    const fn as_bytes(&self) -> [u8; 2] {
        [0xFF, *self as u8]
    }
}

#[derive(Debug)]
pub struct MessageBuilder<'a> {
    data: &'a mut [u8],
    length: usize,
    post_code: u16,
}

impl<'a> MessageBuilder<'a> {
    fn build(mut data: &'a mut [u8], setter: impl FnOnce(&mut Self)) -> usize {
        data.fill(0);

        // initialize header - 0x8000 = single-byte mode
        data.write(&[0x00, 0x80]).unwrap();

        let mut builder = Self { data, length: 2, post_code: 0 };
        setter(&mut builder);
        builder.add_control_code(ControlCode::EndOfMessage);

        let mut length = builder.length;
        if (length & 1) != 0 {
            // length must be even because the file header gives the offset in 16-bit units
            // padding must go between end-of-message code and post-message code
            builder.data.write(&[0]).unwrap();
            length += 1;
        }
        // post-message code; don't fully understand this yet
        builder.data.write(&builder.post_code.to_le_bytes()).unwrap();

        length + 2
    }

    pub fn add_text(&mut self, text: &str) {
        for c in text.chars() {
            if c == '\n' {
                self.add_control_code(ControlCode::LineBreak);
            } else if c == 'ó' {
                // hack until I can be bothered to determine the rest of the characters
                self.data.write(&[0xD3]).unwrap();
                self.length += 1;
            } else {
                let index = CHAR_MAP.find(c).unwrap_or(0);
                self.data.write(&[index as u8]).unwrap();
                self.length += 1;
            }
        }
    }

    pub fn add_control_code(&mut self, code: ControlCode) {
        self.data.write(&code.as_bytes()).unwrap();
        self.length += 2;
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

    pub fn from_raw(data: &[u8]) -> Self {
        let mut message = Self::new();
        message.data[..data.len()].copy_from_slice(data);
        message.length = data.len();
        message
    }

    pub fn raw(setter: impl FnOnce(&mut MessageBuilder)) -> [u8; MESSAGE_MAX_LEN] {
        let mut data = [0; MESSAGE_MAX_LEN];
        MessageBuilder::build(&mut data, setter);
        data
    }

    pub fn raw_from_str(s: &str) -> [u8; MESSAGE_MAX_LEN] {
        Self::raw(|builder| builder.add_text(s))
    }

    pub fn set_message(&mut self, setter: impl FnOnce(&mut MessageBuilder)) {
        self.length = MessageBuilder::build(&mut self.data, setter);
    }

    pub fn set_message_from_str(&mut self, text: &str) {
        self.set_message(|builder| builder.add_text(text));
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

    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.length]
    }

    pub fn num_messages(&self) -> usize {
        self.messages.len()
    }

    pub fn get(&self, i: usize) -> &[u8] {
        self.messages[i].as_slice()
    }
}
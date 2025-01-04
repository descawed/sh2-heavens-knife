use std::io::Write;

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
}

impl<'a> MessageBuilder<'a> {
    fn build(mut data: &'a mut [u8], setter: impl FnOnce(&mut Self)) {
        data.fill(0);

        // initialize header - 0x8000 = single-byte mode
        data.write(&[0x00, 0x80]).unwrap();

        let mut builder = Self { data };
        setter(&mut builder);
        builder.add_control_code(ControlCode::EndOfMessage);
        // post-message code; don't fully understand this yet
        builder.data.write(&[0, 0]).unwrap();
    }

    pub fn add_text(&mut self, text: &str) {
        for c in text.chars() {
            if c == '\n' {
                self.add_control_code(ControlCode::LineBreak);
            } else {
                let index = CHAR_MAP.find(c).unwrap_or(0);
                self.data.write(&[index as u8]).unwrap();
            }
        }
    }

    pub fn add_control_code(&mut self, code: ControlCode) {
        self.data.write(&code.as_bytes()).unwrap();
    }
}

pub const MESSAGE_MAX_LEN: usize = 0x1000;

#[derive(Debug)]
pub struct Message([u8; MESSAGE_MAX_LEN]);

impl Message {
    pub const fn new() -> Self {
        Self([0; MESSAGE_MAX_LEN])
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
        MessageBuilder::build(&mut self.0, setter);
    }

    pub fn set_message_from_str(&mut self, text: &str) {
        self.set_message(|builder| builder.add_text(text));
    }

    pub const fn data(&self) -> *const u8 {
        self.0.as_ptr()
    }
}
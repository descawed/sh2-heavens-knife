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
    message_data: &'a mut Vec<u8>,
}

impl<'a> MessageBuilder<'a> {
    fn new(data: &'a mut Vec<u8>) -> Self {
        // initialize header - 0x8000 = single-byte mode
        data.clear();
        data.extend_from_slice(&[0x00, 0x80]);

        Self {
            message_data: data,
        }
    }

    pub fn add_text(&mut self, text: &str) {
        for c in text.chars() {
            if c == '\n' {
                self.add_control_code(ControlCode::LineBreak);
            } else {
                let index = CHAR_MAP.find(c).unwrap_or(0);
                self.message_data.push(index as u8);
            }
        }
    }

    pub fn add_control_code(&mut self, code: ControlCode) {
        self.message_data.extend_from_slice(&code.as_bytes());
    }

    fn finalize(mut self) {
        self.add_control_code(ControlCode::EndOfMessage);
        // post-message code; don't fully understand this yet
        self.message_data.push(0);
        self.message_data.push(0);
    }
}

#[derive(Debug)]
pub struct Message {
    message_data: Vec<u8>,
}

impl Message {
    pub const fn new() -> Self {
        Self {
            message_data: Vec::new(),
        }
    }

    pub fn set_message(&mut self, setter: impl FnOnce(&mut MessageBuilder)) {
        let mut builder = MessageBuilder::new(&mut self.message_data);
        setter(&mut builder);
        builder.finalize();
    }

    pub fn set_message_from_str(&mut self, text: &str) {
        self.set_message(|builder| builder.add_text(text));
    }

    pub fn data(&self) -> *const u8 {
        self.message_data.as_ptr()
    }
}
//! Generic command registry runner.
//!
//! Core owns no command names and no protocol behavior. It only provides the
//! small dispatch shape needed by a binary: a command advertises its name,
//! usage, and help text, and the runner calls the matching function with a
//! caller-owned context. The context is where protocol code can keep a store,
//! workers, TCP helpers, or anything else it needs; this file never imports
//! those concepts.
//!
//! The important invariant is locality. If a command's parser, help text, or
//! formatting changes, that change should happen in the module that exported
//! the command spec. This runner merely rejects duplicate names, reports
//! unknown commands with the registry's usage lines, and returns text lines for
//! the binary to print.

/// Positional arguments passed to a command after its command name.
#[derive(Debug, Clone, Copy)]
pub struct CliArgs<'a> {
    values: &'a [String],
}

impl<'a> CliArgs<'a> {
    pub const fn new(values: &'a [String]) -> Self {
        Self { values }
    }

    pub fn values(self) -> &'a [String] {
        self.values
    }

    pub fn get(self, index: usize) -> Option<&'a str> {
        self.values.get(index).map(String::as_str)
    }

    pub fn require_len(self, expected: usize, usage: &str) -> Result<(), String> {
        if self.values.len() == expected {
            Ok(())
        } else {
            Err(usage.to_string())
        }
    }

    pub fn parse_positive_usize(self, index: usize, usage: &str) -> Result<usize, String> {
        let value = self.get(index).ok_or_else(|| usage.to_string())?;
        let parsed = value.parse::<usize>().map_err(|_| usage.to_string())?;
        if parsed == 0 {
            return Err(usage.to_string());
        }
        Ok(parsed)
    }
}

/// Text returned by a command for the binary to print.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CliOutput {
    pub lines: Vec<String>,
}

impl CliOutput {
    pub fn lines(lines: Vec<String>) -> Self {
        Self { lines }
    }

    pub fn line(line: impl Into<String>) -> Self {
        Self {
            lines: vec![line.into()],
        }
    }
}

/// One command exported by a protocol or module.
#[derive(Clone, Copy)]
pub struct CliCommand<C> {
    pub name: &'static str,
    pub usage: &'static str,
    pub help: &'static str,
    pub run: for<'a> fn(&mut C, CliArgs<'a>) -> Result<CliOutput, String>,
}

/// Dispatch argv to one of the supplied command specs.
pub fn run<C>(
    commands: &[CliCommand<C>],
    context: &mut C,
    args: &[String],
) -> Result<CliOutput, String> {
    validate_command_names(commands)?;
    let Some(command_name) = args.first() else {
        return Err(usage(commands, "missing command"));
    };
    let Some(command) = commands.iter().find(|command| command.name == command_name) else {
        return Err(usage(
            commands,
            &format!("unknown command `{command_name}`"),
        ));
    };
    (command.run)(context, CliArgs::new(&args[1..]))
        .map_err(|err| format!("{}: {err}", command.name))
}

fn validate_command_names<C>(commands: &[CliCommand<C>]) -> Result<(), String> {
    for (index, left) in commands.iter().enumerate() {
        if commands[index + 1..]
            .iter()
            .any(|right| right.name == left.name)
        {
            return Err(format!("duplicate CLI command `{}`", left.name));
        }
    }
    Ok(())
}

pub fn usage<C>(commands: &[CliCommand<C>], reason: &str) -> String {
    let mut lines = vec![reason.to_string(), "usage:".to_string()];
    for command in commands {
        lines.push(format!("  topo --db PATH {}", command.usage));
    }
    lines.join("\n")
}

pub fn decode_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err("hex id must be 64 hex characters".to_string());
    }
    let mut out = [0; 32];
    let bytes = value.as_bytes();
    for idx in 0..32 {
        out[idx] = (hex_nibble(bytes[idx * 2])? << 4) | hex_nibble(bytes[idx * 2 + 1])?;
    }
    Ok(out)
}

pub fn encode_hex_32(id: &[u8; 32]) -> String {
    encode_hex(id)
}

pub fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("hex id contains non-hex character".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_hex_32, encode_hex, encode_hex_32};

    #[test]
    fn decode_hex_32_accepts_lowercase_and_uppercase() {
        let parsed =
            decode_hex_32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .expect("valid hex");

        assert_eq!(
            parsed,
            [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ]
        );
        assert_eq!(
            decode_hex_32(&"A".repeat(64)).expect("valid hex"),
            [0xaa; 32]
        );
    }

    #[test]
    fn decode_hex_32_rejects_wrong_length() {
        assert_eq!(
            decode_hex_32("00").expect_err("too short"),
            "hex id must be 64 hex characters"
        );
    }

    #[test]
    fn decode_hex_32_rejects_non_hex() {
        let mut value = "0".repeat(64);
        value.replace_range(12..13, "x");

        assert_eq!(
            decode_hex_32(&value).expect_err("not hex"),
            "hex id contains non-hex character"
        );
    }

    #[test]
    fn encode_hex_uses_lowercase() {
        assert_eq!(encode_hex(&[0, 1, 10, 15, 16, 255]), "00010a0f10ff");
        assert_eq!(encode_hex_32(&[0xab; 32]), "ab".repeat(32));
    }
}

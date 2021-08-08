use byteorder::{ByteOrder, NetworkEndian};
use nom::IResult;
use std::fmt::Write;

pub type BIResult<'a, O> = IResult<&'a [u8], O>;
pub type SIResult<'a, O> = IResult<&'a str, O>;

#[macro_export]
macro_rules! proto_enum {
    ($name:ident, $type:ty, { $($variant_name:ident = $variant_disc:expr,)+ } $(,)?) => {
        #[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
        pub enum $name {
            $( $variant_name = $variant_disc, )+
        }

        impl std::convert::TryFrom<$type> for $name {
            type Error = anyhow::Error;

            fn try_from(value: $type) -> Result<Self, Self::Error> {
                match value {
                    $( $variant_disc => Ok($name::$variant_name), )+
                    _ => { anyhow::bail!("unknown {}: {}", std::stringify!($ident), value) }
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
                write!(f, "{}", match self {
                    $( $name::$variant_name => std::stringify!($variant_name), )+
                })
            }
        }
    };
}

#[macro_export]
macro_rules! proto_enum_with_unknown {
    ($name:ident, $type:ty, { $($variant_name:ident = $variant_disc:expr,)+ } $(,)?) => {
        #[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
        pub enum $name {
            $( $variant_name, )+
            Unknown($type),
        }

        impl std::convert::TryFrom<$type> for $name {
            type Error = anyhow::Error;

            fn try_from(value: $type) -> Result<Self, Self::Error> {
                match value {
                    $( $variant_disc => Ok($name::$variant_name), )+
                    _ => Ok($name::Unknown(value))
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
                match self {
                    $( $name::$variant_name => write!(f, "{}", std::stringify!($variant_name)), )+
                    $name::Unknown(value) => write!(f, "Unknown({})", value),
                }
            }
        }

        impl crate::protocols::encdec::EncodeTo for $name {
            fn encoded_len(&self) -> usize {
                std::mem::size_of::<$type>()
            }

            fn encode_to(&self, buf: &mut [u8]) {
                match self {
                    $( $name::$variant_name => $variant_disc, )+
                    $name::Unknown(value) => *value
                }.encode_to(buf)
            }
        }
    };
}

pub fn hexdump(data: &[u8]) -> Result<String, std::fmt::Error> {
    let mut result = String::new();

    let offsetlen = (data.len() as f64).log(16.).ceil() as usize;

    for (chunk_num, chunk) in data.chunks(16).enumerate() {
        {
            let mut i = 0;

            write!(&mut result, "{:1$x}: ", chunk_num * 16, offsetlen)?;

            while i < 16 && i < chunk.len() {
                write!(&mut result, "{:02x} ", chunk[i])?;

                i = i + 1;
            }

            write!(&mut result, "{}", "   ".repeat(16 - i))?;
        }

        {
            let mut i = 0;

            while i < 16 && i < chunk.len() {
                if (chunk[i] as char).is_ascii_graphic() || (chunk[i] as char) == ' ' {
                    write!(&mut result, "{}", chunk[i] as char)?;
                } else {
                    write!(&mut result, ".")?;
                }

                i = i + 1;
            }
        }

        write!(&mut result, "\n")?;
    }

    Ok(result)
}

pub trait EncodeTo {
    fn encoded_len(&self) -> usize;
    fn encode_to(&self, buf: &mut [u8]);
}

impl<T: EncodeTo> EncodeTo for &T {
    fn encoded_len(&self) -> usize {
        (**self).encoded_len()
    }

    fn encode_to(&self, buf: &mut [u8]) {
        (**self).encode_to(buf)
    }
}

impl EncodeTo for u8 {
    fn encoded_len(&self) -> usize {
        1
    }

    fn encode_to(&self, buf: &mut [u8]) {
        buf[0] = *self;
    }
}

impl EncodeTo for u16 {
    fn encoded_len(&self) -> usize {
        2
    }

    fn encode_to(&self, buf: &mut [u8]) {
        NetworkEndian::write_u16(buf, *self);
    }
}

impl EncodeTo for u32 {
    fn encoded_len(&self) -> usize {
        4
    }

    fn encode_to(&self, buf: &mut [u8]) {
        NetworkEndian::write_u32(buf, *self);
    }
}

impl EncodeTo for &[u8] {
    fn encoded_len(&self) -> usize {
        self.len()
    }

    fn encode_to(&self, buf: &mut [u8]) {
        (&mut buf[..self.len()]).copy_from_slice(self);
    }
}

impl<T: EncodeTo> EncodeTo for Vec<T> {
    fn encoded_len(&self) -> usize {
        self.iter().map(|x| x.encoded_len()).sum()
    }

    fn encode_to(&self, buf: &mut [u8]) {
        let mut output = buf;

        for part in self.iter() {
            part.encode_to(&mut output);
            output = &mut output[part.encoded_len()..];
        }
    }
}

#[macro_export]
macro_rules! encode_to {
    ( $buf:expr, $($val:expr $(,)?)+ ) => {
        {
            let mut buf = $buf;
            $(
                $val.encode_to(&mut buf);
                buf = &mut buf[$val.encoded_len()..];
            )+
            let _ = buf;
        }
    }
}
#[macro_export]
macro_rules! encode {
    ( $($val:expr $(,)?)+ ) => {
        {
            let mut result = Vec::new();
            result.resize(
                $($val.encoded_len() + )+ 0,
                0u8,
            );

            crate::encode_to!(&mut result[..], $($val,)+);

            result
        }
    }
}

#[macro_export]
macro_rules! try_parse {
    ($block:tt, $error_template:expr) => {
        {
            let result = || -> nom::IResult<_, _> $block ();

            match result {
                Ok((_, output)) => Ok(output),
                Err(e) => Err(anyhow!($error_template, e.to_string())),
            }
        }
    };
}

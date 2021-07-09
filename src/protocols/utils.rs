use anyhow::{anyhow, Result as AHResult};
use byteorder::{ByteOrder, NetworkEndian};
use crossbeam::channel;
use nom::IResult;
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::RwLock;

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

#[macro_export]
macro_rules! encode {
    ( $($val:expr $(,)?)+ ) => {
        {
            let mut result = Vec::new();
            result.resize(
                $($val.encoded_len() + )+ 0,
                0u8,
            );

            let mut buf = &mut result[..];
            $(
                $val.encode_to(&mut buf);
                buf = &mut buf[$val.encoded_len()..];
            )+
            let _ = buf;

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

pub trait DispatchKeyed: Send + Sync + std::fmt::Debug
where
    Self::Key: std::fmt::Display + Eq + std::hash::Hash + Sync + Send,
{
    type Key;

    fn dispatch_key(&self) -> Self::Key;
}

pub struct RecvSenderMap<T: DispatchKeyed>(
    RwLock<HashMap<<T as DispatchKeyed>::Key, channel::Sender<T>>>,
);

impl<T: DispatchKeyed + Send + Sync + std::fmt::Debug> RecvSenderMap<T> {
    pub fn new() -> Self {
        Self(RwLock::new(HashMap::new()))
    }

    pub fn dispatch(&self, item: T) -> AHResult<()> {
        let key = item.dispatch_key();
        if let Some(ref sender) = &self.0.write().unwrap().get(&key) {
            sender
                .send(item)
                .map_err(|_| anyhow!("failed to send to {}", key))?;
        } else {
            println!("WARN: no receiver for {} ({:?})", key, item,);
        };

        Ok(())
    }

    pub fn register(&self, key: <T as DispatchKeyed>::Key, sender: channel::Sender<T>) {
        self.0.write().unwrap().insert(key, sender.clone());
    }
}

pub trait KeyedDispatcher
where
    Self::Item: DispatchKeyed,
{
    type Item;

    fn recv_map(&self) -> &RecvSenderMap<Self::Item>;

    fn register(
        &mut self,
        key: <Self::Item as DispatchKeyed>::Key,
        sender: channel::Sender<Self::Item>,
    ) {
        self.recv_map().register(key, sender);
    }
}

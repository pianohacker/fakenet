use anyhow::{anyhow, Result as AHResult};
use crossbeam::channel;
use std::collections::HashMap;
use std::sync::RwLock;

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

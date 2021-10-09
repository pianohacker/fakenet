use lazy_static::lazy_static;
use serde::Serialize;
use std::io::Write;
use std::sync::Mutex;

lazy_static! {
    static ref STATUS_UPDATE_LOCK: Mutex<()> = Mutex::new(());
    static ref STATUS: Mutex<serde_json::Map<String, serde_json::Value>> =
        Mutex::new(serde_json::Map::new());
}

#[must_use]
pub struct UpdateBuilder<'a> {
    _status_lock: std::sync::MutexGuard<'a, ()>,
    path: Vec<String>,
}

impl<'a> UpdateBuilder<'a> {
    pub fn child(mut self, name: impl Into<String>) -> Self {
        self.path.push(name.into());

        self
    }

    pub fn field(self, name: impl AsRef<str>, value: impl Serialize) -> Self {
        let mut current = &mut *STATUS.lock().unwrap();

        for elem in &self.path {
            current = current
                .entry(elem)
                .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
                .as_object_mut()
                .unwrap();
        }

        current.insert(
            name.as_ref().to_string(),
            serde_json::to_value(value).unwrap(),
        );

        self
    }

    pub fn write(self) {
        let stdout_handle = std::io::stdout();
        let mut stdout = stdout_handle.lock();

        serde_json::to_writer(&mut stdout, &*STATUS).unwrap();
        write!(stdout, "\n").unwrap();
    }
}

pub fn update<'a>() -> UpdateBuilder<'a> {
    UpdateBuilder {
        _status_lock: STATUS_UPDATE_LOCK.lock().unwrap(),
        path: Vec::new(),
    }
}

use serde::Serialize;
use std::io::Write;

#[must_use]
pub struct Builder(serde_json::Map<String, serde_json::Value>);

impl Builder {
    pub fn field(mut self, name: impl AsRef<str>, value: impl Serialize) -> Self {
        self.0.insert(
            name.as_ref().to_string(),
            serde_json::to_value(value).unwrap(),
        );

        self
    }

    pub fn write(self) {
        let stdout_handle = std::io::stdout();
        let mut stdout = stdout_handle.lock();

        serde_json::to_writer(&mut stdout, &self.0).unwrap();
        write!(stdout, "\n").unwrap();
    }
}

pub fn build(type_: impl AsRef<str>) -> Builder {
    let mut m = serde_json::Map::new();
    m.insert(
        "type".to_string(),
        serde_json::Value::String(type_.as_ref().to_string()),
    );

    Builder(m)
}

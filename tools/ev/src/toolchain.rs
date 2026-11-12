use std::path::Path;

#[derive(Debug)]
pub struct Toolchain {
    pub channel: String,
    pub components: Vec<String>,
    pub targets: Vec<String>,
}

impl Toolchain {
    pub fn load(root: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(root.join("rust-toolchain.toml"))
            .map_err(|error| error.to_string())?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let document = text
            .parse::<toml::Table>()
            .map_err(|error| error.to_string())?;
        let table = document
            .get("toolchain")
            .and_then(toml::Value::as_table)
            .ok_or("missing [toolchain] table")?;
        let channel = table
            .get("channel")
            .and_then(toml::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or("missing toolchain.channel")?;
        if ["nightly", "stable", "beta"].contains(&channel)
            || channel.chars().any(char::is_whitespace)
        {
            return Err("toolchain.channel must be an exact version or dated channel".into());
        }
        let list = |key: &str| -> Result<Vec<String>, String> {
            let array = table
                .get(key)
                .and_then(toml::Value::as_array)
                .filter(|values| !values.is_empty())
                .ok_or_else(|| format!("missing or empty toolchain.{key}"))?;
            array
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .filter(|value| !value.is_empty())
                        .map(str::to_owned)
                        .ok_or_else(|| format!("toolchain.{key} must contain nonempty strings"))
                })
                .collect()
        };
        Ok(Self {
            channel: channel.to_owned(),
            components: list("components")?,
            targets: list("targets")?,
        })
    }

    pub fn install_hint(&self) -> String {
        format!(
            "rustup toolchain install {} --profile minimal --component {} --target {}",
            self.channel,
            self.components.join(","),
            self.targets.join(",")
        )
    }
}

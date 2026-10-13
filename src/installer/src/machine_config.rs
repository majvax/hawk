//! Edits the machine's config.toml without disturbing what its owner wrote
//! there: only the tables the installer owns ([[relay]], [[update]]) are
//! touched, and comments and everything else stay as they were. The
//! service reads each table as an array of tables (`[[relay]]`), so that's
//! the shape written.

use toml_edit::{ArrayOfTables, DocumentMut, Item, Table, value};

use crate::release::{Overrides, Source};

/// The update settings in a machine's config, as written.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateSettings {
    pub policy: Option<String>,
    pub channel: Option<String>,
    pub manifest_url: Option<String>,
    pub public_key: Option<String>,
}

impl UpdateSettings {
    /// Where to look for releases, with command-line choices on top.
    pub fn source(&self, overrides: &Overrides) -> Result<Source, String> {
        let channel_name = self.channel.clone().unwrap_or_default();
        let channel = hawk_update::Channel::parse(&channel_name)
            .ok_or_else(|| format!("the config's update channel \"{channel_name}\" isn't stable or beta"))?;
        Ok(overrides.over(
            self.manifest_url.as_deref().unwrap_or_default(),
            self.public_key.as_deref().unwrap_or_default(),
            channel,
        ))
    }
}

pub fn parse(text: &str) -> Result<DocumentMut, String> {
    text.parse::<DocumentMut>().map_err(|error| format!("config.toml doesn't parse: {error}"))
}

/// The one table of an array-of-tables, created if missing. A config with
/// several (which the service refuses anyway) is reduced to the first.
fn single_table<'a>(document: &'a mut DocumentMut, name: &str) -> &'a mut Table {
    let keep = match document.get(name) {
        Some(Item::ArrayOfTables(array)) => array.get(0).cloned(),
        _ => None,
    };
    let mut array = ArrayOfTables::new();
    array.push(keep.unwrap_or_default());
    document.insert(name, Item::ArrayOfTables(array));
    document[name].as_array_of_tables_mut().and_then(|array| array.get_mut(0)).expect("just inserted")
}

pub fn set_relay_url(document: &mut DocumentMut, url: &str) {
    single_table(document, "relay")["url"] = value(url);
}

pub fn relay_url(document: &DocumentMut) -> Option<String> {
    first_table(document, "relay")?.get("url")?.as_str().map(str::to_owned)
}

fn first_table<'a>(document: &'a DocumentMut, name: &str) -> Option<&'a Table> {
    document.get(name)?.as_array_of_tables()?.get(0)
}

/// Sets what was chosen; leaves what wasn't as it is.
pub fn set_update(document: &mut DocumentMut, settings: &UpdateSettings) {
    let table = single_table(document, "update");
    let fields = [
        ("policy", &settings.policy),
        ("channel", &settings.channel),
        ("manifest_url", &settings.manifest_url),
        ("public_key", &settings.public_key),
    ];
    for (key, setting) in fields {
        if let Some(setting) = setting {
            table[key] = value(setting.as_str());
        }
    }
}

pub fn update_settings(document: &DocumentMut) -> UpdateSettings {
    let Some(table) = first_table(document, "update") else { return UpdateSettings::default() };
    let text = |key: &str| table.get(key).and_then(Item::as_str).map(str::to_owned).filter(|text| !text.is_empty());
    UpdateSettings {
        policy: text("policy"),
        channel: text("channel"),
        manifest_url: text("manifest_url"),
        public_key: text("public_key"),
    }
}

/// What a new machine's config says before its owner changes anything: the
/// relay, update settings, and the off-by-default features spelled out so
/// they're easy to find.
pub const NEW_CONFIG: &str = r#"# Hawk machine settings. Changes take effect when the service restarts
# (Services > Hawk Remote Service > Restart, or `hawk-setup repair machine`).
# Only administrators of this PC can change this file: nothing on the relay
# can widen what it allows.

# What viewers may do with this PC's clipboard: off, pull (paste in, and
# read it when asked) or sync (pull, plus every copy here is sent to them).
[[clipboard]]
mode = "pull"
view_pull = false

# Sending files to and from one folder. Off unless turned on here.
[[files]]
enabled = false
drop_dir = ""        # empty: %USERPROFILE%\Downloads\Hawk

# A shell for dev and owner shares, as the logged-on user. Off unless turned on.
[[shell]]
enabled = false
command = "powershell.exe -NoLogo"
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edits_keep_the_rest() {
        let mut document = parse("# mine\n[[shell]]\nenabled = true # really\n").unwrap();
        set_relay_url(&mut document, "wss://relay.example.com/v1/ws");
        set_update(&mut document, &UpdateSettings { policy: Some("auto".into()), ..UpdateSettings::default() });
        let text = document.to_string();
        assert!(text.contains("# mine") && text.contains("enabled = true # really"));
        assert!(text.contains("[[relay]]") && text.contains("[[update]]"));

        let reread = parse(&text).unwrap();
        assert_eq!(relay_url(&reread).as_deref(), Some("wss://relay.example.com/v1/ws"));
        assert_eq!(update_settings(&reread).policy.as_deref(), Some("auto"));

        // Changing the relay again replaces it rather than adding a second.
        let mut again = reread;
        set_relay_url(&mut again, "wss://other.example.com/v1/ws");
        assert_eq!(again.to_string().matches("[[relay]]").count(), 1);
        assert_eq!(update_settings(&again).policy.as_deref(), Some("auto"), "update settings kept");
    }

    #[test]
    fn new_config_parses() {
        let document = parse(NEW_CONFIG).unwrap();
        assert!(document.get("clipboard").is_some_and(Item::is_array_of_tables));
    }

    #[test]
    fn source_from_settings() {
        let settings = UpdateSettings { channel: Some("beta".into()), ..UpdateSettings::default() };
        let source = settings.source(&Overrides::default()).unwrap();
        assert_eq!(source.channel, hawk_update::Channel::Beta);
        let stable = Overrides { channel: Some(hawk_update::Channel::Stable), ..Overrides::default() };
        assert_eq!(settings.source(&stable).unwrap().channel, hawk_update::Channel::Stable);
        let bad = UpdateSettings { channel: Some("nightly".into()), ..UpdateSettings::default() };
        assert!(bad.source(&Overrides::default()).is_err());
    }
}

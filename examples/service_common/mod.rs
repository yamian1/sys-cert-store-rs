use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::time::Duration;

const DEFAULT_INTERVAL_MINUTES: u64 = 30;

pub fn read_interval(path: &Path) -> Result<Duration, String> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == ErrorKind::NotFound => String::new(),
        Err(error) => {
            return Err(format!(
                "cannot read configuration {}: {error}",
                path.display()
            ));
        }
    };

    let mut interval_minutes = None;
    for (index, line) in contents.lines().enumerate() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!(
                "{}:{} must use key=value syntax",
                path.display(),
                index + 1
            ));
        };
        if key.trim() != "interval_minutes" {
            return Err(format!(
                "{}:{} has unknown setting {}",
                path.display(),
                index + 1,
                key.trim()
            ));
        }
        if interval_minutes.is_some() {
            return Err(format!(
                "{}:{} defines interval_minutes more than once",
                path.display(),
                index + 1
            ));
        }
        let minutes = value.trim().parse::<u64>().map_err(|_| {
            format!(
                "{}:{} has an invalid interval_minutes value",
                path.display(),
                index + 1
            )
        })?;
        if minutes == 0 {
            return Err(format!(
                "{}:{} requires interval_minutes to be greater than zero",
                path.display(),
                index + 1
            ));
        }
        interval_minutes = Some(minutes);
    }

    let minutes = interval_minutes.unwrap_or(DEFAULT_INTERVAL_MINUTES);
    let seconds = minutes
        .checked_mul(60)
        .ok_or_else(|| "interval_minutes is too large".to_owned())?;
    Ok(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_configuration_uses_default() {
        let path = std::env::temp_dir().join(format!(
            "sys-cert-store-missing-config-{}",
            std::process::id()
        ));
        assert_eq!(read_interval(&path).unwrap(), Duration::from_secs(1800));
    }
}

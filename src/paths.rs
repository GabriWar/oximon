use anyhow::{Context, Result};
use directories::ProjectDirs;
use std::path::PathBuf;

fn dirs() -> Result<ProjectDirs> {
    ProjectDirs::from("", "", "oximon").context("no home dir")
}

pub fn data_dir() -> Result<PathBuf> {
    let d = dirs()?;
    let p = d.data_dir().to_path_buf();
    std::fs::create_dir_all(&p)?;
    Ok(p)
}

pub fn cache_dir() -> Result<PathBuf> {
    let d = dirs()?;
    let p = d.cache_dir().to_path_buf();
    std::fs::create_dir_all(&p)?;
    Ok(p)
}

pub fn state_db() -> Result<PathBuf> {
    Ok(data_dir()?.join("state.db"))
}

pub fn oui_csv() -> Result<PathBuf> {
    Ok(cache_dir()?.join("oui.csv"))
}

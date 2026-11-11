//! StatScan statik tarama motoru (Rust).
//!
//! Ilkeler: dosya ASLA calistirilmaz; ag kullanilmaz; hicbir dosya degistirilmez/silinmez/tasinmaz.
//! Girdi guvenilmezdir: tum okumalar sinirli ve panik etmeyecek sekilde yazilir.

pub mod data;
pub mod deobf;
pub mod engine;
pub mod ioc;
pub mod model;
pub mod report;
pub mod rules;
pub mod score;
pub mod rx;
pub mod state;
pub mod util;

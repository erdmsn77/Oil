#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod spherical_roll;
mod synapse;
mod theme;

use app::OilGuiApp;
use eframe::egui::Vec2;
use eframe::NativeOptions;

fn main() -> eframe::Result<()> {
    let native_options = NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size(Vec2::new(1200.0, 750.0))
            .with_min_inner_size(Vec2::new(800.0, 500.0))
            .with_drag_and_drop(true)
            .with_title("Oil — Forensic Binary Triage Engine"),
        ..Default::default()
    };

    eframe::run_native(
        "Oil Forensic Triage",
        native_options,
        Box::new(|cc| Ok(Box::new(OilGuiApp::new(cc)))),
    )
}

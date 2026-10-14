//! Oil GUI Theme & Aesthetics.
//!
//! Strict forensic palette inspired by bl00d.money and high-contrast terminal tools:
//! Matte Charcoal (#080808), Electric Acid (#e8ff00), Emerald Phosphor (#4ef2bb),
//! and Slate typography (#94a3b8 / #e2e8f0).

use eframe::egui::{Color32, Context, Visuals};

#[allow(dead_code)]
pub const COLOR_BG_DEEP: Color32 = Color32::from_rgb(8, 8, 8);
#[allow(dead_code)]
pub const COLOR_BG_PANEL: Color32 = Color32::from_rgb(12, 14, 13);
#[allow(dead_code)]
pub const COLOR_BORDER_SUBTLE: Color32 = Color32::from_rgb(26, 36, 32);
#[allow(dead_code)]
pub const COLOR_ACCENT_ACID: Color32 = Color32::from_rgb(232, 255, 0);
#[allow(dead_code)]
pub const COLOR_ACCENT_MINT: Color32 = Color32::from_rgb(78, 242, 187);
#[allow(dead_code)]
pub const COLOR_TEXT_MUTED: Color32 = Color32::from_rgb(100, 116, 139);
#[allow(dead_code)]
pub const COLOR_TEXT_BRIGHT: Color32 = Color32::from_rgb(241, 245, 249);

/// Configures egui context visuals for the Oil forensic experience.
pub fn apply_oil_theme(ctx: &Context) {
    let mut visuals = Visuals::dark();

    visuals.override_text_color = Some(COLOR_TEXT_BRIGHT);
    visuals.panel_fill = COLOR_BG_DEEP;
    visuals.window_fill = COLOR_BG_PANEL;
    visuals.window_stroke.color = COLOR_BORDER_SUBTLE;
    visuals.window_stroke.width = 1.0;

    visuals.widgets.noninteractive.bg_fill = COLOR_BG_PANEL;
    visuals.widgets.noninteractive.bg_stroke.color = COLOR_BORDER_SUBTLE;
    visuals.widgets.noninteractive.fg_stroke.color = COLOR_TEXT_MUTED;

    visuals.widgets.inactive.bg_fill = Color32::from_rgb(16, 20, 18);
    visuals.widgets.inactive.bg_stroke.color = COLOR_BORDER_SUBTLE;
    visuals.widgets.inactive.fg_stroke.color = COLOR_TEXT_BRIGHT;

    visuals.widgets.hovered.bg_fill = Color32::from_rgb(24, 30, 26);
    visuals.widgets.hovered.bg_stroke.color = COLOR_ACCENT_ACID;
    visuals.widgets.hovered.fg_stroke.color = COLOR_ACCENT_ACID;

    visuals.widgets.active.bg_fill = Color32::from_rgb(32, 40, 34);
    visuals.widgets.active.bg_stroke.color = COLOR_ACCENT_ACID;
    visuals.widgets.active.fg_stroke.color = COLOR_ACCENT_ACID;

    ctx.set_visuals(visuals);
}

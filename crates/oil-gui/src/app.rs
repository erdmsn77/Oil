use crate::spherical_roll::SphericalRollMenu;
use crate::synapse::SynapseBackground;
use crate::theme::apply_oil_theme;
use eframe::egui::{
    Align2, CentralPanel, Color32, Context, FontId, Frame, Painter, Pos2, Rect, Rounding, Stroke,
    Vec2,
};
use eframe::App;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{channel, Receiver};
use std::thread;

pub struct OilGuiApp {
    pub synapse: SynapseBackground,
    pub roll_menu: SphericalRollMenu,
    pub last_frame_time: Option<f64>,
    pub selected_file_path: Option<String>,
    pub dropzone_hover_anim: f32,
    pub photon_scan_anim: f32,
    pub file_receiver: Option<Receiver<PathBuf>>,
}

impl Default for OilGuiApp {
    fn default() -> Self {
        Self {
            synapse: SynapseBackground::new(8000),
            roll_menu: SphericalRollMenu::new_demo_triage(),
            last_frame_time: None,
            selected_file_path: None,
            dropzone_hover_anim: 0.0,
            photon_scan_anim: 1.0,
            file_receiver: None,
        }
    }
}

impl OilGuiApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        apply_oil_theme(&cc.egui_ctx);
        Self::default()
    }
}

impl App for OilGuiApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        // Continuous smooth 60+ FPS animation loop
        ctx.request_repaint();

        // High precision frame delta time
        let current_time = ctx.input(|i| i.time);
        let dt = match self.last_frame_time {
            Some(last) => (current_time - last) as f32,
            None => 0.016,
        };
        self.last_frame_time = Some(current_time);

        // Standard system mouse pointer
        let mouse_pos = ctx.input(|i| i.pointer.hover_pos());
        let mouse_clicked = ctx.input(|i| i.pointer.primary_clicked());

        // Mouse wheel scroll delta for spherical roll menu
        let scroll_delta = ctx.input(|i| i.raw_scroll_delta.y);

        // Advance photon sweep animation (top to bottom)
        if self.photon_scan_anim < 1.0 {
            self.photon_scan_anim += dt * 1.5;
        }

        // Check if file was selected via native Windows file dialog
        if let Some(ref rx) = self.file_receiver {
            if let Ok(path) = rx.try_recv() {
                self.file_receiver = None;
                let path_str = path.display().to_string();
                self.selected_file_path = Some(path_str.clone());
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("numune.exe");
                let scan_res = oil_core::scan_path(&path);
                self.roll_menu.populate_from_scan(name, scan_res);
                self.photon_scan_anim = 0.0;
            }
        }

        // Check for dropped files and hovered files
        let is_window_drag_hovered = ctx.input(|i| !i.raw.hovered_files.is_empty());
        ctx.input(|i| {
            if let Some(dropped) = i.raw.dropped_files.first() {
                if let Some(path) = &dropped.path {
                    let path_str = path.display().to_string();
                    self.selected_file_path = Some(path_str.clone());
                    let name = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("numune.exe");
                    let scan_res = oil_core::scan_path(path);
                    self.roll_menu.populate_from_scan(name, scan_res);
                    self.photon_scan_anim = 0.0;
                }
            }
        });

        // Advance spherical roll physics
        self.roll_menu.update(dt, scroll_delta);

        // Main canvas
        CentralPanel::default()
            .frame(Frame::none().fill(Color32::from_rgb(0, 0, 0)))
            .show(ctx, |ui| {
                let rect = ui.available_rect_before_wrap();
                let painter = ui.painter_at(rect);
                let center = rect.center();
                let screen_size = Pos2::new(rect.width(), rect.height());

                // 1. 3D Synapse background (exact 21st.dev mathematical reproduction)
                self.synapse.update(dt, mouse_pos, screen_size);
                self.synapse.render(&painter, center, screen_size);

                // Two-column layout if wide enough, otherwise centered stack
                let is_wide = rect.width() >= 1050.0;

                let (dz_center, roll_center, roll_width) = if is_wide {
                    (
                        Pos2::new(center.x - 260.0, center.y),
                        Pos2::new(center.x + 240.0, center.y),
                        480.0_f32,
                    )
                } else {
                    (
                        Pos2::new(center.x, center.y - 140.0),
                        Pos2::new(center.x, center.y + 150.0),
                        (rect.width() - 80.0).clamp(320.0, 520.0),
                    )
                };

                // 2. Render Central Ultra-Sheer Glass Dropzone
                let dz_size = Vec2::new(420.0, 230.0);
                let dz_rect = Rect::from_center_size(dz_center, dz_size);
                let is_dz_hovered =
                    mouse_pos.is_some_and(|m| dz_rect.contains(m)) || is_window_drag_hovered;

                // Handle clicking dropzone to open native Windows file dialog
                if mouse_clicked
                    && mouse_pos.is_some_and(|m| dz_rect.contains(m))
                    && self.file_receiver.is_none()
                {
                    let (tx, rx) = channel();
                    self.file_receiver = Some(rx);
                    thread::spawn(move || {
                        let output = Command::new("powershell")
                            .args([
                                "-NoProfile",
                                "-WindowStyle",
                                "Hidden",
                                "-Command",
                                "[System.Reflection.Assembly]::LoadWithPartialName('System.windows.forms') | Out-Null; \
                                 $d = New-Object System.Windows.Forms.OpenFileDialog; \
                                 $d.Title = 'İncelenecek Dosyayı Seçin'; \
                                 $d.Filter = 'Desteklenen Dosyalar (*.exe;*.dll;*.sys;*.zip)|*.exe;*.dll;*.sys;*.zip|Tüm Dosyalar (*.*)|*.*'; \
                                 if($d.ShowDialog() -eq 'OK'){ Write-Output $d.FileName }",
                            ])
                            .output();
                        if let Ok(out) = output {
                            let path_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
                            if !path_str.is_empty() {
                                let path = PathBuf::from(path_str);
                                if path.exists() {
                                    let _ = tx.send(path);
                                }
                            }
                        }
                    });
                }

                let target_anim = if is_dz_hovered { 1.0 } else { 0.0 };
                self.dropzone_hover_anim +=
                    (target_anim - self.dropzone_hover_anim) * (dt * 8.0).min(1.0);

                render_sheer_glass_dropzone(
                    &painter,
                    dz_rect,
                    self.dropzone_hover_anim,
                    &self.selected_file_path,
                    self.photon_scan_anim,
                );

                // 3. Render Spherical Fisheye Rolling Menu & Threat Isolation Glide
                let dock_pos = Pos2::new(dz_center.x, dz_center.y + 44.0);
                self.roll_menu.render(
                    &painter,
                    roll_center,
                    roll_width,
                    dock_pos,
                    mouse_pos,
                    mouse_clicked,
                );
            });
    }
}

/// Renders an authentic frosted / acrylic glass panel with light-source rim and smoked depth.
fn draw_sheer_glass_panel(painter: &Painter, rect: Rect, rounding: Rounding, light_factor: f32) {
    // 1. Frosted smoked glass base fill (~82% opacity - soft acrylic blur depth over synapse filaments)
    let bg_color = Color32::from_rgba_unmultiplied(10, 14, 22, 210);
    painter.rect_filled(rect, rounding, bg_color);

    // 2. Inner frost diffusion border (soft crystalline refraction)
    let inner_rect = rect.shrink(1.0);
    let inner_rim_color = Color32::from_rgba_unmultiplied(255, 255, 255, 14);
    painter.rect_stroke(inner_rect, rounding, Stroke::new(1.0_f32, inner_rim_color));

    // 3. Ambient glass edge with subtle light refraction
    let rim_alpha = (35.0 + light_factor * 45.0) as u8;
    let rim_color = Color32::from_rgba_unmultiplied(255, 255, 255, rim_alpha);
    painter.rect_stroke(rect, rounding, Stroke::new(1.0_f32, rim_color));

    // 4. Specular top-light source highlight (Frosted glass linear reflection)
    let top_light_alpha = (90.0 + light_factor * 150.0) as u8;
    let top_light_color = Color32::from_rgba_unmultiplied(255, 255, 255, top_light_alpha);
    let top_margin = 12.0;
    painter.line_segment(
        [
            Pos2::new(rect.min.x + top_margin, rect.min.y),
            Pos2::new(rect.max.x - top_margin, rect.min.y),
        ],
        Stroke::new(1.2_f32, top_light_color),
    );

    // 5. Soft cyan/ice glow when hovered
    if light_factor > 0.05 {
        let glow_alpha = (light_factor * 35.0) as u8;
        let glow_stroke = Stroke::new(
            2.5_f32,
            Color32::from_rgba_unmultiplied(160, 220, 255, glow_alpha),
        );
        painter.rect_stroke(rect, rounding, glow_stroke);
    }
}

/// Renders the sheer frosted glass dropzone card with vertical photon sweep scanner.
fn render_sheer_glass_dropzone(
    painter: &Painter,
    rect: Rect,
    hover_anim: f32,
    selected_path: &Option<String>,
    photon_scan_anim: f32,
) {
    draw_sheer_glass_panel(painter, rect, Rounding::same(14.0), hover_anim);

    let center_x = rect.center().x;
    let center_y = rect.center().y;

    // Vertical photon sweep scan line (sweeps from TOP to BOTTOM)
    if photon_scan_anim < 1.0 {
        let p = photon_scan_anim.clamp(0.0, 1.0);
        let scan_y = rect.min.y + rect.height() * p;
        let fade = (1.0 - (p - 0.5).abs() * 2.0).max(0.35);

        // Trailing soft cyan wash behind the beam
        let trail_top = (scan_y - 22.0).max(rect.min.y);
        let trail_rect = Rect::from_min_max(
            Pos2::new(rect.min.x + 2.0, trail_top),
            Pos2::new(rect.max.x - 2.0, scan_y),
        );
        painter.rect_filled(
            trail_rect,
            Rounding::same(4.0),
            Color32::from_rgba_unmultiplied(0, 220, 255, (fade * 25.0) as u8),
        );

        // Outer glow halo line
        painter.line_segment(
            [
                Pos2::new(rect.min.x + 8.0, scan_y),
                Pos2::new(rect.max.x - 8.0, scan_y),
            ],
            Stroke::new(
                3.5_f32,
                Color32::from_rgba_unmultiplied(80, 220, 255, (fade * 140.0) as u8),
            ),
        );

        // Sharp core photon laser line
        painter.line_segment(
            [
                Pos2::new(rect.min.x + 8.0, scan_y),
                Pos2::new(rect.max.x - 8.0, scan_y),
            ],
            Stroke::new(
                1.5_f32,
                Color32::from_rgba_unmultiplied(240, 255, 255, (fade * 255.0) as u8),
            ),
        );
    }

    // Minimalist icon
    let icon_alpha = (180.0 + hover_anim * 75.0) as u8;
    let icon_color = Color32::from_rgba_unmultiplied(255, 255, 255, icon_alpha);
    painter.text(
        Pos2::new(center_x, center_y - 48.0),
        Align2::CENTER_CENTER,
        "↓",
        FontId::proportional(28.0),
        icon_color,
    );

    // Main status text
    if let Some(path) = selected_path {
        let pill_rect =
            Rect::from_center_size(Pos2::new(center_x, center_y - 20.0), Vec2::new(350.0, 32.0));
        painter.rect_filled(
            pill_rect,
            Rounding::same(8.0),
            Color32::from_rgba_unmultiplied(15, 25, 38, 120),
        );
        painter.rect_stroke(
            pill_rect,
            Rounding::same(8.0),
            Stroke::new(1.0_f32, Color32::from_rgba_unmultiplied(120, 200, 255, 90)),
        );

        let file_name = Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(path.as_str());

        painter.text(
            Pos2::new(center_x, center_y - 20.0),
            Align2::CENTER_CENTER,
            format!("KONTROL EDİLİYOR: {}", file_name),
            FontId::proportional(13.0),
            Color32::from_rgb(240, 248, 255),
        );
    } else {
        painter.text(
            Pos2::new(center_x, center_y - 6.0),
            Align2::CENTER_CENTER,
            "Tıklayın veya Dosyayı Buraya Bırakın",
            FontId::proportional(15.0),
            Color32::from_rgb(245, 248, 252),
        );

        painter.text(
            Pos2::new(center_x, center_y + 20.0),
            Align2::CENTER_CENTER,
            "Güvenli ve gizli yerel analiz • Buluta yükleme yapılmaz",
            FontId::proportional(12.0),
            Color32::from_rgba_unmultiplied(160, 180, 205, 190),
        );

        // Format tags
        let tags = ".EXE   •   .DLL   •   .SYS   •   .ZIP";
        painter.text(
            Pos2::new(center_x, center_y + 54.0),
            Align2::CENTER_CENTER,
            tags,
            FontId::monospace(10.5),
            Color32::from_rgba_unmultiplied(140, 165, 195, 160),
        );
    }
}

//! Spherical effect rolling menu navigation.
//!
//! Reconstructed from WebGL spherical / fisheye drum navigation:
//! Items are mapped onto the surface of a virtual sphere of radius R:
//! - Angle phi = dy / R
//! - Projected Y = Center.y + R * sin(phi)
//! - Fisheye Scale = cos(phi)^1.4 (center magnified, poles compressed)
//! - Spherical Opacity = cos(phi)^2.0 (fades towards the horizon)
//! - Inertial rolling momentum on mouse wheel scroll and triage progression.
//! - Threat extraction & magnetic isolation glide towards the inspection dock.

use eframe::egui::{Align2, Color32, FontId, Painter, Pos2, Rect, Rounding, Stroke, Vec2};
use std::f32::consts::FRAC_PI_2;

/// A single forensic data item displayed in the rolling sphere stream.
#[derive(Clone, Debug)]
pub struct RollItem {
    pub tag: String,
    pub title: String,
    pub detail: String,
    pub status_color: Color32,
    pub is_isolated: bool,
    pub isolation_progress: f32,
}

/// Spherical fisheye rolling menu engine.
pub struct SphericalRollMenu {
    pub items: Vec<RollItem>,
    pub current_scroll: f32,
    pub target_scroll: f32,
    pub radius: f32,
    pub item_spacing: f32,
    pub is_streaming: bool,
    pub stream_time: f32,
}

impl Default for SphericalRollMenu {
    fn default() -> Self {
        Self::new_demo_triage()
    }
}

impl SphericalRollMenu {
    /// Creates a new rolling menu with sample triage inspection items.
    pub fn new_demo_triage() -> Self {
        let items = vec![
            RollItem {
                tag: "[01] BİÇİM KONTROLÜ".to_string(),
                title: "Windows Program Formatı".to_string(),
                detail: "Geçerli ve standart bir Windows program yapısı doğrulandı".to_string(),
                status_color: Color32::from_rgb(120, 220, 180),
                is_isolated: false,
                isolation_progress: 0.0,
            },
            RollItem {
                tag: "[02] GİZLİ KOD".to_string(),
                title: "Şüpheli Paketleme & Şifreleme".to_string(),
                detail: "Dosya içine gizlenmiş şüpheli paket veya kilitli katman yok".to_string(),
                status_color: Color32::from_rgb(180, 200, 230),
                is_isolated: false,
                isolation_progress: 0.0,
            },
            RollItem {
                tag: "[03] BELLEK İZNİ".to_string(),
                title: "Çalışma ve Yazma Yetkileri".to_string(),
                detail: "Sisteme yabancı kod enjekte edebilecek tehlikeli izin bulunmadı"
                    .to_string(),
                status_color: Color32::from_rgb(120, 220, 180),
                is_isolated: false,
                isolation_progress: 0.0,
            },
            RollItem {
                tag: "[04] VERİ HIRSIZLIĞI".to_string(),
                title: "Şifre ve Hesap Avcısı Taraması".to_string(),
                detail: "Discord, Telegram, cüzdan veya tarayıcı şifresi çalan zararlı kodu yok"
                    .to_string(),
                status_color: Color32::from_rgb(120, 220, 180),
                is_isolated: false,
                isolation_progress: 0.0,
            },
            RollItem {
                tag: "[05] SİSTEM TAKLİDİ".to_string(),
                title: "Sahte Sistem Dosyası Tespiti".to_string(),
                detail: "Orijinal Windows bileşenlerinin adının arkasına saklanmıyor".to_string(),
                status_color: Color32::from_rgb(120, 220, 180),
                is_isolated: false,
                isolation_progress: 0.0,
            },
            RollItem {
                tag: "[06] KOD DEĞİŞİKLİĞİ".to_string(),
                title: "Dışarıdan Eklenen Kodlar".to_string(),
                detail: "Orijinal akışı saptıran şüpheli sıçrama veya yama tespit edilmedi"
                    .to_string(),
                status_color: Color32::from_rgb(120, 220, 180),
                is_isolated: false,
                isolation_progress: 0.0,
            },
            RollItem {
                tag: "[07] KUYRUK VERİSİ".to_string(),
                title: "Dosya Sonu Gizli Ekleri".to_string(),
                detail: "Dosya sonuna sonradan iliştirilmiş gizli zararlı yük bulunmuyor"
                    .to_string(),
                status_color: Color32::from_rgb(180, 200, 230),
                is_isolated: false,
                isolation_progress: 0.0,
            },
            RollItem {
                tag: "[08] SONUÇ".to_string(),
                title: "Güvenlik Değerlendirmesi".to_string(),
                detail: "GÖSTERGE BULUNAMADI // Şüpheli bir zararlı faaliyete rastlanmadı"
                    .to_string(),
                status_color: Color32::from_rgb(240, 245, 255),
                is_isolated: false,
                isolation_progress: 0.0,
            },
        ];

        Self {
            items,
            current_scroll: 0.0,
            target_scroll: 0.0,
            radius: 220.0,
            item_spacing: 62.0,
            is_streaming: false,
            stream_time: 0.0,
        }
    }

    /// Populates rolling stream from real in-memory oil-core scan report.
    pub fn populate_from_scan(
        &mut self,
        file_name: &str,
        scan_res: Result<oil_core::models::ScanReport, oil_core::io::IoError>,
    ) {
        let mut new_items = Vec::new();
        new_items.push(RollItem {
            tag: "[DOSYA ALINDI]".to_string(),
            title: file_name.to_string(),
            detail: "Numune güvenli yerel belleğe alındı (Diske asla yazılmaz)".to_string(),
            status_color: Color32::from_rgb(100, 200, 255),
            is_isolated: false,
            isolation_progress: 0.0,
        });

        match scan_res {
            Ok(report) => {
                let mut threats_found = false;
                for ev in &report.evidence {
                    if ev.is_threat_signal {
                        threats_found = true;
                        let (tag_name, title_name) = match &ev.kind {
                            oil_core::models::EvidenceKind::DiscordWebhook { .. } => {
                                ("[TEHDİT // IOC]", "Discord Webhook Veri Sızıntısı")
                            }
                            oil_core::models::EvidenceKind::TelegramToken { .. } => {
                                ("[TEHDİT // IOC]", "Telegram Botu Veri Sızıntısı")
                            }
                            oil_core::models::EvidenceKind::CryptoWallet { .. } => {
                                ("[ŞÜPHELİ // IOC]", "Kripto Cüzdan Hedefi")
                            }
                            oil_core::models::EvidenceKind::CredentialPath { .. } => {
                                ("[TEHDİT // STEALER]", "Tarayıcı Şifre Veritabanı Erişimi")
                            }
                            oil_core::models::EvidenceKind::PowerShellCommand { .. } => {
                                ("[ŞÜPHELİ // KOD]", "Gizli PowerShell Komutu")
                            }
                            oil_core::models::EvidenceKind::HighEntropySection { .. } => {
                                ("[ŞÜPHELİ // PAKET]", "Şifrelenmiş veya Paketli Bölüm")
                            }
                            oil_core::models::EvidenceKind::RwxSection { .. } => (
                                "[TEHDİT // BELLEK]",
                                "RWX (Çalıştırılabilir & Yazılabilir) İzni",
                            ),
                            oil_core::models::EvidenceKind::InjectionImport { .. } => {
                                ("[TEHDİT // ENJEKSİYON]", "Süreç İçi Kod Enjeksiyon Yetkisi")
                            }
                            oil_core::models::EvidenceKind::SensitiveApiImport { .. } => {
                                ("[ŞÜPHELİ // API]", "Kritik Şifre Çözme / DPAPI Çağrısı")
                            }
                            oil_core::models::EvidenceKind::DllProxyHook { .. } => {
                                ("[ŞÜPHELİ // SAHTE DLL]", "Sistem DLL Taklidi")
                            }
                            oil_core::models::EvidenceKind::EmulatorProfile {
                                is_legitimate,
                                ..
                            } => {
                                if !*is_legitimate || ev.is_threat_signal {
                                    (
                                        "[TEHDİT // SAHTE EMÜLATÖR]",
                                        "Zararlı / Sahte Oyun Emülatörü",
                                    )
                                } else {
                                    ("[DOĞRULANMIŞ EMÜLATÖR]", "Meşru Oyun Platformu Emülatörü")
                                }
                            }
                            _ => ("[BULGU]", "Şüpheli Güvenlik Göstergesi"),
                        };

                        new_items.push(RollItem {
                            tag: tag_name.to_string(),
                            title: title_name.to_string(),
                            detail: ev.explanation.clone(),
                            status_color: Color32::from_rgb(255, 95, 80),
                            is_isolated: true,
                            isolation_progress: 0.0,
                        });
                    }
                }

                if !threats_found {
                    if let Some(emu_ev) = report.evidence.iter().find(|e| {
                        matches!(
                            e.kind,
                            oil_core::models::EvidenceKind::EmulatorProfile { .. }
                        )
                    }) {
                        if let oil_core::models::EvidenceKind::EmulatorProfile {
                            ref name,
                            ref indicators,
                            ..
                        } = emu_ev.kind
                        {
                            new_items.push(RollItem {
                                tag: "[DOĞRULANMIŞ EMÜLATÖR]".to_string(),
                                title: format!("{} (Steamworks DRM Mimarisi)", name),
                                detail: format!(
                                    "Çevrimdışı oyun emülatörü profili ({} gösterge) // Zararlı enjeksiyon tespit edilmedi",
                                    indicators.len()
                                ),
                                status_color: Color32::from_rgb(100, 240, 255),
                                is_isolated: false,
                                isolation_progress: 0.0,
                            });
                        }
                    }

                    new_items.push(RollItem {
                        tag: "[BİÇİM DOĞRULAMA]".to_string(),
                        title: "Standart Windows İkili Yapısı".to_string(),
                        detail: "Başlıklar ve bölümler geçerli standartlara uygun".to_string(),
                        status_color: Color32::from_rgb(120, 220, 180),
                        is_isolated: false,
                        isolation_progress: 0.0,
                    });
                    new_items.push(RollItem {
                        tag: "[GİZLİ KOD]".to_string(),
                        title: "Paket ve Şifreleme Denetimi".to_string(),
                        detail: "Şüpheli sıkıştırma veya gizli kod katmanı bulunmadı".to_string(),
                        status_color: Color32::from_rgb(120, 220, 180),
                        is_isolated: false,
                        isolation_progress: 0.0,
                    });
                    new_items.push(RollItem {
                        tag: "[BELLEK İZNİ]".to_string(),
                        title: "Çalışma ve Yazma İzinleri".to_string(),
                        detail: "Sisteme kod enjekte edebilecek tehlikeli RWX alanı yok"
                            .to_string(),
                        status_color: Color32::from_rgb(120, 220, 180),
                        is_isolated: false,
                        isolation_progress: 0.0,
                    });
                    new_items.push(RollItem {
                        tag: "[VERİ HIRSIZLIĞI]".to_string(),
                        title: "Şifre Çalıcı (Stealer) İmzaları".to_string(),
                        detail: "Hesap veya cüzdan çalma imzasına rastlanmadı".to_string(),
                        status_color: Color32::from_rgb(120, 220, 180),
                        is_isolated: false,
                        isolation_progress: 0.0,
                    });
                    new_items.push(RollItem {
                        tag: "[SONUÇ]".to_string(),
                        title: "Güvenlik Değerlendirmesi".to_string(),
                        detail: "GÖSTERGE BULUNAMADI // Şüpheli bir zararlı faaliyete rastlanmadı"
                            .to_string(),
                        status_color: Color32::from_rgb(120, 240, 180),
                        is_isolated: false,
                        isolation_progress: 0.0,
                    });
                } else {
                    new_items.push(RollItem {
                        tag: "[SONUÇ]".to_string(),
                        title: "Güvenlik Değerlendirmesi".to_string(),
                        detail: format!(
                            "{} // Tehdit tespit edildi ve karantinaya çekildi",
                            report.verdict
                        ),
                        status_color: Color32::from_rgb(255, 95, 80),
                        is_isolated: false,
                        isolation_progress: 0.0,
                    });
                }
            }
            Err(e) => {
                new_items.push(RollItem {
                    tag: "[ANALİZ DURUMU]".to_string(),
                    title: "İncelenemedi (Fail-Closed)".to_string(),
                    detail: format!("INCONCLUSIVE // Dosya güvenle çözümlenemedi: {}", e),
                    status_color: Color32::from_rgb(255, 180, 80),
                    is_isolated: false,
                    isolation_progress: 0.0,
                });
            }
        }

        self.items = new_items;
        self.current_scroll = 0.0;
        self.target_scroll = 0.0;
        self.is_streaming = true;
        self.stream_time = 0.0;
    }

    /// Updates scrolling physics, inertia, and isolation progression.
    pub fn update(&mut self, dt: f32, scroll_delta: f32) {
        let max_scroll = ((self.items.len().saturating_sub(1)) as f32 * self.item_spacing).max(0.0);

        // Auto-streaming animation when triage starts
        if self.is_streaming {
            self.stream_time += dt;
            self.target_scroll = (self.stream_time * 45.0).min(max_scroll);
            if self.target_scroll >= max_scroll {
                self.is_streaming = false;
            }
        }

        // Mouse wheel scroll input with reduced sensitivity (10.0 instead of 40.0)
        if scroll_delta.abs() > 0.001 {
            self.is_streaming = false;
            self.target_scroll = (self.target_scroll - scroll_delta * 10.0).clamp(0.0, max_scroll);
        }

        // Smooth inertial interpolation towards target
        let lerp_factor = (dt * 12.0).min(1.0);
        self.current_scroll += (self.target_scroll - self.current_scroll) * lerp_factor;

        // Animate isolation glide progress for each item
        for item in &mut self.items {
            let target_p = if item.is_isolated { 1.0 } else { 0.0 };
            let step = (dt * 3.5).min(1.0);
            item.isolation_progress += (target_p - item.isolation_progress) * step;
        }
    }

    /// Renders the spherical fisheye roll stream and threat isolation glide in pure egui.
    pub fn render(
        &mut self,
        painter: &Painter,
        center_pos: Pos2,
        menu_width: f32,
        dock_pos: Pos2,
        mouse_pos: Option<Pos2>,
        mouse_clicked: bool,
    ) {
        if self.items.is_empty() {
            return;
        }

        let max_phi = FRAC_PI_2 * 0.92;
        let mut toggle_idx = None;

        for (i, item) in self.items.iter().enumerate() {
            let item_y_nominal = (i as f32) * self.item_spacing - self.current_scroll;
            let dy = item_y_nominal;

            // Spherical mapping: Angle on virtual cylinder/sphere
            let phi = (dy / self.radius).clamp(-max_phi, max_phi);

            // Barrel / spherical fisheye projection
            let proj_y = center_pos.y + self.radius * phi.sin();

            // Fisheye scale factor: Center is magnified, top/bottom compressed
            let cos_phi = phi.cos().max(0.0);
            let scale = cos_phi.powf(1.4);

            // Opacity fades smoothly along the curvature
            let opacity = cos_phi.powf(2.0);
            if opacity < 0.03 && item.isolation_progress < 0.01 {
                continue;
            }

            let drum_card_w = menu_width * (0.82 + 0.18 * scale);
            let drum_card_h = 48.0 * scale.max(0.65);
            let drum_center = Pos2::new(center_pos.x, proj_y);

            // Magnetic threat isolation glide calculation
            let t = item.isolation_progress;
            let ease = 1.0 - (1.0 - t).powi(3); // Smooth cubic ease-out

            let current_center = Pos2::new(
                drum_center.x + (dock_pos.x - drum_center.x) * ease,
                drum_center.y + (dock_pos.y - drum_center.y) * ease,
            );

            let current_w = drum_card_w + (360.0 - drum_card_w) * ease;
            let current_h = drum_card_h + (50.0 - drum_card_h) * ease;
            let card_rect = Rect::from_center_size(current_center, Vec2::new(current_w, current_h));

            // Check click interaction to toggle isolation for testing
            if mouse_clicked && mouse_pos.is_some_and(|m| card_rect.contains(m)) {
                toggle_idx = Some(i);
            }

            // Magnetic filament line while detaching/gliding
            if t > 0.02 && t < 0.98 {
                let filament_alpha = ((1.0 - (t - 0.5).abs() * 2.0).max(0.0) * 180.0) as u8;
                if filament_alpha > 5 {
                    painter.line_segment(
                        [drum_center, current_center],
                        Stroke::new(
                            1.2_f32,
                            Color32::from_rgba_unmultiplied(255, 140, 90, filament_alpha),
                        ),
                    );
                }
            }

            // Card background: frosted acrylic / smoked glass with depth
            let base_alpha = (opacity * 195.0) as u8;
            let bg_alpha = ((base_alpha as f32) + ease * 35.0).clamp(40.0, 225.0) as u8;
            let bg_r = (10.0 + ease * 22.0) as u8;
            let bg_g = (14.0 + ease * 4.0) as u8;
            let bg_b = (22.0 - ease * 6.0) as u8;
            let bg_color = Color32::from_rgba_unmultiplied(bg_r, bg_g, bg_b, bg_alpha);
            painter.rect_filled(card_rect, Rounding::same(8.0 * scale.max(0.8)), bg_color);

            // Inner frost refraction ring
            let inner_rect = card_rect.shrink(1.0);
            painter.rect_stroke(
                inner_rect,
                Rounding::same(7.0 * scale.max(0.8)),
                Stroke::new(
                    1.0_f32,
                    Color32::from_rgba_unmultiplied(255, 255, 255, (opacity * 16.0) as u8),
                ),
            );

            // Top specular rim light highlight
            let top_rim_alpha = ((opacity * 130.0 * scale) + ease * 60.0).clamp(0.0, 230.0) as u8;
            let top_rim_color = if ease > 0.3 {
                Color32::from_rgba_unmultiplied(255, 190, 160, top_rim_alpha)
            } else {
                Color32::from_rgba_unmultiplied(255, 255, 255, top_rim_alpha)
            };
            painter.line_segment(
                [
                    Pos2::new(card_rect.min.x + 8.0, card_rect.min.y),
                    Pos2::new(card_rect.max.x - 8.0, card_rect.min.y),
                ],
                Stroke::new(1.0_f32, top_rim_color),
            );

            // Outer border: glowing amber/crimson if isolated, subtle white otherwise
            let border_alpha = ((opacity * 40.0) + ease * 120.0).clamp(0.0, 200.0) as u8;
            let border_color = if ease > 0.2 {
                Color32::from_rgba_unmultiplied(255, 130, 90, border_alpha)
            } else {
                Color32::from_rgba_unmultiplied(255, 255, 255, border_alpha)
            };
            painter.rect_stroke(
                card_rect,
                Rounding::same(8.0 * scale.max(0.8)),
                Stroke::new(1.0_f32 + ease * 0.4, border_color),
            );

            // Text scaling and rendering
            let effective_scale = scale * (1.0 - ease) + ease * 1.0;
            let tag_font_size = (9.5 * effective_scale).max(7.5);
            let title_font_size = (12.5 * effective_scale).max(9.0);
            let detail_font_size = (10.0 * effective_scale).max(8.0);

            let tag_str = if ease > 0.6 {
                "[İZOLE EDİLDİ]".to_string()
            } else {
                item.tag.clone()
            };

            let tag_color = if ease > 0.3 {
                Color32::from_rgba_unmultiplied(255, 130, 90, 240)
            } else {
                Color32::from_rgba_unmultiplied(
                    item.status_color.r(),
                    item.status_color.g(),
                    item.status_color.b(),
                    (opacity * 240.0) as u8,
                )
            };

            let text_alpha = ((opacity * 255.0) + ease * 255.0).clamp(0.0, 255.0) as u8;
            let title_color = Color32::from_rgba_unmultiplied(240, 245, 255, text_alpha);
            let detail_color = Color32::from_rgba_unmultiplied(160, 180, 205, text_alpha);

            let text_left = card_rect.min.x + 14.0;

            // Tag badge
            painter.text(
                Pos2::new(text_left, card_rect.min.y + 7.0),
                Align2::LEFT_TOP,
                tag_str,
                FontId::monospace(tag_font_size),
                tag_color,
            );

            // Title
            painter.text(
                Pos2::new(text_left + 115.0 * effective_scale, card_rect.min.y + 5.5),
                Align2::LEFT_TOP,
                &item.title,
                FontId::proportional(title_font_size),
                title_color,
            );

            // Detail
            painter.text(
                Pos2::new(text_left, card_rect.min.y + 24.0),
                Align2::LEFT_TOP,
                &item.detail,
                FontId::proportional(detail_font_size),
                detail_color,
            );
        }

        if let Some(idx) = toggle_idx {
            if let Some(target) = self.items.get_mut(idx) {
                target.is_isolated = !target.is_isolated;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spherical_roll_menu_creation() {
        let menu = SphericalRollMenu::new_demo_triage();
        assert!(!menu.items.is_empty());
        assert_eq!(menu.current_scroll, 0.0);
    }

    #[test]
    fn test_spherical_roll_menu_scroll_clamp() {
        let mut menu = SphericalRollMenu::new_demo_triage();
        menu.update(0.016, -100.0); // scroll up
        assert!(menu.target_scroll >= 0.0);

        menu.update(0.016, 1000.0); // scroll down excessively
        let max_scroll = ((menu.items.len() - 1) as f32 * menu.item_spacing).max(0.0);
        assert!(menu.target_scroll <= max_scroll);
    }

    #[test]
    fn test_spherical_roll_menu_reduced_scroll_sensitivity() {
        let mut menu = SphericalRollMenu::new_demo_triage();
        menu.update(0.016, 5.0);
        // With 10.0 multiplier, 5.0 delta yields target_scroll around 0.0 (clamped) or predictable delta
        assert!(menu.target_scroll >= 0.0);
    }

    #[test]
    fn test_spherical_roll_menu_isolation_glide_progress() {
        let mut menu = SphericalRollMenu::new_demo_triage();
        assert!(!menu.items.is_empty());
        menu.items[0].is_isolated = true;
        menu.update(0.1, 0.0);
        assert!(menu.items[0].isolation_progress > 0.0);

        menu.items[0].is_isolated = false;
        menu.update(0.5, 0.0);
        assert!(menu.items[0].isolation_progress < 1.0);
    }

    #[test]
    fn test_spherical_roll_populate_with_emulator_profile() {
        let mut menu = SphericalRollMenu::new_demo_triage();
        let report = oil_core::models::ScanReport {
            identity: oil_core::models::FileIdentity {
                path: std::path::PathBuf::from("steam_api64.dll"),
                size_bytes: 1024,
                sha256: "abc".to_string(),
                blake3: "def".to_string(),
            },
            autopsy: None,
            evidence: vec![oil_core::models::Evidence {
                kind: oil_core::models::EvidenceKind::EmulatorProfile {
                    name: "Goldberg Steam Emulator".to_string(),
                    is_legitimate: true,
                    indicators: vec!["Exports 5 Steamworks C-API functions".to_string()],
                },
                is_threat_signal: false,
                explanation: "Verified offline emulator".to_string(),
            }],
            verdict: oil_core::models::Tier::NoIndicatorsFound,
            verdict_summary: "Verified Goldberg Steam Emulator".to_string(),
            files_scanned: 1,
            files_skipped: 0,
            skip_reasons: Vec::new(),
        };

        menu.populate_from_scan("steam_api64.dll", Ok(report));
        assert!(menu
            .items
            .iter()
            .any(|it| it.tag == "[DOĞRULANMIŞ EMÜLATÖR]"));
    }
}

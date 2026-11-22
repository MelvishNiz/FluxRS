//! FluxRS design system: palette, typography, icons and reusable widgets.

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Frame, Margin,
    Response, RichText, Sense, Stroke, Ui, Vec2,
};
use std::sync::Arc;

// ---------------------------------------------------------------- palette

pub const BG: Color32 = Color32::from_rgb(0x0A, 0x0C, 0x10);
pub const SIDEBAR: Color32 = Color32::from_rgb(0x0E, 0x11, 0x17);
pub const SURFACE: Color32 = Color32::from_rgb(0x12, 0x16, 0x1E);
pub const RAISED: Color32 = Color32::from_rgb(0x19, 0x1E, 0x29);
pub const HOVER: Color32 = Color32::from_rgb(0x20, 0x26, 0x33);
pub const BORDER: Color32 = Color32::from_rgb(0x1F, 0x25, 0x31);
pub const BORDER_STRONG: Color32 = Color32::from_rgb(0x2B, 0x32, 0x41);
pub const TEXT: Color32 = Color32::from_rgb(0xE8, 0xEB, 0xF2);
pub const TEXT_DIM: Color32 = Color32::from_rgb(0x9A, 0xA3, 0xB5);
pub const TEXT_FAINT: Color32 = Color32::from_rgb(0x60, 0x68, 0x7B);
pub const ACCENT: Color32 = Color32::from_rgb(0x7C, 0x6C, 0xFF);
pub const ACCENT_HI: Color32 = Color32::from_rgb(0x9D, 0x91, 0xFF);
pub const ACCENT_SOFT: Color32 = Color32::from_rgb(0x22, 0x1F, 0x45);
pub const CYAN: Color32 = Color32::from_rgb(0x22, 0xD3, 0xEE);
pub const GREEN: Color32 = Color32::from_rgb(0x34, 0xD3, 0x99);
pub const YELLOW: Color32 = Color32::from_rgb(0xFB, 0xBF, 0x24);
pub const ORANGE: Color32 = Color32::from_rgb(0xFB, 0x92, 0x3C);
pub const RED: Color32 = Color32::from_rgb(0xF8, 0x71, 0x71);
pub const BLUE: Color32 = Color32::from_rgb(0x60, 0xA5, 0xFA);
pub const PINK: Color32 = Color32::from_rgb(0xF4, 0x72, 0xB6);
pub const CODE_BG: Color32 = Color32::from_rgb(0x0C, 0x0F, 0x14);

// ---------------------------------------------------------------- icons

/// Lucide icon code points (font subset in assets/fonts/lucide-icons.ttf).
pub mod icon {
    pub const ACTIVITY: &str = "\u{E038}";
    pub const PAUSE: &str = "\u{E12E}";
    pub const WAND: &str = "\u{E357}";
    pub const SETTINGS: &str = "\u{E154}";
    pub const SCROLL: &str = "\u{E45F}";
    pub const PLAY: &str = "\u{E13C}";
    pub const SQUARE: &str = "\u{E167}";
    pub const TRASH: &str = "\u{E18E}";
    pub const SEARCH: &str = "\u{E151}";
    pub const COPY: &str = "\u{E09E}";
    pub const SHIELD_CHECK: &str = "\u{E1FF}";
    pub const SHIELD_ALERT: &str = "\u{E1FE}";
    pub const LOCK: &str = "\u{E10B}";
    pub const X: &str = "\u{E1B2}";
    pub const PLUS: &str = "\u{E13D}";
    pub const CHEVRON_DOWN: &str = "\u{E06D}";
    pub const CHEVRON_UP: &str = "\u{E070}";
    pub const ZAP: &str = "\u{E1B4}";
    pub const GLOBE: &str = "\u{E0E8}";
    pub const CIRCLE_ALERT: &str = "\u{E077}";
    pub const CHECK: &str = "\u{E06C}";
    pub const ROTATE_CCW: &str = "\u{E148}";
    pub const SEND: &str = "\u{E152}";
    pub const BAN: &str = "\u{E051}";
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub const FOLDER_OPEN: &str = "\u{E247}";
    pub const TERMINAL: &str = "\u{E181}";
    pub const LIST_PLUS: &str = "\u{E23F}";
    pub const COPY_PLUS: &str = "\u{E3FD}";
    pub const CLOCK: &str = "\u{E087}";
    pub const GAUGE: &str = "\u{E1BF}";
    pub const DOWNLOAD: &str = "\u{E0B2}";
    pub const NETWORK: &str = "\u{E125}";
    pub const ARROW_LEFT_RIGHT: &str = "\u{E417}";
    pub const SERVER: &str = "\u{E153}";
    pub const MONITOR: &str = "\u{E11D}";
    pub const KEY: &str = "\u{E4A3}";
    pub const INFO: &str = "\u{E0F9}";
    pub const REFRESH: &str = "\u{E145}";
}

// ---------------------------------------------------------------- fonts

pub fn semibold_family() -> FontFamily {
    FontFamily::Name("semibold".into())
}

pub fn icon_family() -> FontFamily {
    FontFamily::Name("icons".into())
}

pub fn sb(size: f32) -> FontId {
    FontId::new(size, semibold_family())
}

pub fn mono(size: f32) -> FontId {
    FontId::new(size, FontFamily::Monospace)
}

/// Semibold text.
pub fn strong(text: impl Into<String>, size: f32, color: Color32) -> RichText {
    RichText::new(text).font(sb(size)).color(color)
}

/// Icon glyph.
pub fn ico(icon: &str, size: f32, color: Color32) -> RichText {
    RichText::new(icon)
        .family(icon_family())
        .size(size)
        .color(color)
}

fn install_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    let fallbacks: Vec<String> = fonts
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    fonts.font_data.insert(
        "inter".into(),
        Arc::new(FontData::from_static(include_bytes!(
            "../assets/fonts/Inter-Regular.ttf"
        ))),
    );
    fonts.font_data.insert(
        "inter-semibold".into(),
        Arc::new(FontData::from_static(include_bytes!(
            "../assets/fonts/Inter-SemiBold.ttf"
        ))),
    );
    fonts.font_data.insert(
        "jetbrains-mono".into(),
        Arc::new(FontData::from_static(include_bytes!(
            "../assets/fonts/JetBrainsMono-Regular.ttf"
        ))),
    );
    fonts.font_data.insert(
        "lucide".into(),
        Arc::new(
            FontData::from_static(include_bytes!("../assets/fonts/lucide-icons.ttf")).tweak(
                egui::FontTweak {
                    y_offset_factor: 0.07,
                    ..Default::default()
                },
            ),
        ),
    );
    if let Some(p) = fonts.families.get_mut(&FontFamily::Proportional) {
        p.insert(0, "inter".into());
    }
    if let Some(m) = fonts.families.get_mut(&FontFamily::Monospace) {
        m.insert(0, "jetbrains-mono".into());
    }
    let mut semibold = vec!["inter-semibold".to_string()];
    semibold.extend(fallbacks.iter().cloned());
    fonts.families.insert(semibold_family(), semibold);
    fonts.families.insert(icon_family(), vec!["lucide".into()]);
    ctx.set_fonts(fonts);
}

pub fn apply(ctx: &egui::Context) {
    install_fonts(ctx);
    ctx.set_theme(egui::Theme::Dark);
    ctx.style_mut_of(egui::Theme::Dark, |style| {
        let v = &mut style.visuals;
        v.dark_mode = true;
        v.override_text_color = Some(TEXT);
        v.panel_fill = BG;
        v.window_fill = SURFACE;
        v.window_stroke = Stroke::new(1.0, BORDER_STRONG);
        v.window_corner_radius = CornerRadius::from(12u8);
        v.menu_corner_radius = CornerRadius::from(10u8);
        v.extreme_bg_color = CODE_BG;
        v.faint_bg_color = Color32::from_rgb(0x15, 0x19, 0x22);
        v.code_bg_color = CODE_BG;
        v.hyperlink_color = ACCENT_HI;
        v.warn_fg_color = YELLOW;
        v.error_fg_color = RED;
        v.selection.bg_fill = Color32::from_rgb(0x2C, 0x27, 0x5E);
        v.selection.stroke = Stroke::new(1.0, ACCENT_HI);
        v.striped = false;

        let r = CornerRadius::from(7u8);
        let w = &mut v.widgets;
        w.noninteractive.bg_fill = SURFACE;
        w.noninteractive.weak_bg_fill = SURFACE;
        w.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
        w.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_DIM);
        w.noninteractive.corner_radius = r;

        w.inactive.bg_fill = RAISED;
        w.inactive.weak_bg_fill = RAISED;
        w.inactive.bg_stroke = Stroke::new(1.0, BORDER_STRONG);
        w.inactive.fg_stroke = Stroke::new(1.0, TEXT);
        w.inactive.corner_radius = r;

        w.hovered.bg_fill = HOVER;
        w.hovered.weak_bg_fill = HOVER;
        w.hovered.bg_stroke = Stroke::new(1.0, Color32::from_rgb(0x3A, 0x42, 0x55));
        w.hovered.fg_stroke = Stroke::new(1.5, TEXT);
        w.hovered.corner_radius = r;
        w.hovered.expansion = 0.0;

        w.active.bg_fill = ACCENT_SOFT;
        w.active.weak_bg_fill = ACCENT_SOFT;
        w.active.bg_stroke = Stroke::new(1.0, ACCENT);
        w.active.fg_stroke = Stroke::new(1.5, TEXT);
        w.active.corner_radius = r;
        w.active.expansion = 0.0;

        w.open = w.active;

        let s = &mut style.spacing;
        s.item_spacing = Vec2::new(8.0, 6.0);
        s.button_padding = Vec2::new(10.0, 5.0);
        s.interact_size.y = 28.0;
        s.window_margin = Margin::same(14);
        s.menu_margin = Margin::same(6);
        s.combo_width = 130.0;
        s.scroll.bar_width = 8.0;
        s.scroll.floating = true;

        use egui::TextStyle as T;
        style
            .text_styles
            .insert(T::Body, FontId::new(13.0, FontFamily::Proportional));
        style
            .text_styles
            .insert(T::Button, FontId::new(13.0, FontFamily::Proportional));
        style
            .text_styles
            .insert(T::Monospace, FontId::new(12.5, FontFamily::Monospace));
        style.text_styles.insert(T::Heading, sb(18.0));
        style
            .text_styles
            .insert(T::Small, FontId::new(11.0, FontFamily::Proportional));
    });
}

// ---------------------------------------------------------------- containers

pub fn card() -> Frame {
    Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::from(12u8))
        .inner_margin(Margin::same(16))
}

/// Inset area (code, nested blocks).
pub fn inset() -> Frame {
    Frame::new()
        .fill(CODE_BG)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::from(9u8))
        .inner_margin(Margin::same(10))
}

/// Small uppercase caption.
pub fn caption(ui: &mut Ui, text: &str) {
    ui.label(strong(text.to_uppercase(), 10.5, TEXT_FAINT));
}

// ---------------------------------------------------------------- buttons

/// Filled primary button with icon.
pub fn primary_button(ui: &mut Ui, icon: &str, text: &str, color: Color32) -> Response {
    let fg = BG;
    ui.add(
        egui::Button::new((ico(icon, 14.0, fg), strong(text, 13.0, fg)))
            .fill(color)
            .stroke(Stroke::NONE)
            .corner_radius(CornerRadius::from(8u8))
            .min_size(Vec2::new(0.0, 32.0)),
    )
}

/// Subtle outlined button with icon + label.
pub fn ghost_button(ui: &mut Ui, icon: &str, text: &str) -> Response {
    ui.add(
        egui::Button::new((ico(icon, 14.0, TEXT_DIM), RichText::new(text).color(TEXT)))
            .fill(Color32::TRANSPARENT)
            .stroke(Stroke::new(1.0, BORDER_STRONG))
            .corner_radius(CornerRadius::from(7u8)),
    )
}

/// Square icon-only button with tooltip.
pub fn icon_button(ui: &mut Ui, icon: &str, tooltip: &str) -> Response {
    ui.add(
        egui::Button::new(ico(icon, 14.0, TEXT_DIM))
            .fill(Color32::TRANSPARENT)
            .stroke(Stroke::NONE)
            .corner_radius(CornerRadius::from(6u8))
            .min_size(Vec2::new(26.0, 26.0)),
    )
    .on_hover_text(tooltip)
}

/// Segmented control. Returns true when changed.
pub fn segmented<T: PartialEq + Copy>(
    ui: &mut Ui,
    value: &mut T,
    items: &[(T, Option<&str>, &str)],
) -> bool {
    let mut changed = false;
    Frame::new()
        .fill(CODE_BG)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::from(9u8))
        .inner_margin(Margin::same(3))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                for (v, icon, label) in items {
                    let selected = *value == *v;
                    let color = if selected { TEXT } else { TEXT_DIM };
                    let text = if selected {
                        strong(*label, 12.5, color)
                    } else {
                        RichText::new(*label).size(12.5).color(color)
                    };
                    let mut button = match icon {
                        Some(i) => egui::Button::new((ico(i, 13.0, color), text)),
                        None => egui::Button::new(text),
                    };
                    button = button
                        .fill(if selected {
                            RAISED
                        } else {
                            Color32::TRANSPARENT
                        })
                        .stroke(if selected {
                            Stroke::new(1.0, BORDER_STRONG)
                        } else {
                            Stroke::NONE
                        })
                        .corner_radius(CornerRadius::from(7u8))
                        .min_size(Vec2::new(0.0, 24.0));
                    if ui.add(button).clicked() && !selected {
                        *value = *v;
                        changed = true;
                    }
                }
            });
        });
    changed
}

/// Underlined tab bar.
pub fn tabs<T: PartialEq + Copy>(ui: &mut Ui, value: &mut T, items: &[(T, &str)]) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 20.0;
        for (v, label) in items {
            let selected = *value == *v;
            let text = if selected {
                strong(*label, 13.0, TEXT)
            } else {
                RichText::new(*label).size(13.0).color(TEXT_DIM)
            };
            let resp = ui.add(egui::Label::new(text).sense(Sense::click()));
            if resp.hovered() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            }
            if selected {
                let r = resp.rect;
                ui.painter().line_segment(
                    [
                        egui::pos2(r.left(), r.bottom() + 7.0),
                        egui::pos2(r.right(), r.bottom() + 7.0),
                    ],
                    Stroke::new(2.0, ACCENT),
                );
            }
            if resp.clicked() {
                *value = *v;
            }
        }
    });
    ui.add_space(6.0);
    let rect = ui.available_rect_before_wrap();
    ui.painter()
        .hline(rect.x_range(), rect.top(), Stroke::new(1.0, BORDER));
    ui.add_space(10.0);
}

/// iOS like switch.
pub fn toggle(ui: &mut Ui, on: &mut bool) -> Response {
    let size = Vec2::new(34.0, 19.0);
    let (rect, mut resp) = ui.allocate_exact_size(size, Sense::click());
    if resp.clicked() {
        *on = !*on;
        resp.mark_changed();
    }
    let t = ui.ctx().animate_bool_responsive(resp.id, *on);
    let bg = if *on { ACCENT } else { RAISED };
    let painter = ui.painter();
    painter.rect(
        rect,
        CornerRadius::from(10u8),
        bg,
        Stroke::new(1.0, if *on { ACCENT } else { BORDER_STRONG }),
        egui::StrokeKind::Inside,
    );
    let x = egui::lerp(rect.left() + 9.5..=rect.right() - 9.5, t);
    painter.circle_filled(egui::pos2(x, rect.center().y), 6.5, Color32::WHITE);
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

// ---------------------------------------------------------------- badges

/// Rounded tinted label.
pub fn pill(ui: &mut Ui, text: impl Into<String>, color: Color32) -> Response {
    Frame::new()
        .fill(color.gamma_multiply(0.14))
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.35)))
        .corner_radius(CornerRadius::from(6u8))
        .inner_margin(Margin::symmetric(7, 1))
        .show(ui, |ui| {
            ui.label(strong(text, 11.0, color));
        })
        .response
}

/// Counter badge (painted, keeps its size in any layout).
pub fn badge(ui: &mut Ui, n: usize, color: Color32) {
    if n == 0 {
        return;
    }
    let galley = ui
        .painter()
        .layout_no_wrap(n.to_string(), sb(10.5), Color32::BLACK);
    let size = Vec2::new((galley.size().x + 10.0).max(18.0), 17.0);
    let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
    ui.painter()
        .rect_filled(rect, CornerRadius::from(9u8), color);
    let pos = rect.center() - galley.size() / 2.0;
    ui.painter().galley(pos, galley, Color32::BLACK);
}

/// Pulsing "live" dot.
pub fn live_dot(ui: &mut Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(12.0), Sense::hover());
    let t = ui.input(|i| i.time);
    let pulse = ((t * 2.5).sin() * 0.5 + 0.5) as f32;
    ui.painter()
        .circle_filled(rect.center(), 3.5 + pulse * 2.5, color.gamma_multiply(0.25));
    ui.painter().circle_filled(rect.center(), 3.5, color);
    ui.ctx()
        .request_repaint_after(std::time::Duration::from_millis(60));
}

pub fn dot(ui: &mut Ui, color: Color32, r: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(r * 2.0 + 2.0), Sense::hover());
    ui.painter().circle_filled(rect.center(), r, color);
}

pub fn method_color(method: &str) -> Color32 {
    match method {
        "GET" => GREEN,
        "POST" => BLUE,
        "PUT" => ORANGE,
        "PATCH" => YELLOW,
        "DELETE" => RED,
        "OPTIONS" | "HEAD" => TEXT_DIM,
        "TUNNEL" | "CONNECT" => TEXT_FAINT,
        _ => PINK,
    }
}

pub fn status_color(status: u16) -> Color32 {
    match status {
        100..=199 => CYAN,
        200..=299 => GREEN,
        300..=399 => BLUE,
        400..=499 => ORANGE,
        _ => RED,
    }
}

/// Banner with icon, message and optional action. Returns true when the
/// action is clicked.
pub fn banner(ui: &mut Ui, color: Color32, icon: &str, text: &str, action: Option<&str>) -> bool {
    let mut clicked = false;
    Frame::new()
        .fill(color.gamma_multiply(0.08))
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.35)))
        .corner_radius(CornerRadius::from(10u8))
        .inner_margin(Margin::symmetric(14, 8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(ico(icon, 16.0, color));
                ui.label(RichText::new(text).color(TEXT));
                if let Some(a) = action {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        clicked = primary_button(ui, icon::SHIELD_CHECK, a, color).clicked();
                    });
                }
            });
        });
    clicked
}

/// KPI tile.
pub fn stat_tile(ui: &mut Ui, icon: &str, label: &str, value: &str, hint: &str, color: Color32) {
    card()
        .inner_margin(Margin::symmetric(14, 12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                Frame::new()
                    .fill(color.gamma_multiply(0.13))
                    .corner_radius(CornerRadius::from(8u8))
                    .inner_margin(Margin::same(8))
                    .show(ui, |ui| {
                        ui.label(ico(icon, 16.0, color));
                    });
                ui.add_space(4.0);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.label(RichText::new(label).size(11.5).color(TEXT_DIM));
                    ui.horizontal(|ui| {
                        ui.label(strong(value, 18.0, TEXT));
                        if !hint.is_empty() {
                            ui.label(RichText::new(hint).size(11.0).color(TEXT_FAINT));
                        }
                    });
                });
            });
        });
}

// ---------------------------------------------------------------- misc

pub fn human_bytes(n: usize) -> String {
    const K: f64 = 1024.0;
    let n = n as f64;
    if n < K {
        format!("{n} B")
    } else if n < K * K {
        format!("{:.1} KB", n / K)
    } else if n < K * K * K {
        format!("{:.1} MB", n / K / K)
    } else {
        format!("{:.2} GB", n / K / K / K)
    }
}

pub fn human_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms} ms")
    } else {
        format!("{:.2} s", ms as f64 / 1000.0)
    }
}

/// App logo.
pub fn logo(ui: &mut Ui, size: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let p = ui.painter();
    let r = CornerRadius::from((size * 0.27) as u8);
    p.rect_filled(rect, r, ACCENT);
    // soft highlight on the upper half for depth
    let top = egui::Rect::from_min_max(rect.min, egui::pos2(rect.max.x, rect.center().y));
    p.rect_filled(
        top,
        CornerRadius {
            nw: r.nw,
            ne: r.ne,
            sw: 0,
            se: 0,
        },
        Color32::from_white_alpha(20),
    );
    let galley = p.layout_no_wrap(
        icon::ARROW_LEFT_RIGHT.to_string(),
        FontId::new(size * 0.56, icon_family()),
        Color32::WHITE,
    );
    p.galley(rect.center() - galley.size() / 2.0, galley, Color32::WHITE);
}

/// Window icon (RGBA) rendered procedurally.
#[cfg(not(target_arch = "wasm32"))]
pub fn window_icon() -> egui::IconData {
    let n = 64usize;
    let mut rgba = vec![0u8; n * n * 4];
    let r = 16.0f32;
    for y in 0..n {
        for x in 0..n {
            let fx = x as f32 + 0.5;
            let fy = y as f32 + 0.5;
            let dx = (fx - n as f32 / 2.0).abs() - (n as f32 / 2.0 - r);
            let dy = (fy - n as f32 / 2.0).abs() - (n as f32 / 2.0 - r);
            let d = (dx.max(0.0).powi(2) + dy.max(0.0).powi(2)).sqrt();
            if d > r {
                continue;
            }
            let i = (y * n + x) * 4;
            let t = fy / n as f32;
            rgba[i] = (0x9D as f32 * (1.0 - t) + 0x6C as f32 * t) as u8;
            rgba[i + 1] = (0x91 as f32 * (1.0 - t) + 0x5C as f32 * t) as u8;
            rgba[i + 2] = 0xFF;
            rgba[i + 3] = 255;
            let on_line = |y0: f32| (fy - y0).abs() < 2.6 && (18.0..46.0).contains(&fx);
            if on_line(25.0) || on_line(39.0) {
                rgba[i] = 255;
                rgba[i + 1] = 255;
                rgba[i + 2] = 255;
            }
        }
    }
    egui::IconData {
        rgba,
        width: n as u32,
        height: n as u32,
    }
}

//! Dark theme, palette and small reusable widgets.

use eframe::egui::{
    self, Color32, CornerRadius, FontId, Frame, Margin, RichText, Sense, Stroke, Ui, Vec2,
};

pub const BG: Color32 = Color32::from_rgb(0x0B, 0x0D, 0x12);
pub const PANEL: Color32 = Color32::from_rgb(0x10, 0x13, 0x1A);
pub const SURFACE: Color32 = Color32::from_rgb(0x16, 0x1A, 0x23);
pub const SURFACE_HI: Color32 = Color32::from_rgb(0x1E, 0x23, 0x2F);
pub const BORDER: Color32 = Color32::from_rgb(0x25, 0x2B, 0x38);
pub const TEXT: Color32 = Color32::from_rgb(0xE6, 0xE9, 0xF0);
pub const TEXT_DIM: Color32 = Color32::from_rgb(0x8A, 0x93, 0xA8);
pub const TEXT_FAINT: Color32 = Color32::from_rgb(0x5C, 0x64, 0x78);
pub const ACCENT: Color32 = Color32::from_rgb(0x7C, 0x6C, 0xFF);
pub const ACCENT_SOFT: Color32 = Color32::from_rgb(0x2A, 0x25, 0x52);
pub const CYAN: Color32 = Color32::from_rgb(0x22, 0xD3, 0xEE);
pub const GREEN: Color32 = Color32::from_rgb(0x34, 0xD3, 0x99);
pub const YELLOW: Color32 = Color32::from_rgb(0xFB, 0xBF, 0x24);
pub const ORANGE: Color32 = Color32::from_rgb(0xFB, 0x92, 0x3C);
pub const RED: Color32 = Color32::from_rgb(0xF8, 0x71, 0x71);
pub const BLUE: Color32 = Color32::from_rgb(0x60, 0xA5, 0xFA);
pub const PINK: Color32 = Color32::from_rgb(0xF4, 0x72, 0xB6);

pub fn apply(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Dark);
    ctx.style_mut_of(egui::Theme::Dark, |style| {
        let v = &mut style.visuals;
        v.dark_mode = true;
        v.override_text_color = Some(TEXT);
        v.panel_fill = PANEL;
        v.window_fill = SURFACE;
        v.window_stroke = Stroke::new(1.0, BORDER);
        v.window_corner_radius = CornerRadius::from(12u8);
        v.menu_corner_radius = CornerRadius::from(10u8);
        v.extreme_bg_color = BG;
        v.faint_bg_color = Color32::from_rgb(0x13, 0x17, 0x1F);
        v.code_bg_color = BG;
        v.hyperlink_color = ACCENT;
        v.warn_fg_color = YELLOW;
        v.error_fg_color = RED;
        v.selection.bg_fill = ACCENT_SOFT;
        v.selection.stroke = Stroke::new(1.0, ACCENT);
        v.striped = true;

        let r = CornerRadius::from(8u8);
        let w = &mut v.widgets;
        w.noninteractive.bg_fill = SURFACE;
        w.noninteractive.weak_bg_fill = SURFACE;
        w.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
        w.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_DIM);
        w.noninteractive.corner_radius = r;

        w.inactive.bg_fill = SURFACE_HI;
        w.inactive.weak_bg_fill = SURFACE_HI;
        w.inactive.bg_stroke = Stroke::new(1.0, BORDER);
        w.inactive.fg_stroke = Stroke::new(1.0, TEXT);
        w.inactive.corner_radius = r;

        w.hovered.bg_fill = Color32::from_rgb(0x2A, 0x30, 0x3F);
        w.hovered.weak_bg_fill = Color32::from_rgb(0x2A, 0x30, 0x3F);
        w.hovered.bg_stroke = Stroke::new(1.0, Color32::from_rgb(0x3A, 0x42, 0x55));
        w.hovered.fg_stroke = Stroke::new(1.5, TEXT);
        w.hovered.corner_radius = r;

        w.active.bg_fill = ACCENT_SOFT;
        w.active.weak_bg_fill = ACCENT_SOFT;
        w.active.bg_stroke = Stroke::new(1.0, ACCENT);
        w.active.fg_stroke = Stroke::new(2.0, TEXT);
        w.active.corner_radius = r;

        w.open = w.active;

        let s = &mut style.spacing;
        s.item_spacing = Vec2::new(8.0, 6.0);
        s.button_padding = Vec2::new(10.0, 5.0);
        s.interact_size.y = 26.0;
        s.window_margin = Margin::same(14);
        s.menu_margin = Margin::same(8);
        s.combo_width = 140.0;

        style.text_styles.insert(
            egui::TextStyle::Body,
            FontId::new(13.5, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Button,
            FontId::new(13.5, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Monospace,
            FontId::new(12.5, egui::FontFamily::Monospace),
        );
        style.text_styles.insert(
            egui::TextStyle::Heading,
            FontId::new(19.0, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Small,
            FontId::new(11.0, egui::FontFamily::Proportional),
        );
    });
}

pub fn card() -> Frame {
    Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::from(12u8))
        .inner_margin(Margin::same(14))
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

/// Rounded label with tinted background.
pub fn pill(ui: &mut Ui, text: impl Into<String>, color: Color32) -> egui::Response {
    let text = text.into();
    Frame::new()
        .fill(color.gamma_multiply(0.16))
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.45)))
        .corner_radius(CornerRadius::from(20u8))
        .inner_margin(Margin::symmetric(8, 2))
        .show(ui, |ui| {
            ui.label(RichText::new(text).color(color).size(11.5).strong());
        })
        .response
}

/// Small counter badge (painted, so it keeps its size in any layout).
pub fn badge(ui: &mut Ui, n: usize, color: Color32) {
    if n == 0 {
        return;
    }
    let galley = ui.painter().layout_no_wrap(
        n.to_string(),
        FontId::new(11.0, egui::FontFamily::Proportional),
        Color32::BLACK,
    );
    let size = Vec2::new((galley.size().x + 12.0).max(20.0), 18.0);
    let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
    ui.painter()
        .rect_filled(rect, CornerRadius::from(9u8), color);
    let pos = rect.center() - galley.size() / 2.0;
    ui.painter().galley(pos, galley, Color32::BLACK);
}

/// Primary (filled) button.
pub fn primary_button(ui: &mut Ui, text: &str, color: Color32) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(text).color(Color32::BLACK).strong())
            .fill(color)
            .corner_radius(CornerRadius::from(8u8))
            .min_size(Vec2::new(0.0, 30.0)),
    )
}

/// iOS like switch.
pub fn toggle(ui: &mut Ui, on: &mut bool) -> egui::Response {
    let size = Vec2::new(36.0, 20.0);
    let (rect, mut resp) = ui.allocate_exact_size(size, Sense::click());
    if resp.clicked() {
        *on = !*on;
        resp.mark_changed();
    }
    let t = ui.ctx().animate_bool_responsive(resp.id, *on);
    let bg = if *on { ACCENT } else { SURFACE_HI };
    let painter = ui.painter();
    painter.rect(
        rect,
        CornerRadius::from(10u8),
        bg,
        Stroke::new(1.0, if *on { ACCENT } else { BORDER }),
        egui::StrokeKind::Inside,
    );
    let x = egui::lerp(rect.left() + 10.0..=rect.right() - 10.0, t);
    painter.circle_filled(egui::pos2(x, rect.center().y), 7.0, TEXT);
    resp
}

pub fn section_title(ui: &mut Ui, title: &str, subtitle: &str) {
    ui.label(RichText::new(title).size(16.0).strong().color(TEXT));
    if !subtitle.is_empty() {
        ui.label(RichText::new(subtitle).size(12.0).color(TEXT_DIM));
    }
    ui.add_space(6.0);
}

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

/// App logo drawn with shapes (no image assets needed).
pub fn logo(ui: &mut Ui, size: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let p = ui.painter();
    p.rect_filled(rect, CornerRadius::from((size * 0.28) as u8), ACCENT);
    let c = rect.center();
    let s = size * 0.22;
    let stroke = Stroke::new(size * 0.09, Color32::WHITE);
    // stylised "flux" arrows
    p.line_segment(
        [
            egui::pos2(c.x - s, c.y - s * 0.5),
            egui::pos2(c.x + s, c.y - s * 0.5),
        ],
        stroke,
    );
    p.line_segment(
        [
            egui::pos2(c.x + s * 0.4, c.y - s),
            egui::pos2(c.x + s, c.y - s * 0.5),
        ],
        stroke,
    );
    p.line_segment(
        [
            egui::pos2(c.x + s, c.y + s * 0.5),
            egui::pos2(c.x - s, c.y + s * 0.5),
        ],
        stroke,
    );
    p.line_segment(
        [
            egui::pos2(c.x - s * 0.4, c.y + s),
            egui::pos2(c.x - s, c.y + s * 0.5),
        ],
        stroke,
    );
}

/// Window icon (RGBA) rendered procedurally.
pub fn window_icon() -> egui::IconData {
    let n = 64usize;
    let mut rgba = vec![0u8; n * n * 4];
    let r = 16.0f32;
    for y in 0..n {
        for x in 0..n {
            let fx = x as f32 + 0.5;
            let fy = y as f32 + 0.5;
            // rounded square mask
            let dx = (fx - n as f32 / 2.0).abs() - (n as f32 / 2.0 - r);
            let dy = (fy - n as f32 / 2.0).abs() - (n as f32 / 2.0 - r);
            let d = (dx.max(0.0).powi(2) + dy.max(0.0).powi(2)).sqrt();
            if d > r {
                continue;
            }
            let i = (y * n + x) * 4;
            let t = fy / n as f32;
            rgba[i] = (0x7C as f32 * (1.0 - t) + 0x22 as f32 * t) as u8;
            rgba[i + 1] = (0x6C as f32 * (1.0 - t) + 0xD3 as f32 * t * 0.6) as u8;
            rgba[i + 2] = 0xFF - (t * 0x11 as f32) as u8;
            rgba[i + 3] = 255;
            // white arrows
            let on_line = |y0: f32| (fy - y0).abs() < 3.0 && (18.0..46.0).contains(&fx);
            if on_line(24.0) || on_line(40.0) {
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

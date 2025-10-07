use eframe::egui;
use anyhow::Result;

mod wfp;
use wfp::{Engine, FilterSummary, WfpAction};

struct AppState {
    status: String,
    filters: Vec<FilterSummary>,
    refresh_pending: bool,
    // quick “add” inputs (extend as needed)
    add_name: String,
    add_tcp_port: u16,
    add_block: bool,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            status: "Ready".into(),
            filters: Vec::new(),
            refresh_pending: true,
            add_name: "My Filter".into(),
            add_tcp_port: 445,
            add_block: true,
        }
    }
}

impl eframe::App for AppState {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.heading("SLS WFP Manager");
            if ui.button("Refresh").clicked() {
                self.refresh_pending = true;
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            if self.refresh_pending {
                match Engine::open().and_then(|eng| eng.list_filters()) {
                    Ok(list) => { self.filters = list; self.status = format!("Loaded {} filters", self.filters.len()); }
                    Err(e) => { self.status = format!("Error: {e}"); }
                }
                self.refresh_pending = false;
            }

            ui.label(&self.status);
            ui.separator();

            egui::CollapsingHeader::new("Add quick TCP rule").default_open(true).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Name:");
                    ui.text_edit_singleline(&mut self.add_name);
                    ui.label("TCP Port:");
                    ui.add(egui::DragValue::new(&mut self.add_tcp_port).clamp_range(1..=65535));
                    ui.checkbox(&mut self.add_block, "Block (unchecked = Allow)");
                });
                if ui.button("Add Filter at ALE_AUTH_CONNECT_V4").clicked() {
                    let res = Engine::open().and_then(|eng| {
                        eng.add_simple_tcp_filter_v4(
                            &self.add_name,
                            self.add_tcp_port,
                            if self.add_block { WfpAction::Block } else { WfpAction::Permit },
                        )
                    });
                    self.status = match res {
                        Ok(_) => "Filter added.".into(),
                        Err(e) => format!("Add failed: {e}"),
                    };
                    self.refresh_pending = true;
                }
            });

            ui.separator();
            ui.label("Current WFP Filters (subset of fields):");
            egui::ScrollArea::vertical().show(ui, |ui| {
                egui::Grid::new("filters_grid").striped(true).show(ui, |ui| {
                    ui.heading("ID"); ui.heading("Name"); ui.heading("Layer"); ui.heading("Action"); ui.end_row();
                    for f in &self.filters {
                        ui.label(format!("{}", f.id));
                        ui.label(&f.name);
                        ui.label(&f.layer);
                        ui.label(match f.action { WfpAction::Permit => "Permit", WfpAction::Block => "Block", WfpAction::Callout => "Callout" });
                        ui.end_row();
                    }
                });
            });
        });
    }
}

fn main() -> Result<()> {
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "SLS WFP Manager",
        native_options,
        Box::new(|_| Box::<AppState>::default()),
    )?;
    Ok(())
}

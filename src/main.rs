use anyhow::Result;
use eframe::egui;
use windows::core::GUID;

mod wfp;
use wfp::{Engine, FilterConfig, FilterSummary, NamedGuid, Snapshot, WfpAction};

struct AppState {
    status: String,
    filters: Vec<FilterSummary>,
    providers: Vec<NamedGuid>,
    sublayers: Vec<NamedGuid>,
    layers: Vec<NamedGuid>,
    refresh_pending: bool,
    add_name: String,
    add_tcp_port: u16,
    add_block: bool,
    export_text: String,
    edit_state: Option<EditState>,
    delete_state: Option<DeleteState>,
}

struct EditState {
    id: u64,
    name: String,
    remote_port: u16,
    action: WfpAction,
}

struct DeleteState {
    id: u64,
    name: String,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            status: "Ready".into(),
            filters: Vec::new(),
            providers: Vec::new(),
            sublayers: Vec::new(),
            layers: Vec::new(),
            refresh_pending: true,
            add_name: "My Filter".into(),
            add_tcp_port: 445,
            add_block: true,
            export_text: String::new(),
            edit_state: None,
            delete_state: None,
        }
    }
}

impl eframe::App for AppState {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.heading("SLS WFP Manager");
            ui.horizontal(|ui| {
                if ui.button("Refresh").clicked() {
                    self.refresh_pending = true;
                }
                ui.label(&self.status);
            });
        });

        if self.refresh_pending {
            self.load_snapshot();
            self.refresh_pending = false;
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            self.render_add_section(ui);
            ui.separator();
            self.render_export_import(ui);
            ui.separator();
            self.render_filters(ui);
            ui.separator();
            self.render_metadata(ui);
        });

        self.render_edit_window(ctx);
        self.render_delete_window(ctx);
    }
}

impl AppState {
    fn load_snapshot(&mut self) {
        match Engine::open().and_then(|eng| eng.snapshot()) {
            Ok(snapshot) => {
                self.apply_snapshot(snapshot);
                self.status = format!("Loaded {} filters", self.filters.len());
            }
            Err(err) => {
                self.status = format!("Error loading filters: {err}");
            }
        }
    }

    fn apply_snapshot(&mut self, snapshot: Snapshot) {
        self.filters = snapshot.filters;
        self.providers = snapshot.providers;
        self.sublayers = snapshot.sublayers;
        self.layers = snapshot.layers;
    }

    fn render_add_section(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new("Add quick TCP rule")
            .default_open(true)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Name:");
                    ui.text_edit_singleline(&mut self.add_name);
                    ui.label("TCP Port:");
                    ui.add(egui::DragValue::new(&mut self.add_tcp_port).clamp_range(1..=65535));
                    ui.checkbox(&mut self.add_block, "Block (unchecked = Allow)");
                });
                if ui.button("Add Filter at ALE_AUTH_CONNECT_V4").clicked() {
                    let action = if self.add_block {
                        WfpAction::Block
                    } else {
                        WfpAction::Permit
                    };
                    let res = Engine::open().and_then(|eng| {
                        eng.add_simple_tcp_filter_v4(&self.add_name, self.add_tcp_port, action)
                    });
                    self.status = match res {
                        Ok(_) => "Filter added.".into(),
                        Err(e) => format!("Add failed: {e}"),
                    };
                    self.refresh_pending = true;
                }
            });
    }

    fn render_export_import(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new("Export / Import Owned Rules")
            .default_open(false)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    if ui.button("Export to JSON").clicked() {
                        self.status =
                            match Engine::open().and_then(|eng| eng.export_owned_filters()) {
                                Ok(json) => {
                                    self.export_text = json;
                                    "Exported owned filters.".into()
                                }
                                Err(err) => format!("Export failed: {err}"),
                            };
                    }
                    if ui.button("Import from JSON").clicked() {
                        let parsed: Result<Vec<FilterConfig>, _> =
                            serde_json::from_str(&self.export_text);
                        match parsed {
                            Ok(configs) => {
                                self.status = match Engine::open()
                                    .and_then(|eng| eng.import_filters(&configs))
                                {
                                    Ok(_) => {
                                        self.refresh_pending = true;
                                        "Import complete.".into()
                                    }
                                    Err(err) => format!("Import failed: {err}"),
                                };
                            }
                            Err(err) => {
                                self.status = format!("JSON parse error: {err}");
                            }
                        }
                    }
                });
                ui.add(
                    egui::TextEdit::multiline(&mut self.export_text)
                        .desired_rows(6)
                        .hint_text("JSON export area"),
                );
            });
    }

    fn render_filters(&mut self, ui: &mut egui::Ui) {
        ui.label("Current WFP Filters (subset of fields):");
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("filters_grid")
                .striped(true)
                .min_col_width(80.0)
                .show(ui, |ui| {
                    ui.heading("ID");
                    ui.heading("Name");
                    ui.heading("Provider");
                    ui.heading("Layer");
                    ui.heading("Action");
                    ui.heading("Remote Port");
                    ui.heading("Owned");
                    ui.heading("Actions");
                    ui.end_row();

                    for filter in &self.filters {
                        ui.label(filter.id.to_string());
                        ui.label(&filter.name);
                        ui.label(&filter.provider);
                        ui.label(&filter.layer);
                        ui.label(filter.action.as_str());
                        ui.label(
                            filter
                                .remote_port
                                .map(|p| p.to_string())
                                .unwrap_or_else(|| "-".into()),
                        );
                        ui.label(if filter.owned_by_app { "Yes" } else { "No" });
                        ui.horizontal(|ui| {
                            let can_edit = filter.owned_by_app && filter.remote_port.is_some();
                            if ui
                                .add_enabled(can_edit, egui::Button::new("Edit"))
                                .clicked()
                            {
                                if let Some(port) = filter.remote_port {
                                    self.edit_state = Some(EditState {
                                        id: filter.id,
                                        name: filter.name.clone(),
                                        remote_port: port,
                                        action: filter.action,
                                    });
                                }
                            }
                            if ui
                                .add_enabled(filter.owned_by_app, egui::Button::new("Delete"))
                                .clicked()
                            {
                                self.delete_state = Some(DeleteState {
                                    id: filter.id,
                                    name: filter.name.clone(),
                                });
                            }
                        });
                        ui.end_row();
                    }
                });
        });
    }

    fn render_metadata(&self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new("Providers").show(ui, |ui| {
            for item in &self.providers {
                ui.label(format!("{} — {}", format_guid(item.key), item.name));
                if let Some(desc) = &item.description {
                    ui.label(egui::RichText::new(desc).small());
                }
            }
        });
        egui::CollapsingHeader::new("Sublayers").show(ui, |ui| {
            for item in &self.sublayers {
                ui.label(format!("{} — {}", format_guid(item.key), item.name));
                if let Some(desc) = &item.description {
                    ui.label(egui::RichText::new(desc).small());
                }
            }
        });
        egui::CollapsingHeader::new("Layers").show(ui, |ui| {
            for item in &self.layers {
                ui.label(format!("{} — {}", format_guid(item.key), item.name));
                if let Some(desc) = &item.description {
                    ui.label(egui::RichText::new(desc).small());
                }
            }
        });
    }

    fn render_edit_window(&mut self, ctx: &egui::Context) {
        if let Some(edit) = &mut self.edit_state {
            let mut open = true;
            egui::Window::new(format!("Edit Filter {}", edit.id))
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.label(format!("Editing filter '{}'", edit.name));
                    ui.label("Name:");
                    ui.text_edit_singleline(&mut edit.name);
                    ui.label("Remote TCP Port:");
                    ui.add(egui::DragValue::new(&mut edit.remote_port).clamp_range(1..=65535));
                    ui.label("Action:");
                    egui::ComboBox::from_id_source("action_combo")
                        .selected_text(edit.action.as_str())
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut edit.action, WfpAction::Permit, "Permit");
                            ui.selectable_value(&mut edit.action, WfpAction::Block, "Block");
                        });
                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() {
                            let result = Engine::open().and_then(|eng| {
                                eng.update_simple_tcp_filter_v4(
                                    edit.id,
                                    &edit.name,
                                    edit.remote_port,
                                    edit.action,
                                )
                            });
                            self.status = match result {
                                Ok(_) => {
                                    self.refresh_pending = true;
                                    "Filter updated.".into()
                                }
                                Err(err) => format!("Update failed: {err}"),
                            };
                        }
                        if ui.button("Cancel").clicked() {
                            open = false;
                        }
                    });
                });
            if !open {
                self.edit_state = None;
            }
        }
    }

    fn render_delete_window(&mut self, ctx: &egui::Context) {
        if let Some(delete) = &self.delete_state {
            let mut open = true;
            let id = delete.id;
            let name = delete.name.clone();
            egui::Window::new("Confirm delete")
                .collapsible(false)
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.label(format!("Delete filter '{}' (ID {})?", name, id));
                    ui.horizontal(|ui| {
                        if ui.button("Delete").clicked() {
                            let result = Engine::open().and_then(|eng| eng.delete_filter_by_id(id));
                            self.status = match result {
                                Ok(_) => {
                                    self.refresh_pending = true;
                                    "Filter deleted.".into()
                                }
                                Err(err) => format!("Delete failed: {err}"),
                            };
                        }
                        if ui.button("Cancel").clicked() {
                            open = false;
                        }
                    });
                });
            if !open {
                self.delete_state = None;
            }
        }
    }
}

fn format_guid(guid: GUID) -> String {
    format!("{guid:?}")
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

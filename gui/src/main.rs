use eframe::egui;
use protocol_infer_core::{
    pcap, plugins, Corpus, Flow, InferenceEngine, InferenceResult,
};
use std::sync::{Arc, Mutex};
use std::sync::mpsc;
use std::thread;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1200.0, 800.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Protocol Infer GUI",
        options,
        Box::new(|_cc| Box::new(ProtocolInferApp::default())),
    )
}

struct ProtocolInferApp {
    flows: Vec<Flow>,
    selected_flow: Option<usize>,
    inference_result: Option<InferenceResult>,
    inference_in_progress: Arc<Mutex<bool>>,
    inference_receiver: Option<mpsc::Receiver<InferenceResult>>,
    selected_pdu: Option<(usize, usize)>, // (layer_idx, pdu_idx)
    hexdump_data: Vec<u8>,
    hexdump_offset: usize,
}

impl Default for ProtocolInferApp {
    fn default() -> Self {
        Self {
            flows: Vec::new(),
            selected_flow: None,
            inference_result: None,
            inference_in_progress: Arc::new(Mutex::new(false)),
            inference_receiver: None,
            selected_pdu: None,
            hexdump_data: Vec::new(),
            hexdump_offset: 0,
        }
    }
}

impl eframe::App for ProtocolInferApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Vérifier si un résultat d'inférence est disponible
        if let Some(receiver) = &self.inference_receiver {
            if let Ok(result) = receiver.try_recv() {
                self.inference_result = Some(result);
                self.inference_receiver = None;
                *self.inference_in_progress.lock().unwrap() = false;
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Protocol Infer - Analyse de Protocoles");

            ui.horizontal(|ui| {
                if ui.button("Ouvrir PCAP").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("PCAP", &["pcap", "pcapng"])
                        .pick_file()
                    {
                        self.load_pcap(path.to_str().unwrap());
                    }
                }

                if let Some(flow_idx) = self.selected_flow {
                    if ui.button("Lancer Inférence").clicked() {
                        self.start_inference(flow_idx);
                    }
                }
            });

            ui.separator();

            egui::SidePanel::left("flows_panel")
                .resizable(true)
                .default_width(200.0)
                .show_inside(ui, |ui| {
                    ui.heading("Flows");
                    for (idx, flow) in self.flows.iter().enumerate() {
                        let label = format!(
                            "Flow {}: {} → {}:{} ({} pkts)",
                            idx,
                            flow.src_ip,
                            flow.dst_ip,
                            flow.dst_port,
                            flow.datagrams.len()
                        );

                        if ui.selectable_label(
                            self.selected_flow == Some(idx),
                            label,
                        )
                        .clicked()
                        {
                            self.selected_flow = Some(idx);
                            self.inference_result = None;
                        }
                    }
                });

            if let Some(_flow_idx) = self.selected_flow {
                // Appeler show_layers_panel d'abord (ne nécessite pas &mut self)
                if let Some(result) = self.inference_result.as_ref() {
                    self.show_layers_panel(ui, result);
                }
                
                // Pour show_message_inspector, on doit éviter le conflit de borrow
                // en utilisant une approche différente : on clone seulement les indices nécessaires
                let selected_pdu_copy = self.selected_pdu;
                if let Some(result) = self.inference_result.as_ref() {
                    // Créer une version temporaire qui ne modifie pas self.selected_pdu directement
                    // mais utilise une copie locale
                    let mut temp_selected = selected_pdu_copy;
                    egui::TopBottomPanel::bottom("hexdump_panel")
                        .resizable(true)
                        .default_height(200.0)
                        .show_inside(ui, |ui| {
                            ui.heading("Hexdump");
                            if let Some((layer_idx, pdu_idx)) = temp_selected {
                                if let Some(layer) = result.layers.get(layer_idx) {
                                    if let Some(_pdu) = layer.parsed.parsed_pdus.get(pdu_idx) {
                                        ui.monospace(format!("PDU {} de la couche {}", pdu_idx, layer_idx));
                                    }
                                }
                            } else {
                                ui.label("Sélectionnez un PDU pour voir le hexdump");
                            }
                        });

                    ui.vertical(|ui| {
                        ui.heading("Messages");
                        if let Some(layer_idx) = temp_selected.map(|(l, _)| l) {
                            if let Some(layer) = result.layers.get(layer_idx) {
                                egui::ScrollArea::vertical().show(ui, |ui| {
                                    for (pdu_idx, parsed_pdu) in layer.parsed.parsed_pdus.iter().enumerate() {
                                        let label = format!(
                                            "PDU {} ({} segments)",
                                            pdu_idx,
                                            parsed_pdu.segments.len()
                                        );
                                        if ui.selectable_label(
                                            temp_selected == Some((layer_idx, pdu_idx)),
                                            label,
                                        )
                                        .clicked()
                                        {
                                            temp_selected = Some((layer_idx, pdu_idx));
                                        }
                                    }
                                });
                            }
                        }
                    });
                    // Mettre à jour self.selected_pdu après avoir libéré l'emprunt
                    self.selected_pdu = temp_selected;
                } else {
                    ui.centered_and_justified(|ui| {
                        if *self.inference_in_progress.lock().unwrap() {
                            ui.spinner();
                            ui.label("Inférence en cours...");
                        } else {
                            ui.label("Sélectionnez un flow et lancez l'inférence");
                        }
                    });
                }
            } else {
                ui.centered_and_justified(|ui| {
                    ui.label("Ouvrez un fichier PCAP pour commencer");
                });
            }
        });
    }
}

impl ProtocolInferApp {
    fn load_pcap(&mut self, path: &str) {
        match pcap::parse_pcap(path) {
            Ok(flows) => {
                self.flows = flows;
                self.selected_flow = if !self.flows.is_empty() {
                    Some(0)
                } else {
                    None
                };
            }
            Err(e) => {
                eprintln!("Erreur lors du chargement du PCAP: {}", e);
            }
        }
    }

    fn start_inference(&mut self, flow_idx: usize) {
        if *self.inference_in_progress.lock().unwrap() {
            return;
        }

        let flow = self.flows[flow_idx].clone();
        let (sender, receiver) = mpsc::channel();
        let in_progress = Arc::clone(&self.inference_in_progress);

        *in_progress.lock().unwrap() = true;
        self.inference_receiver = Some(receiver);

        thread::spawn(move || {
            let corpus = Corpus::from_datagrams(&flow.datagrams, Some(flow_idx));
            let registry = plugins::create_default_registry();
            let engine = InferenceEngine::new();
            let result = engine.infer(corpus, &registry);
            let _ = sender.send(result);
            *in_progress.lock().unwrap() = false;
        });
    }

    fn show_layers_panel(&self, ui: &mut egui::Ui, result: &InferenceResult) {
        egui::SidePanel::right("layers_panel")
            .resizable(true)
            .default_width(300.0)
            .show_inside(ui, |ui| {
                ui.heading("Couches");
                for (idx, layer) in result.layers.iter().enumerate() {
                    ui.collapsing(format!("Layer {}", idx), |ui| {
                        ui.label(format!("Hypothèse: {}", layer.hypothesis.name()));
                        ui.label(format!(
                            "Score total: {:.2} bits",
                            layer.score.total_bits
                        ));
                        ui.label(format!(
                            "PSR: {:.2}%",
                            layer.score.breakdown.parse_success_ratio * 100.0
                        ));
                        ui.label(format!(
                            "MDL Model: {:.2} bits",
                            layer.score.breakdown.mdl_model_bits
                        ));
                        ui.label(format!(
                            "MDL Data: {:.2} bits",
                            layer.score.breakdown.mdl_data_bits
                        ));
                    });
                }
            });
    }

    fn show_message_inspector(&mut self, ui: &mut egui::Ui, result: &InferenceResult) {
        egui::TopBottomPanel::bottom("hexdump_panel")
            .resizable(true)
            .default_height(200.0)
            .show_inside(ui, |ui| {
                ui.heading("Hexdump");

                if let Some((layer_idx, pdu_idx)) = self.selected_pdu {
                    if let Some(layer) = result.layers.get(layer_idx) {
                        if let Some(pdu) = layer.parsed.parsed_pdus.get(pdu_idx) {
                            // Afficher le hexdump avec segments surlignés
                            ui.monospace(format!("PDU {} de la couche {}", pdu_idx, layer_idx));
                            // TODO: afficher hexdump avec coloration des segments
                        }
                    }
                } else {
                    ui.label("Sélectionnez un PDU pour voir le hexdump");
                }
            });

        ui.vertical(|ui| {
            ui.heading("Messages");
            if let Some(layer_idx) = self.selected_pdu.map(|(l, _)| l) {
                if let Some(layer) = result.layers.get(layer_idx) {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        for (pdu_idx, parsed_pdu) in layer.parsed.parsed_pdus.iter().enumerate() {
                            let label = format!(
                                "PDU {} ({} segments)",
                                pdu_idx,
                                parsed_pdu.segments.len()
                            );
                            if ui.selectable_label(
                                self.selected_pdu == Some((layer_idx, pdu_idx)),
                                label,
                            )
                            .clicked()
                            {
                                self.selected_pdu = Some((layer_idx, pdu_idx));
                            }
                        }
                    });
                }
            }
        });
    }
}


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
    flow: Option<Flow>,
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
            flow: None,
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

        // Barre de menu en haut
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Ouvrir PCAP").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("PCAP", &["pcap", "pcapng"])
                        .pick_file()
                    {
                        self.load_pcap(path.to_str().unwrap());
                    }
                }

                if self.flow.is_some() {
                    if ui.button("Lancer Inférence").clicked() {
                        self.start_inference();
                    }
                }

                // Afficher les informations du flow unique
                if let Some(ref flow) = self.flow {
                    ui.separator();
                    ui.label(format!("Paquets: {}", flow.datagrams.len()));
                    let total_bytes: usize = flow.datagrams.iter().map(|d| d.payload.len()).sum();
                    ui.label(format!("Total: {} octets", total_bytes));
                }
            });
        });

        if self.flow.is_some() {
            // Afficher les messages et le hexdump
            if let Some(result) = self.inference_result.as_ref() {
                // Sélectionner la couche 0 par défaut si aucune n'est sélectionnée
                let default_layer = 0;
                let selected_pdu_copy = self.selected_pdu.unwrap_or((default_layer, 0));
                let mut temp_selected = selected_pdu_copy;
                
                // Panneau latéral gauche pour la liste des messages
                egui::SidePanel::left("messages_panel")
                    .resizable(true)
                    .default_width(300.0)
                    .show(ctx, |ui| {
                            ui.heading("Messages");
                            
                            // Sélecteur de couche
                            ui.horizontal(|ui| {
                                ui.label("Couche:");
                                for layer_idx in 0..result.layers.len() {
                                    let is_selected = temp_selected.0 == layer_idx;
                                    if ui.selectable_label(is_selected, format!("{}", layer_idx))
                                        .clicked()
                                    {
                                        temp_selected = (layer_idx, 0);
                                    }
                                }
                            });
                            
                            ui.separator();
                            
                            // Liste des messages de la couche sélectionnée
                            if let Some(layer) = result.layers.get(temp_selected.0) {
                                // Compter les messages réels (en comptant les boundaries)
                                let total_messages: usize = layer.parsed.parsed_pdus.iter()
                                    .map(|p| {
                                        let boundaries = p.segments.iter()
                                            .filter(|s| matches!(s.kind, protocol_infer_core::SegmentKind::MessageBoundary))
                                            .count();
                                        1 + boundaries // 1 message de base + boundaries = messages supplémentaires
                                    })
                                    .sum();
                                
                                ui.label(format!("{} PDUs originaux, {} messages extraits", 
                                    layer.parsed.parsed_pdus.len(), total_messages));
                                ui.separator();
                                
                                egui::ScrollArea::vertical().show(ui, |ui| {
                                    for (pdu_idx, parsed_pdu) in layer.parsed.parsed_pdus.iter().enumerate() {
                                        let is_selected = temp_selected == (temp_selected.0, pdu_idx);
                                        
                                        // Compter les segments par type
                                        let pci_count = parsed_pdu.segments.iter()
                                            .filter(|s| matches!(s.kind, protocol_infer_core::SegmentKind::Pci))
                                            .count();
                                        let sdu_count = parsed_pdu.segments.iter()
                                            .filter(|s| matches!(s.kind, protocol_infer_core::SegmentKind::Sdu))
                                            .count();
                                        let boundary_count = parsed_pdu.segments.iter()
                                            .filter(|s| matches!(s.kind, protocol_infer_core::SegmentKind::MessageBoundary))
                                            .count();
                                        
                                        // Calculer la taille totale
                                        let total_size: usize = parsed_pdu.segments.iter()
                                            .map(|s| s.range.end - s.range.start)
                                            .sum();
                                        
                                        let label = if boundary_count > 0 {
                                            format!(
                                                "PDU {} ({} messages, {} octets, {} segments)",
                                                pdu_idx,
                                                boundary_count + 1,
                                                total_size,
                                                parsed_pdu.segments.len()
                                            )
                                        } else {
                                            format!(
                                                "PDU {} (1 message, {} octets, {} segments)",
                                                pdu_idx,
                                                total_size,
                                                parsed_pdu.segments.len()
                                            )
                                        };
                                        
                                        if ui.selectable_label(is_selected, label).clicked() {
                                            temp_selected = (temp_selected.0, pdu_idx);
                                        }
                                        
                                        // Afficher les détails des segments si sélectionné
                                        if is_selected {
                                            ui.indent("segments", |ui| {
                                                // Grouper les segments par message (séparés par MessageBoundary)
                                                let mut message_idx = 0;
                                                let mut current_message_segments: Vec<&protocol_infer_core::Segment> = Vec::new();
                                                
                                                for segment in &parsed_pdu.segments {
                                                    if matches!(segment.kind, protocol_infer_core::SegmentKind::MessageBoundary) {
                                                        // Afficher le message actuel
                                                        if !current_message_segments.is_empty() {
                                                            ui.label(format!("  Message {}:", message_idx));
                                                            for seg in &current_message_segments {
                                                                let seg_type = match seg.kind {
                                                                    protocol_infer_core::SegmentKind::Pci => "PCI",
                                                                    protocol_infer_core::SegmentKind::Sdu => "SDU",
                                                                    protocol_infer_core::SegmentKind::Field(ref name) => name,
                                                                    protocol_infer_core::SegmentKind::Error(ref msg) => msg,
                                                                    _ => "?",
                                                                };
                                                                ui.label(format!(
                                                                    "    {} [{}-{}] ({} octets)",
                                                                    seg_type,
                                                                    seg.range.start,
                                                                    seg.range.end,
                                                                    seg.range.end - seg.range.start
                                                                ));
                                                            }
                                                            message_idx += 1;
                                                            current_message_segments.clear();
                                                        }
                                                    } else {
                                                        current_message_segments.push(segment);
                                                    }
                                                }
                                                
                                                // Afficher le dernier message s'il reste des segments
                                                if !current_message_segments.is_empty() {
                                                    ui.label(format!("  Message {}:", message_idx));
                                                    for seg in &current_message_segments {
                                                        let seg_type = match seg.kind {
                                                            protocol_infer_core::SegmentKind::Pci => "PCI",
                                                            protocol_infer_core::SegmentKind::Sdu => "SDU",
                                                            protocol_infer_core::SegmentKind::Field(ref name) => name,
                                                            protocol_infer_core::SegmentKind::Error(ref msg) => msg,
                                                            _ => "?",
                                                        };
                                                        ui.label(format!(
                                                            "    {} [{}-{}] ({} octets)",
                                                            seg_type,
                                                            seg.range.start,
                                                            seg.range.end,
                                                            seg.range.end - seg.range.start
                                                        ));
                                                    }
                                                }
                                                
                                                // Afficher les erreurs s'il y en a
                                                if !parsed_pdu.exceptions.is_empty() {
                                                    ui.separator();
                                                    ui.label("Exceptions:");
                                                    for exc in &parsed_pdu.exceptions {
                                                        ui.label(format!("  ⚠ {}", exc));
                                                    }
                                                }
                                            });
                                        }
                                    }
                                });
                            }
                            
                        // Mettre à jour la sélection
                        self.selected_pdu = Some(temp_selected);
                    });
                
                // Cloner les données nécessaires pour éviter les problèmes de borrow
                let result_for_layers = result.clone();
                let result_for_hexdump = result.clone();
                let selected_pdu_for_hexdump = self.selected_pdu;
                
                // Panneau latéral droit pour les couches
                egui::SidePanel::right("layers_panel")
                    .resizable(true)
                    .default_width(400.0)
                    .show(ctx, |ui| {
                        self.show_layers_panel(ui, &result_for_layers);
                    });
                
                // Panneau central pour le hexdump
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.heading("Hexdump");
                    
                    if let Some((layer_idx, pdu_idx)) = selected_pdu_for_hexdump {
                        if let Some(layer) = result_for_hexdump.layers.get(layer_idx) {
                            if let Some(parsed_pdu) = layer.parsed.parsed_pdus.get(pdu_idx) {
                                // Récupérer les données originales du corpus
                                if let Some(original_pdu) = result_for_hexdump.corpus.items.get(pdu_idx) {
                                    self.show_hexdump_with_segments(ui, original_pdu, parsed_pdu);
                                } else {
                                    ui.label(format!("PDU {} de la couche {} (données non disponibles)", pdu_idx, layer_idx));
                                }
                            }
                        }
                    } else {
                        ui.centered_and_justified(|ui| {
                            ui.label("Sélectionnez un message pour voir le hexdump");
                        });
                    }
                });
            } else {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.centered_and_justified(|ui| {
                        if *self.inference_in_progress.lock().unwrap() {
                            ui.spinner();
                            ui.label("Inférence en cours...");
                        } else {
                            ui.label("Lancez l'inférence pour voir les messages");
                        }
                    });
                });
            }
        } else {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.centered_and_justified(|ui| {
                    ui.label("Ouvrez un fichier PCAP pour commencer");
                });
            });
        }
    }
}

impl ProtocolInferApp {
    fn load_pcap(&mut self, path: &str) {
        match pcap::parse_pcap(path) {
            Ok(flow) => {
                self.flow = Some(flow);
                self.inference_result = None;
            }
            Err(e) => {
                eprintln!("Erreur lors du chargement du PCAP: {}", e);
            }
        }
    }

    fn start_inference(&mut self) {
        if *self.inference_in_progress.lock().unwrap() {
            return;
        }

        let flow = match &self.flow {
            Some(f) => f.clone(),
            None => return,
        };

        let (sender, receiver) = mpsc::channel();
        let in_progress = Arc::clone(&self.inference_in_progress);

        *in_progress.lock().unwrap() = true;
        self.inference_receiver = Some(receiver);

        thread::spawn(move || {
            let corpus = Corpus::from_datagrams(&flow.datagrams, Some(0));
            let registry = plugins::create_default_registry();
            let engine = InferenceEngine::new();
            let result = engine.infer(corpus, &registry);
            let _ = sender.send(result);
            *in_progress.lock().unwrap() = false;
        });
    }

    fn show_layers_panel(&mut self, ui: &mut egui::Ui, result: &InferenceResult) {
        egui::SidePanel::right("layers_panel")
            .resizable(true)
            .default_width(400.0)
            .show_inside(ui, |ui| {
                ui.heading("Couches & Détails");
                
                ui.heading("Couches Inférées");
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for (idx, layer) in result.layers.iter().enumerate() {
                        ui.collapsing(format!("Layer {} - {}", idx, layer.hypothesis.name()), |ui| {
                            ui.label(format!("Hypothèse sélectionnée: {}", layer.hypothesis.name()));
                            ui.separator();
                            
                            // Afficher les détails spécifiques selon le type d'hypothèse
                            self.show_hypothesis_details(ui, &layer.hypothesis);
                            
                            ui.separator();
                            ui.label("Métriques de l'hypothèse sélectionnée:");
                            ui.horizontal(|ui| {
                                ui.label("Score total:");
                                ui.label(format!("{:.2} bits", layer.score.total_bits));
                            });
                            ui.horizontal(|ui| {
                                ui.label("PSR:");
                                ui.label(format!("{:.2}%", layer.score.breakdown.parse_success_ratio * 100.0));
                            });
                            ui.horizontal(|ui| {
                                ui.label("MDL Model:");
                                ui.label(format!("{:.2} bits", layer.score.breakdown.mdl_model_bits));
                            });
                            ui.horizontal(|ui| {
                                ui.label("MDL Data:");
                                ui.label(format!("{:.2} bits", layer.score.breakdown.mdl_data_bits));
                            });
                            ui.horizontal(|ui| {
                                ui.label("Pénalités:");
                                ui.label(format!("{:.2} bits", layer.score.breakdown.penalties_bits));
                            });
                            
                            // Afficher toutes les hypothèses testées
                            if !layer.all_hypotheses.is_empty() {
                                ui.separator();
                                ui.heading(format!("Toutes les hypothèses testées ({})", layer.all_hypotheses.len()));
                                
                                // Tableau comparatif
                                egui::ScrollArea::horizontal().show(ui, |ui| {
                                    egui::Grid::new(format!("hypotheses_grid_{}", idx))
                                        .num_columns(7)
                                        .spacing([10.0, 4.0])
                                        .striped(true)
                                        .show(ui, |ui| {
                                            // En-têtes
                                            ui.strong("Rang");
                                            ui.strong("Hypothèse");
                                            ui.strong("Score Total");
                                            ui.strong("PSR");
                                            ui.strong("MDL Model");
                                            ui.strong("MDL Data");
                                            ui.strong("Diff vs Best");
                                            ui.end_row();
                                            
                                            let best_score = layer.all_hypotheses.first()
                                                .map(|h| h.score.total_bits)
                                                .unwrap_or(0.0);
                                            
                                            // Lignes de données
                                            for (rank, hyp_result) in layer.all_hypotheses.iter().enumerate() {
                                                let is_best = rank == 0;
                                                let diff = hyp_result.score.total_bits - best_score;
                                                
                                                // Rang avec indicateur visuel
                                                if is_best {
                                                    ui.label(egui::RichText::new(format!("{} ✓", rank + 1))
                                                        .color(egui::Color32::from_rgb(0, 200, 0)));
                                                } else {
                                                    ui.label(format!("{}", rank + 1));
                                                }
                                                
                                                // Nom de l'hypothèse
                                                ui.label(hyp_result.hypothesis.name());
                                                
                                                // Score total
                                                ui.label(format!("{:.2}", hyp_result.score.total_bits));
                                                
                                                // PSR avec couleur selon la qualité
                                                let psr = hyp_result.score.breakdown.parse_success_ratio * 100.0;
                                                let psr_color = if psr >= 95.0 {
                                                    egui::Color32::from_rgb(0, 200, 0)
                                                } else if psr >= 80.0 {
                                                    egui::Color32::from_rgb(200, 200, 0)
                                                } else {
                                                    egui::Color32::from_rgb(200, 0, 0)
                                                };
                                                ui.label(egui::RichText::new(format!("{:.1}%", psr))
                                                    .color(psr_color));
                                                
                                                // MDL Model
                                                ui.label(format!("{:.2}", hyp_result.score.breakdown.mdl_model_bits));
                                                
                                                // MDL Data
                                                ui.label(format!("{:.2}", hyp_result.score.breakdown.mdl_data_bits));
                                                
                                                // Différence vs meilleur
                                                if is_best {
                                                    ui.label(egui::RichText::new("—")
                                                        .color(egui::Color32::GRAY));
                                                } else {
                                                    ui.label(format!("+{:.2}", diff));
                                                }
                                                
                                                ui.end_row();
                                            }
                                        });
                                });
                                
                                // Option pour voir les détails de chaque hypothèse
                                ui.separator();
                                ui.collapsing("Détails de chaque hypothèse", |ui| {
                                    for (rank, hyp_result) in layer.all_hypotheses.iter().enumerate() {
                                        ui.collapsing(format!("#{} - {}", rank + 1, hyp_result.hypothesis.name()), |ui| {
                                            self.show_hypothesis_details(ui, &hyp_result.hypothesis);
                                            ui.separator();
                                            ui.label("Métriques complètes:");
                                            ui.horizontal(|ui| {
                                                ui.label("Score total:");
                                                ui.label(format!("{:.2} bits", hyp_result.score.total_bits));
                                            });
                                            ui.horizontal(|ui| {
                                                ui.label("PSR:");
                                                ui.label(format!("{:.2}%", hyp_result.score.breakdown.parse_success_ratio * 100.0));
                                            });
                                            ui.horizontal(|ui| {
                                                ui.label("MDL Model:");
                                                ui.label(format!("{:.2} bits", hyp_result.score.breakdown.mdl_model_bits));
                                            });
                                            ui.horizontal(|ui| {
                                                ui.label("MDL Data:");
                                                ui.label(format!("{:.2} bits", hyp_result.score.breakdown.mdl_data_bits));
                                            });
                                            ui.horizontal(|ui| {
                                                ui.label("Alignment Gain:");
                                                ui.label(format!("{:.2} bits", hyp_result.score.breakdown.alignment_gain_bits));
                                            });
                                            ui.horizontal(|ui| {
                                                ui.label("Entropy Drop:");
                                                ui.label(format!("{:.2} bits", hyp_result.score.breakdown.entropy_drop_bits));
                                            });
                                            ui.horizontal(|ui| {
                                                ui.label("Pénalités:");
                                                ui.label(format!("{:.2} bits", hyp_result.score.breakdown.penalties_bits));
                                            });
                                        });
                                    }
                                });
                            }
                        });
                    }
                });
            });
    }

    fn show_hypothesis_details(&self, ui: &mut egui::Ui, hypothesis: &protocol_infer_core::Hypothesis) {
        use protocol_infer_core::hypothesis::*;
        
        match hypothesis {
            Hypothesis::Tlv { tag_offset, tag_bytes, len_offset, len_rule, length_includes_header } => {
                ui.label("Détails TLV:");
                ui.separator();
                
                let len_bytes = match len_rule {
                    TlvLenRule::DefiniteShort => 1,
                    TlvLenRule::DefiniteMedium => 2,
                    TlvLenRule::DefiniteLong => 4,
                    TlvLenRule::IndefiniteWithEoc => 0,
                };
                
                let endian_str = match len_rule {
                    TlvLenRule::DefiniteShort => "N/A (1 byte)",
                    TlvLenRule::DefiniteMedium => "Big Endian",
                    TlvLenRule::DefiniteLong => "Big Endian",
                    TlvLenRule::IndefiniteWithEoc => "N/A (indefinite)",
                };
                
                ui.horizontal(|ui| {
                    ui.label("Tag offset:");
                    ui.label(format!("{} octets", tag_offset));
                });
                ui.horizontal(|ui| {
                    ui.label("Tag bytes:");
                    ui.label(format!("{}", tag_bytes));
                });
                ui.horizontal(|ui| {
                    ui.label("Length offset:");
                    ui.label(format!("{} octets", len_offset));
                });
                ui.horizontal(|ui| {
                    ui.label("Length bytes:");
                    ui.label(format!("{}", len_bytes));
                });
                ui.horizontal(|ui| {
                    ui.label("Endianness:");
                    ui.label(endian_str);
                });
                
                ui.horizontal(|ui| {
                    ui.label("Length includes header:");
                    ui.label(format!("{}", length_includes_header));
                });
                
                if matches!(len_rule, TlvLenRule::DefiniteLong) {
                    ui.separator();
                    ui.label("Note: DefiniteLong utilise Big Endian par défaut");
                } else if matches!(len_rule, TlvLenRule::DefiniteMedium) {
                    ui.separator();
                    ui.label("Note: DefiniteMedium (2 bytes) utilise Big Endian par défaut");
                } else if matches!(len_rule, TlvLenRule::IndefiniteWithEoc) {
                    ui.separator();
                    ui.label("Note: Mode indéfini avec EOC (0x00 0x00)");
                }
            }
            Hypothesis::LengthPrefixBundle { offset, width, endian, includes_header } => {
                ui.label("Détails Length-Prefix:");
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("Length offset:");
                    ui.label(format!("{} octets", offset));
                });
                ui.horizontal(|ui| {
                    ui.label("Length width:");
                    ui.label(format!("{} octets", *width as usize));
                });
                ui.horizontal(|ui| {
                    ui.label("Endianness:");
                    ui.label(format!("{:?}", endian));
                });
                ui.horizontal(|ui| {
                    ui.label("Includes header:");
                    ui.label(format!("{}", includes_header));
                });
                ui.horizontal(|ui| {
                    ui.label("Header length:");
                    ui.label(format!("{} octets", offset + *width as usize));
                });
            }
            Hypothesis::FixedHeader { len } => {
                ui.label("Détails Fixed Header:");
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("Header length:");
                    ui.label(format!("{} octets", len));
                });
                ui.horizontal(|ui| {
                    ui.label("Length offset:");
                    ui.label("N/A");
                });
                ui.horizontal(|ui| {
                    ui.label("Endianness:");
                    ui.label("N/A");
                });
            }
            Hypothesis::ExtensibleBitmap { start, cont_bit, stop_value, max_bytes } => {
                ui.label("Détails Extensible Bitmap:");
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("Start offset:");
                    ui.label(format!("{} octets", start));
                });
                ui.horizontal(|ui| {
                    ui.label("Continuation bit:");
                    ui.label(format!("{}", cont_bit));
                });
                ui.horizontal(|ui| {
                    ui.label("Stop value:");
                    ui.label(format!("{}", stop_value));
                });
                ui.horizontal(|ui| {
                    ui.label("Max bytes:");
                    ui.label(format!("{}", max_bytes));
                });
            }
            Hypothesis::DelimiterBundle { pattern } => {
                ui.label("Détails Delimiter:");
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("Pattern:");
                    ui.label(format!("{:?}", pattern));
                });
                ui.horizontal(|ui| {
                    ui.label("Pattern length:");
                    ui.label(format!("{} octets", pattern.len()));
                });
            }
            Hypothesis::VarintKeyWireType { key_max_bytes, allow_embedded } => {
                ui.label("Détails Varint:");
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("Key max bytes:");
                    ui.label(format!("{}", key_max_bytes));
                });
                ui.horizontal(|ui| {
                    ui.label("Allow embedded:");
                    ui.label(format!("{}", allow_embedded));
                });
            }
        }
    }


    fn show_hexdump_with_segments(&self, ui: &mut egui::Ui, pdu: &protocol_infer_core::PduRef, parsed_pdu: &protocol_infer_core::ParsedPdu) {
        let data = pdu.as_slice();
        let bytes_per_line = 16;
        
        egui::ScrollArea::both().show(ui, |ui| {
            ui.style_mut().wrap = Some(false);
            
            for (line_idx, chunk) in data.chunks(bytes_per_line).enumerate() {
                let offset = line_idx * bytes_per_line;
                
                ui.horizontal(|ui| {
                    // Offset en hexadécimal
                    ui.monospace(format!("{:08x}: ", offset));
                    
                    // Hex dump
                    for (byte_idx, &byte) in chunk.iter().enumerate() {
                        let abs_idx = offset + byte_idx;
                        
                        // Trouver le segment correspondant
                        let segment = parsed_pdu.segments.iter()
                            .find(|s| s.range.contains(&abs_idx));
                        
                        let color = if let Some(seg) = segment {
                            match seg.kind {
                                protocol_infer_core::SegmentKind::Pci => egui::Color32::from_rgb(200, 200, 255),
                                protocol_infer_core::SegmentKind::Sdu => egui::Color32::from_rgb(200, 255, 200),
                                protocol_infer_core::SegmentKind::MessageBoundary => egui::Color32::from_rgb(255, 255, 200),
                                protocol_infer_core::SegmentKind::Field(_) => egui::Color32::from_rgb(255, 200, 200),
                                protocol_infer_core::SegmentKind::Error(_) => egui::Color32::from_rgb(255, 100, 100),
                            }
                        } else {
                            egui::Color32::TRANSPARENT
                        };
                        
                        ui.label(egui::RichText::new(format!("{:02x}", byte))
                            .background_color(color)
                            .color(egui::Color32::BLACK));
                        
                        if byte_idx < chunk.len() - 1 {
                            ui.label(" ");
                        }
                    }
                    
                    // Espace pour aligner l'ASCII
                    let padding = bytes_per_line - chunk.len();
                    for _ in 0..padding {
                        ui.label("   ");
                    }
                    
                    ui.label("  ");
                    
                    // ASCII representation
                    for (byte_idx, &byte) in chunk.iter().enumerate() {
                        let abs_idx = offset + byte_idx;
                        let segment = parsed_pdu.segments.iter()
                            .find(|s| s.range.contains(&abs_idx));
                        
                        let color = if let Some(seg) = segment {
                            match seg.kind {
                                protocol_infer_core::SegmentKind::Pci => egui::Color32::from_rgb(200, 200, 255),
                                protocol_infer_core::SegmentKind::Sdu => egui::Color32::from_rgb(200, 255, 200),
                                protocol_infer_core::SegmentKind::MessageBoundary => egui::Color32::from_rgb(255, 255, 200),
                                protocol_infer_core::SegmentKind::Field(_) => egui::Color32::from_rgb(255, 200, 200),
                                protocol_infer_core::SegmentKind::Error(_) => egui::Color32::from_rgb(255, 100, 100),
                            }
                        } else {
                            egui::Color32::TRANSPARENT
                        };
                        
                        let ch = if byte >= 32 && byte < 127 {
                            byte as char
                        } else {
                            '.'
                        };
                        
                        ui.label(egui::RichText::new(ch.to_string())
                            .background_color(color)
                            .color(egui::Color32::BLACK));
                    }
                });
            }
            
            // Légende
            ui.separator();
            ui.horizontal(|ui| {
                ui.label("Légende:");
                ui.label(egui::RichText::new(" PCI ").background_color(egui::Color32::from_rgb(200, 200, 255)).color(egui::Color32::BLACK));
                ui.label(egui::RichText::new(" SDU ").background_color(egui::Color32::from_rgb(200, 255, 200)).color(egui::Color32::BLACK));
                ui.label(egui::RichText::new(" Boundary ").background_color(egui::Color32::from_rgb(255, 255, 200)).color(egui::Color32::BLACK));
                ui.label(egui::RichText::new(" Field ").background_color(egui::Color32::from_rgb(255, 200, 200)).color(egui::Color32::BLACK));
                ui.label(egui::RichText::new(" Error ").background_color(egui::Color32::from_rgb(255, 100, 100)).color(egui::Color32::BLACK));
            });
        });
    }
}


use crate::corpus::{Direction, Flow, UdpDatagram};
use crate::Error;
use crate::Result;
use std::collections::HashMap;
use std::sync::Arc;

/// Parse un fichier PCAP et extrait tous les paquets UDP dans un seul flow
pub fn parse_pcap(path: &str) -> Result<Flow> {
    use std::fs::File;
    use std::io::BufReader;

    let file = File::open(path)?;
    // Buffer généreux pour couvrir des paquets/snaplen très grands (snaplen vu à 262144)
    // On prend 1 MiB pour limiter les risques d'Incomplete répétés.
    let reader = BufReader::with_capacity(1_048_576, file);
    let mut pcap_reader = pcap_parser::create_reader(1_048_576, reader)
        .map_err(|e| Error::PcapParse(format!("Failed to create reader: {:?}", e)))?;

    let mut all_datagrams: Vec<UdpDatagram> = Vec::new();

    loop {
        match pcap_reader.next() {
            Ok((offset, pkt)) => {
                let (ts, data) = match &pkt {
                    pcap_parser::PcapBlockOwned::LegacyHeader(_) => {
                        pcap_reader.consume(offset);
                        continue;
                    }
                    pcap_parser::PcapBlockOwned::Legacy(block) => {
                        let ts = block.ts_sec as f64 + block.ts_usec as f64 / 1_000_000.0;
                        (ts, &block.data)
                    }
                    pcap_parser::PcapBlockOwned::NG(_block) => {
                        // Support pcapng : non géré pour l'instant
                        pcap_reader.consume(offset);
                        continue;
                    }
                };

                // Parser le paquet Ethernet/IP/UDP
                if let Ok(parsed) = etherparse::PacketHeaders::from_ethernet_slice(data) {
                    if let Some(ip) = parsed.net {
                        let (src_ip, dst_ip, ip_header_len) = match &ip {
                            etherparse::NetHeaders::Ipv4(h, _) => {
                                use std::net::Ipv4Addr;
                                (
                                    Ipv4Addr::from(h.source).to_string(),
                                    Ipv4Addr::from(h.destination).to_string(),
                                    h.header_len() as usize,
                                )
                            }
                            etherparse::NetHeaders::Ipv6(_, _) => {
                                // IPv6 non détaillé ici : valeurs par défaut
                                ("::1".to_string(), "::1".to_string(), 40)
                            }
                            _ => continue,
                        };

                        if let Some(udp) = parsed.transport {
                            if let etherparse::TransportHeader::Udp(udp_header) = udp {
                                let src_port = udp_header.source_port;
                                let dst_port = udp_header.destination_port;

                                // Calculer l'offset du payload
                                let udp_header_len = 8;
                                let eth_header_len = 14; // Ethernet header
                                let payload_start = eth_header_len + ip_header_len + udp_header_len;

                                let payload = if payload_start < data.len() {
                                    Arc::from(&data[payload_start..])
                                } else {
                                    pcap_reader.consume(offset);
                                    continue;
                                };

                                // Tous les paquets sont dans le même flow (flow_id = 0)
                                let flow_id = 0;
                                
                                // Direction basée sur l'ordre des paquets (alternance simple)
                                let direction = if all_datagrams.len() % 2 == 0 {
                                    Direction::ClientToServer
                                } else {
                                    Direction::ServerToClient
                                };

                                let datagram = UdpDatagram {
                                    timestamp: ts,
                                    flow_id,
                                    direction,
                                    payload,
                                };

                                all_datagrams.push(datagram);
                            }
                        }
                    }
                }

                // Réinitialiser le compteur d'Incomplete après un succès
                // (plus utilisé, laissé pour compat éventuelle)
                pcap_reader.consume(offset);
            }
            Err(pcap_parser::PcapError::Eof) => break,
            Err(pcap_parser::PcapError::Incomplete(_needed)) => {
                // Re-remplir le buffer et réessayer
                pcap_reader
                    .refill()
                    .map_err(|e| Error::PcapParse(format!("PCAP refill error: {:?}", e)))?;
                continue;
            }
            Err(e) => {
                return Err(Error::PcapParse(format!("PCAP parsing error: {:?}", e)));
            }
        }
    }

    // Créer un seul flow avec tous les paquets
    // Utiliser les valeurs du premier paquet pour les métadonnées du flow
    let flow = if all_datagrams.is_empty() {
        Flow {
            src_ip: "0.0.0.0".to_string(),
            dst_ip: "0.0.0.0".to_string(),
            src_port: 0,
            dst_port: 0,
            protocol: 17, // UDP
            datagrams: Vec::new(),
        }
    } else {
        // Trier par timestamp pour avoir un ordre chronologique
        all_datagrams.sort_by(|a, b| a.timestamp.partial_cmp(&b.timestamp).unwrap_or(std::cmp::Ordering::Equal));
        
        Flow {
            src_ip: "All".to_string(),
            dst_ip: "All".to_string(),
            src_port: 0,
            dst_port: 0,
            protocol: 17, // UDP
            datagrams: all_datagrams,
        }
    };

    Ok(flow)
}


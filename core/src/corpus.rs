use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Représente un datagramme UDP avec ses métadonnées
#[derive(Debug, Clone)]
pub struct UdpDatagram {
    pub timestamp: f64,
    pub flow_id: usize,
    pub direction: Direction,
    pub payload: Arc<[u8]>,
}

// Implémentation manuelle de Serialize pour UdpDatagram
impl serde::Serialize for UdpDatagram {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("UdpDatagram", 4)?;
        state.serialize_field("timestamp", &self.timestamp)?;
        state.serialize_field("flow_id", &self.flow_id)?;
        state.serialize_field("direction", &self.direction)?;
        state.serialize_field("payload", &self.payload.as_ref())?;
        state.end()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

/// Représente un flow (5-tuple)
#[derive(Debug, Clone)]
pub struct Flow {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub datagrams: Vec<UdpDatagram>,
}

// Implémentation manuelle de Serialize pour Flow
impl serde::Serialize for Flow {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("Flow", 6)?;
        state.serialize_field("src_ip", &self.src_ip)?;
        state.serialize_field("dst_ip", &self.dst_ip)?;
        state.serialize_field("src_port", &self.src_port)?;
        state.serialize_field("dst_port", &self.dst_port)?;
        state.serialize_field("protocol", &self.protocol)?;
        state.serialize_field("datagrams", &self.datagrams)?;
        state.end()
    }
}

/// Référence vers une PDU (évite les copies)
#[derive(Debug, Clone)]
pub struct PduRef {
    pub data: Arc<[u8]>,
    pub range: std::ops::Range<usize>,
}

impl PduRef {
    pub fn new(data: Arc<[u8]>, range: std::ops::Range<usize>) -> Self {
        Self { data, range }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[self.range.clone()]
    }

    pub fn len(&self) -> usize {
        self.range.end - self.range.start
    }

    pub fn is_empty(&self) -> bool {
        self.range.is_empty()
    }
}

/// Corpus de PDUs à analyser
#[derive(Debug, Clone)]
pub struct Corpus {
    pub items: Vec<PduRef>,
    pub meta: CorpusMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusMeta {
    pub source: String,
    pub total_bytes: usize,
    pub pdu_count: usize,
    pub flow_id: Option<usize>,
}

impl Corpus {
    pub fn new(items: Vec<PduRef>, meta: CorpusMeta) -> Self {
        Self { items, meta }
    }

    pub fn from_datagrams(datagrams: &[UdpDatagram], flow_id: Option<usize>) -> Self {
        let items: Vec<PduRef> = datagrams
            .iter()
            .map(|d| PduRef::new(d.payload.clone(), 0..d.payload.len()))
            .collect();

        let total_bytes: usize = items.iter().map(|p| p.len()).sum();

        let meta = CorpusMeta {
            source: format!("flow_{:?}", flow_id),
            total_bytes,
            pdu_count: items.len(),
            flow_id,
        };

        Self { items, meta }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn total_bytes(&self) -> usize {
        self.meta.total_bytes
    }
}


//! Transport layer for command/event communication
//!
//! Currently provides in-memory channels. Future: IPC transport with same interface.

use std::sync::mpsc::{self, Receiver, Sender};

use messpit_protocol::{CommandEnvelope, EventEnvelope};

/// Trait for sending commands to the engine
pub trait CommandSender: Send {
    fn send(&self, command: CommandEnvelope) -> Result<(), TransportError>;
}

/// Trait for receiving commands in the engine
pub trait CommandReceiver: Send {
    fn recv(&self) -> Result<CommandEnvelope, TransportError>;
    fn try_recv(&self) -> Result<Option<CommandEnvelope>, TransportError>;
}

/// Trait for sending events from the engine
pub trait EventSender: Send {
    fn send(&self, event: EventEnvelope) -> Result<(), TransportError>;
}

/// Trait for receiving events in the UI
pub trait EventReceiver: Send {
    fn recv(&self) -> Result<EventEnvelope, TransportError>;
    fn try_recv(&self) -> Result<Option<EventEnvelope>, TransportError>;
}

/// Transport errors
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("Channel disconnected")]
    Disconnected,
    #[error("Channel full")]
    Full,
    #[error("Transport error: {0}")]
    Other(String),
}

/// In-memory transport using std channels
pub struct InMemoryTransport {
    command_tx: Sender<CommandEnvelope>,
    command_rx: Receiver<CommandEnvelope>,
    event_tx: Sender<EventEnvelope>,
    event_rx: Receiver<EventEnvelope>,
}

impl InMemoryTransport {
    /// Create a new in-memory transport pair
    ///
    /// Returns (ui_side, engine_side) handles
    pub fn new() -> (UiTransport, EngineTransport) {
        let (cmd_tx, cmd_rx) = mpsc::channel();
        let (evt_tx, evt_rx) = mpsc::channel();

        let ui = UiTransport {
            command_tx: cmd_tx,
            event_rx: evt_rx,
        };

        let engine = EngineTransport {
            command_rx: cmd_rx,
            event_tx: evt_tx,
        };

        (ui, engine)
    }
}

/// UI-side transport handle
pub struct UiTransport {
    command_tx: Sender<CommandEnvelope>,
    event_rx: Receiver<EventEnvelope>,
}

impl CommandSender for UiTransport {
    fn send(&self, command: CommandEnvelope) -> Result<(), TransportError> {
        self.command_tx
            .send(command)
            .map_err(|_| TransportError::Disconnected)
    }
}

impl EventReceiver for UiTransport {
    fn recv(&self) -> Result<EventEnvelope, TransportError> {
        self.event_rx
            .recv()
            .map_err(|_| TransportError::Disconnected)
    }

    fn try_recv(&self) -> Result<Option<EventEnvelope>, TransportError> {
        match self.event_rx.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Err(TransportError::Disconnected),
        }
    }
}

/// Engine-side transport handle
pub struct EngineTransport {
    command_rx: Receiver<CommandEnvelope>,
    event_tx: Sender<EventEnvelope>,
}

impl CommandReceiver for EngineTransport {
    fn recv(&self) -> Result<CommandEnvelope, TransportError> {
        self.command_rx
            .recv()
            .map_err(|_| TransportError::Disconnected)
    }

    fn try_recv(&self) -> Result<Option<CommandEnvelope>, TransportError> {
        match self.command_rx.try_recv() {
            Ok(cmd) => Ok(Some(cmd)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Err(TransportError::Disconnected),
        }
    }
}

impl EventSender for EngineTransport {
    fn send(&self, event: EventEnvelope) -> Result<(), TransportError> {
        self.event_tx
            .send(event)
            .map_err(|_| TransportError::Disconnected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use messpit_protocol::{EngineCommand, EngineEvent, Pid};

    #[test]
    fn roundtrip_command_event() {
        let (ui, engine) = InMemoryTransport::new();

        // UI sends command
        let cmd = CommandEnvelope::new(EngineCommand::ListProcesses);
        let cmd_id = cmd.id;
        ui.send(cmd).unwrap();

        // Engine receives command
        let received = engine.recv().unwrap();
        assert_eq!(received.id, cmd_id);

        // Engine sends event
        let event = EventEnvelope::response(
            EngineEvent::ProcessList { processes: vec![] },
            cmd_id,
        );
        engine.send(event).unwrap();

        // UI receives event
        let received = ui.recv().unwrap();
        assert_eq!(received.command_id, Some(cmd_id));
    }
}

use tokio::sync::{broadcast, mpsc};

#[derive(Debug, Clone, PartialEq)]
pub enum IfaceObserverAction {
    Up(String),
    Down(String),
}

// ── Sender ────────────────────────────────────────────────────

#[derive(Clone)]
pub struct IfaceEventSender {
    tx: mpsc::Sender<IfaceObserverAction>,
}

impl IfaceEventSender {
    pub(super) fn new(tx: mpsc::Sender<IfaceObserverAction>) -> Self {
        Self { tx }
    }

    pub async fn send(
        &self,
        event: IfaceObserverAction,
    ) -> Result<(), mpsc::error::SendError<IfaceObserverAction>> {
        self.tx.send(event).await
    }

    pub fn try_send(
        &self,
        event: IfaceObserverAction,
    ) -> Result<(), mpsc::error::TrySendError<IfaceObserverAction>> {
        self.tx.try_send(event)
    }
}

// ── Reader ────────────────────────────────────────────────────

pub struct IfaceEventReader {
    rx: broadcast::Receiver<IfaceObserverAction>,
}

impl IfaceEventReader {
    pub(super) fn new(rx: broadcast::Receiver<IfaceObserverAction>) -> Self {
        Self { rx }
    }

    pub async fn recv(&mut self) -> Result<IfaceObserverAction, broadcast::error::RecvError> {
        self.rx.recv().await
    }

    /// Receive the next interface event, tolerating broadcast lag.
    ///
    /// `broadcast::Receiver::recv()` reports `Err(Lagged)` whenever the reader
    /// fell behind the sender. That is not a reason to stop supervising the
    /// interfaces, but a plain `while let Ok(msg) = recv().await` loop treats it
    /// as end-of-stream and silently stops restarting services on link changes.
    /// Lagging here only skips events; `None` means the sender is gone.
    pub async fn recv_skipping_lag(&mut self) -> Option<IfaceObserverAction> {
        loop {
            match self.rx.recv().await {
                Ok(msg) => return Some(msg),
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!("interface event reader lagged, skipped {skipped} events");
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

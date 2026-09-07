//! PostgreSQL-backed event fanout for running Torii replicas.

use std::{sync::Arc, time::Duration};

use sqlx::{PgPool, postgres::PgListener};
use tokio::{sync::oneshot, task::JoinHandle};
use torii_core::events::EventEnvelope;

use crate::{EventBus, EventPublisher};

const DEFAULT_CHANNEL: &str = "torii_events";

/// Publishes event envelopes through PostgreSQL `NOTIFY` and dispatches
/// notifications received by this replica to its local event bus.
pub struct PostgresEventTransport {
    pool: PgPool,
    channel: String,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl PostgresEventTransport {
    /// Start listening for events on the default Torii channel.
    pub async fn new(pool: PgPool, event_bus: Arc<EventBus>) -> Result<Self, sqlx::Error> {
        Self::with_channel(pool, event_bus, DEFAULT_CHANNEL).await
    }

    /// Start listening for events on a custom PostgreSQL channel.
    pub async fn with_channel(
        pool: PgPool,
        event_bus: Arc<EventBus>,
        channel: impl Into<String>,
    ) -> Result<Self, sqlx::Error> {
        let channel = channel.into();
        let (shutdown_sender, mut shutdown_receiver) = oneshot::channel();
        let listener_pool = pool.clone();
        let listener_channel = channel.clone();
        let task = tokio::spawn(async move {
            let mut retry_delay = Duration::from_millis(100);
            loop {
                let mut listener = match PgListener::connect_with(&listener_pool).await {
                    Ok(mut listener) => match listener.listen(&listener_channel).await {
                        Ok(()) => {
                            retry_delay = Duration::from_millis(100);
                            listener
                        }
                        Err(error) => {
                            tracing::warn!(error = %error, "Failed to subscribe to PostgreSQL events");
                            if wait_for_retry(&mut shutdown_receiver, retry_delay).await {
                                break;
                            }
                            retry_delay = (retry_delay * 2).min(Duration::from_secs(5));
                            continue;
                        }
                    },
                    Err(error) => {
                        tracing::warn!(error = %error, "Failed to connect PostgreSQL event listener");
                        if wait_for_retry(&mut shutdown_receiver, retry_delay).await {
                            break;
                        }
                        retry_delay = (retry_delay * 2).min(Duration::from_secs(5));
                        continue;
                    }
                };

                let mut stopping = false;
                loop {
                    tokio::select! {
                        _ = &mut shutdown_receiver => { stopping = true; break },
                        result = listener.recv() => match result {
                            Ok(notification) => match serde_json::from_str::<EventEnvelope>(notification.payload()) {
                                Ok(envelope) => {
                                    if let Err(error) = event_bus.dispatch_remote(&envelope).await {
                                        tracing::error!(error = %error, "Failed to dispatch PostgreSQL event");
                                    }
                                }
                                Err(error) => tracing::warn!(error = %error, "Ignoring malformed Torii event notification"),
                            }
                            Err(error) => {
                                tracing::warn!(error = %error, "PostgreSQL event listener disconnected");
                                break;
                            }
                        }
                    }
                }

                if stopping {
                    break;
                }
            }
        });

        Ok(Self {
            pool,
            channel,
            shutdown: Some(shutdown_sender),
            task: Some(task),
        })
    }

    /// Publish an envelope to every currently listening replica.
    pub async fn publish(&self, envelope: &EventEnvelope) -> Result<(), sqlx::Error> {
        let payload = serde_json::to_string(envelope)
            .map_err(|error| sqlx::Error::Decode(Box::new(error)))?;

        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(&self.channel)
            .bind(payload)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Stop listening and wait for the listener task to exit.
    pub async fn shutdown(mut self) {
        if let Some(sender) = self.shutdown.take() {
            let _ = sender.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

async fn wait_for_retry(shutdown: &mut oneshot::Receiver<()>, delay: Duration) -> bool {
    tokio::select! { _ = shutdown => true, _ = tokio::time::sleep(delay) => false }
}

#[async_trait::async_trait]
impl EventPublisher for PostgresEventTransport {
    async fn publish(&self, envelope: &EventEnvelope) -> Result<(), torii_core::error::EventError> {
        self.publish(envelope)
            .await
            .map_err(|error| torii_core::error::EventError::BusError(error.to_string()))
    }
}

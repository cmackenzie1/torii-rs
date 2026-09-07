# Events

Torii emits authentication and lifecycle events through a per-instance event
bus. Events are generated after the underlying operation succeeds and can be
consumed by trusted server-side handlers for auditing, metrics, notifications,
or integration with other application services.

## Local handlers

Every `Torii` instance creates an event bus by default. Register a handler with
the public bus accessor:

```rust,no_run
use std::sync::Arc;
use async_trait::async_trait;
use torii::{Event, EventError, EventHandler, Torii};

struct AuditHandler;

#[async_trait]
impl EventHandler for AuditHandler {
    async fn handle_event(&self, event: &Event) -> Result<(), EventError> {
        tracing::info!(?event, "Torii authentication event");
        Ok(())
    }
}

torii.event_bus().register(Arc::new(AuditHandler)).await;
```

Handlers are local to the process. Handler failures are logged and do not turn
a successfully completed authentication operation into a failed operation.

## Distributed delivery

For multiple backend replicas, register an `EventPublisher`. Publishers are
storage-independent and can be implemented for an application's message bus:

```rust,no_run
torii.register_event_publisher(Arc::new(my_publisher)).await;
```

The publisher receives an `EventEnvelope` containing an event ID, origin
replica ID, timestamp, and event payload. Event handlers should be idempotent.
Events from concurrently running replicas have no global ordering guarantee.

## PostgreSQL fanout

The `postgres` feature provides `PostgresEventTransport`, which uses
PostgreSQL `LISTEN`/`NOTIFY` to deliver events to all currently connected
replicas:

```rust,no_run
use std::sync::Arc;
use torii::PostgresEventTransport;

let transport = Arc::new(
    PostgresEventTransport::new(pg_pool, torii.event_bus().clone()).await?
);
torii.register_event_publisher(transport).await;
```

The transport reconnects after listener failures and supports graceful
shutdown:

```rust,no_run
transport.shutdown().await;
```

PostgreSQL notifications are live, non-durable fanout. A replica that is
disconnected while a notification is sent can miss the event. No outbox or
replay mechanism is provided. PostgreSQL event fanout may be used with a
PostgreSQL-backed Torii instance or as a separate coordination channel for a
SQLite- or MySQL-backed instance.

## Event guarantees

- Events are emitted after successful underlying operations.
- Local handlers run through the `EventBus` for every configured storage backend.
- Publisher and handler failures are best-effort and are logged.
- PostgreSQL fanout reaches replicas with an active listener connection.
- Disconnected replicas may miss PostgreSQL notifications.
- Cross-replica global ordering is not guaranteed.
- Event consumers should tolerate duplicate delivery.
- Event payloads do not include passwords, reset tokens, magic-link tokens,
  OAuth subjects, or passkey public-key material.
- `SessionDeleted` may contain a trusted server-side `SessionToken`.

## Event categories

Torii currently covers:

- User creation, update, deletion, and email verification.
- Session creation, deletion, bulk deletion, and refresh.
- Failed logins, account lockout, and account unlock.
- Password registration, authentication, change, removal, and reset.
- OAuth authentication and account linking/unlinking.
- Passkey registration, authentication, and removal.
- Magic-link requests and authentication.

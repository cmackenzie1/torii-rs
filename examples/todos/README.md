# torii-example-todos

This is a simple example of how to use torii to build a todo list application using:

- SQLite for storage
- Axum for the web server with HTMX and Askama for templating
- Email/Password authentication

## Running the example

```bash
cargo run
```

## Running the migrations

```bash
cargo run -- --db-url sqlite://todos.db
```

use clap::Parser;
use sqlx::SqlitePool;
use torii_storage_sqlite::SqliteStorage;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Enable email authentication
    #[arg(long)]
    email_auth: bool,

    /// Enable OpenID Connect authentication
    #[arg(long)]
    oidc_auth: bool,

    /// Database connection string
    #[arg(long)]
    db_url: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Run database migrations
    Migrate,
    /// Print version information
    Version,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Migrate => {
            println!("Running migrations...");
            let pool = SqlitePool::connect(&cli.db_url).await.unwrap();
            let storage = SqliteStorage::new(pool);
            storage.migrate().await.unwrap();
        }
        Commands::Version => {
            println!("Torii v{}", env!("CARGO_PKG_VERSION"));
        }
    }
}

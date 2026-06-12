use sea_orm::DatabaseConnection;
use tokio::sync::broadcast;

use crate::config::Config;
use crate::domains::notes::service::NoteChangeEvent;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: DatabaseConnection,
    pub note_events: broadcast::Sender<NoteChangeEvent>,
}

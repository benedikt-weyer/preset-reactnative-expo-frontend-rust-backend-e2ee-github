use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    response::Response,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::{
    app_state::AppState,
    domains::{
        auth::{service as auth_service, AuthenticatedUser},
        notes::service,
    },
    error::AppResult,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/events", get(stream_note_events))
        .route("/", get(list_notes).post(create_note))
        .route(
            "/{note_id}",
            get(get_note).put(update_note).delete(delete_note),
        )
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NoteEventsQuery {
    access_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveNoteRequest {
    encrypted_deks: Vec<WrappedDekRequest>,
    encrypted_payload: EncryptedBlobRequest,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedBlobRequest {
    algorithm: String,
    ciphertext_hex: String,
    nonce_hex: String,
    version: i32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WrappedDekRequest {
    algorithm: String,
    kem_ciphertext_hex: String,
    kek_public_key: String,
    nonce_hex: String,
    user_id: Uuid,
    version: i32,
    wrapped_dek_hex: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoteResponse {
    id: Uuid,
    encrypted_dek: WrappedDekResponse,
    encrypted_payload: EncryptedBlobResponse,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedBlobResponse {
    algorithm: String,
    ciphertext_hex: String,
    nonce_hex: String,
    version: i32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WrappedDekResponse {
    algorithm: String,
    kem_ciphertext_hex: String,
    kek_public_key: String,
    nonce_hex: String,
    user_id: Uuid,
    version: i32,
    wrapped_dek_hex: String,
}

pub async fn list_notes(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
) -> AppResult<Json<Vec<NoteResponse>>> {
    let notes = service::list_notes(&state, &authenticated_user).await?;
    Ok(Json(notes.into_iter().map(map_note_response).collect()))
}

pub async fn get_note(
    State(state): State<AppState>,
    Path(note_id): Path<Uuid>,
    authenticated_user: AuthenticatedUser,
) -> AppResult<Json<NoteResponse>> {
    let note = service::get_note(&state, &authenticated_user, note_id).await?;
    Ok(Json(map_note_response(note)))
}

pub async fn create_note(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
    Json(payload): Json<SaveNoteRequest>,
) -> AppResult<Json<NoteResponse>> {
    let note = service::create_note(&state, &authenticated_user, map_save_command(payload)).await?;
    Ok(Json(map_note_response(note)))
}

pub async fn update_note(
    State(state): State<AppState>,
    Path(note_id): Path<Uuid>,
    authenticated_user: AuthenticatedUser,
    Json(payload): Json<SaveNoteRequest>,
) -> AppResult<Json<NoteResponse>> {
    let note = service::update_note(
        &state,
        &authenticated_user,
        note_id,
        map_save_command(payload),
    )
    .await?;
    Ok(Json(map_note_response(note)))
}

pub async fn delete_note(
    State(state): State<AppState>,
    Path(note_id): Path<Uuid>,
    authenticated_user: AuthenticatedUser,
) -> AppResult<Json<bool>> {
    service::delete_note(&state, &authenticated_user, note_id).await?;
    Ok(Json(true))
}

async fn stream_note_events(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Query(query): Query<NoteEventsQuery>,
) -> AppResult<Response> {
    let authenticated_user = auth_service::authenticate_access_token(&state, &query.access_token)?;

    Ok(ws.on_upgrade(move |socket| handle_note_event_socket(socket, state, authenticated_user)))
}

async fn handle_note_event_socket(
    mut socket: WebSocket,
    state: AppState,
    authenticated_user: AuthenticatedUser,
) {
    let mut receiver = state.note_events.subscribe();

    loop {
        tokio::select! {
            event_result = receiver.recv() => {
                match event_result {
                    Ok(event) => {
                        if should_deliver_event(&event, &authenticated_user) {
                            let Ok(payload) = serde_json::to_string(&event) else {
                                continue;
                            };

                            if socket.send(Message::Text(payload.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                    Some(Ok(_)) => {}
                }
            }
        }
    }
}

fn should_deliver_event(
    event: &service::NoteChangeEvent,
    authenticated_user: &AuthenticatedUser,
) -> bool {
    event.owner_user_id == authenticated_user.owner_user_id
        && event
            .audience_principal_ids
            .iter()
            .any(|principal_id| *principal_id == authenticated_user.principal_id)
}

fn map_save_command(payload: SaveNoteRequest) -> service::SaveNoteCommand {
    service::SaveNoteCommand {
        encrypted_deks: payload
            .encrypted_deks
            .into_iter()
            .map(map_wrapped_dek_request)
            .collect(),
        encrypted_payload: map_blob_request(payload.encrypted_payload),
    }
}

fn map_wrapped_dek_request(payload: WrappedDekRequest) -> service::SaveWrappedDekCommand {
    service::SaveWrappedDekCommand {
        algorithm: payload.algorithm,
        kem_ciphertext_hex: payload.kem_ciphertext_hex,
        kek_public_key: payload.kek_public_key,
        nonce_hex: payload.nonce_hex,
        user_id: payload.user_id,
        version: payload.version,
        wrapped_dek_hex: payload.wrapped_dek_hex,
    }
}

fn map_blob_request(payload: EncryptedBlobRequest) -> service::SaveEncryptedBlobCommand {
    service::SaveEncryptedBlobCommand {
        algorithm: payload.algorithm,
        ciphertext_hex: payload.ciphertext_hex,
        nonce_hex: payload.nonce_hex,
        version: payload.version,
    }
}

fn map_note_response(note: service::StoredNote) -> NoteResponse {
    NoteResponse {
        id: note.id,
        encrypted_dek: map_wrapped_dek_response(note.encrypted_dek),
        encrypted_payload: map_blob_response(note.encrypted_payload),
        created_at: note.created_at,
        updated_at: note.updated_at,
    }
}

fn map_wrapped_dek_response(blob: service::StoredWrappedDek) -> WrappedDekResponse {
    WrappedDekResponse {
        algorithm: blob.algorithm,
        kem_ciphertext_hex: blob.kem_ciphertext_hex,
        kek_public_key: blob.kek_public_key,
        nonce_hex: blob.nonce_hex,
        user_id: blob.user_id,
        version: blob.version,
        wrapped_dek_hex: blob.wrapped_dek_hex,
    }
}

fn map_blob_response(blob: service::StoredEncryptedBlob) -> EncryptedBlobResponse {
    EncryptedBlobResponse {
        algorithm: blob.algorithm,
        ciphertext_hex: blob.ciphertext_hex,
        nonce_hex: blob.nonce_hex,
        version: blob.version,
    }
}

mod auth;
mod db;
mod handlers;
mod models;
mod routes;
mod state;

use crate::state::AppState;

#[tokio::main]
async fn main() {
    let db = db::connect().await;
    let state = AppState { db };

    let app = routes::create_router(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    println!("listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.unwrap();
}

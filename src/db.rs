use mongodb::{Client, Database};

pub async fn connect() -> Database {
    let client = Client::with_uri_str("mongodb://localhost:27017")
        .await
        .expect("failed to connect to mongodb");

    client.database("axum_auth_demo")
}

use mongodb::{Client, Database};

pub async fn connect(uri: &str) -> Database {
    let client = Client::with_uri_str(uri)
        .await
        .expect("failed to connect to mongodb");

    client.database("axum_auth_demo")
}

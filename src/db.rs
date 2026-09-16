use mongodb::{Client, Database, IndexModel, bson::doc, options::IndexOptions};

pub async fn connect(uri: &str) -> Database {
    let client = Client::with_uri_str(uri)
        .await
        .expect("failed to connect to mongodb");

    let db = client.database("axum_auth_demo");

    let ttl_index = IndexModel::builder()
        .keys(doc! {"expires_at": 1})
        .options(
            IndexOptions::builder()
                .expire_after(std::time::Duration::from_secs(0))
                .build(),
        )
        .build();

    db.collection::<crate::models::RefreshToken>("refresh_tokens")
        .create_index(ttl_index)
        .await
        .expect("failed to create TTL index on refresh_tokens");

    db
}

use github_device_oauth::*;

#[tokio::main]
async fn main() {
    let client_id = std::env::var("GITHUB_CLIENT_ID").unwrap();
    let retrieve_refresh_token =
        || std::env::var("GITHUB_REFRESH_TOKEN").map_err(|_| DeviceFlowError::RefreshTokenNotFound);
    let host = "github.com".to_owned();
    let scopes = "read:user".to_owned();
    let flow = DeviceFlow::new(client_id, host, scopes);
    let cred = flow.auth(retrieve_refresh_token).await.unwrap();
    println!("Access token: {}", cred.access_token);
}

use serde_derive::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;
use tokio::time;

#[derive(Error, Debug)]
pub enum DeviceFlowError {
    #[error(transparent)]
    RequestError(#[from] reqwest::Error),
    #[error("Request failed with status code: {}", .0)]
    RequestFailureError(reqwest::StatusCode),
    #[error("Authorization request expired")]
    AuthRequestExpired,
    #[error("Expired access token")]
    ExpiredAccessTokenError,
    // We want to show the erroneous response in the error message
    // thus we do not use #[from] here
    #[error("Could not deserialize response")]
    DeserializationError(String),
    #[error("Device flow disabled")]
    DeviceFlowDisabled,
    #[error("Incorrect client credentials")]
    IncorrectClientCredentials,
    #[error("Incorrect device code")]
    IncorrectDeviceCode,
    #[error("Access denied")]
    AccessDenied,
    #[error("Unsupported grant type")]
    UnsupportedGrantType,
    #[error("Refresh token not found")]
    RefreshTokenNotFound,
}

#[derive(Serialize, Deserialize, Debug)]
struct VerificationParams {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct AnotherResponse {
    x: i32,
    y: i32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Credentials {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: String,
    pub refresh_token_expires_in: u64,
    pub token_type: String,
    pub scope: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
enum GithubAPIResponse {
    VerificationParams(VerificationParams),
    Credentials(Credentials),
    ErrorResponse(GithubAPIErrorResponse),
}

#[derive(Serialize, Deserialize, Debug)]
struct GithubAPIErrorResponse {
    #[serde(flatten)]
    variant: GithubAPIErrorVariant,
    error_description: String,
    error_uri: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "error", rename_all = "snake_case")]
enum GithubAPIErrorVariant {
    AuthorizationPending,
    SlowDown,
    ExpiredToken,
    UnsupportedGrantType,
    IncorrectClientCredentials,
    IncorrectDeviceCode,
    AccessDenied,
    DeviceFlowDisabled,
}

#[derive(Debug, Clone)]
pub struct DeviceFlow {
    client_id: String,
    host: String,
    scopes: String,
}

impl DeviceFlow {
    pub fn new(client_id: String, host: String, scopes: String) -> Self {
        Self {
            client_id,
            host,
            scopes,
        }
    }

    pub async fn auth(
        &self,
        retrive_refresh_token: impl FnOnce() -> Result<String, DeviceFlowError>,
    ) -> Result<Credentials, DeviceFlowError> {
        let vp = self.request_verification().await?;

        eprintln!("Please enter the code: {}", vp.user_code);
        eprintln!("At the following URL in your browser:");
        eprintln!("{}", vp.verification_uri);

        let res = self
            .request_authorize(&vp, vp.expires_in, vp.interval)
            .await;

        if let Err(DeviceFlowError::ExpiredAccessTokenError) = res {
            let refresh_token = retrive_refresh_token()?;
            self.request_refresh(refresh_token.to_string(), vp.expires_in, vp.interval)
                .await
        } else {
            res
        }
    }

    async fn request_verification(&self) -> Result<VerificationParams, DeviceFlowError> {
        // TODO use serde to build request body
        let r = send_request(
            format!("https:/{}/login/device/code", self.host),
            format!("client_id={}&scope={}", self.client_id, self.scopes),
        )
        .await?;

        use GithubAPIErrorVariant::*;
        use GithubAPIResponse::*;
        let vp_result = match r {
            VerificationParams(vp) => Ok(vp),
            ErrorResponse(e) => match e.variant {
                IncorrectClientCredentials => {
                    return Err(DeviceFlowError::IncorrectClientCredentials)
                }
                DeviceFlowDisabled => return Err(DeviceFlowError::DeviceFlowDisabled),
                _ => unreachable!("This should never be returned by the API"),
            },
            Credentials(_) => unreachable!("This should never be returned by the API"),
        };
        vp_result
    }

    async fn request_authorize(
        &self,
        vp: &VerificationParams,
        expires_in: u64,
        interval: u64,
    ) -> Result<Credentials, DeviceFlowError> {
        let request_url = format!("https:/{}/login/oauth/access_token", self.host);
        let request_body = format!(
            "client_id={}&device_code={}&grant_type=urn:ietf:params:oauth:grant-type:device_code",
            self.client_id, vp.device_code
        );
        poll_token_response(request_url, request_body, expires_in, interval).await
    }

    async fn request_refresh(
        &self,
        refresh_token: String,
        expires_in: u64,
        interval: u64,
    ) -> Result<Credentials, DeviceFlowError> {
        let request_url = format!("https:/{}/login/oauth/access_token", self.host);
        let request_body = format!(
            "client_id={}&grant-type:refresh_token&refresh_token={}",
            self.client_id, refresh_token,
        );
        poll_token_response(request_url, request_body, expires_in, interval).await
    }
}

async fn send_request(
    url: impl AsRef<str>,
    body: String,
) -> Result<GithubAPIResponse, DeviceFlowError> {
    let client = reqwest::Client::new();
    let response = client
        .post(url.as_ref())
        .header("Accept", "application/json")
        .body(body)
        .send()
        .await?
        .error_for_status()?;

    // Try to deserialize to a [`GithubApiResponse`] enum if that fails, dump the response body as
    // a string in the error message
    let body_bytes = response.bytes().await?;
    if let Ok(body) = serde_json::from_slice::<GithubAPIResponse>(&body_bytes) {
        return Ok(body);
    } else {
        let bytes_as_string: String = String::from_utf8_lossy(&body_bytes).to_string();
        return Err(DeviceFlowError::DeserializationError(bytes_as_string));
    }
}

async fn poll_token_response(
    request_url: String,
    request_body: String,
    expires_in: u64,
    interval: u64,
) -> Result<Credentials, DeviceFlowError> {
    /*
     * Do not poll this endpoint at a higher frequency than the frequency indicated by interval. If
     * you do, you will hit the rate limit and receive a slow_down error. The slow_down error
     * response adds 5 seconds to the last interval.
     */
    let mut interval = interval;

    let time_start = std::time::Instant::now();
    while time_start.elapsed().as_secs() < expires_in {
        let r = send_request(&request_url, request_body.clone()).await?;

        use GithubAPIErrorVariant::*;
        use GithubAPIResponse::*;
        match r {
            Credentials(credentials) => return Ok(credentials),
            ErrorResponse(er) => match er.variant {
                AuthorizationPending => time::sleep(Duration::from_secs(interval)).await,
                SlowDown => interval += 5,
                ExpiredToken => return Err(DeviceFlowError::ExpiredAccessTokenError),
                UnsupportedGrantType => return Err(DeviceFlowError::UnsupportedGrantType),
                IncorrectClientCredentials => {
                    return Err(DeviceFlowError::IncorrectClientCredentials)
                }
                IncorrectDeviceCode => return Err(DeviceFlowError::IncorrectDeviceCode),
                AccessDenied => return Err(DeviceFlowError::AccessDenied),
                DeviceFlowDisabled => return Err(DeviceFlowError::DeviceFlowDisabled),
            },
            VerificationParams(_) => unreachable!("This should never be returned by the API"),
        }
    }

    Err(DeviceFlowError::AuthRequestExpired)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_decode_credentials() {
        let payload = r#"{
            "access_token":"secret",
            "expires_in":28800,
            "refresh_token":"secret",
            "token_type":"bearer",
            "refresh_token_expires_in":15811200,
            "scope":""}"#;

        let _ = serde_json::from_str::<GithubAPIResponse>(payload).unwrap();
    }

    #[tokio::test]
    async fn test_decode_verification_params() {
        let payload = r#"{
        "device_code":"AA",
        "user_code":"user-code",
        "verification_uri":"https://example.com/device",
        "expires_in":1800,
        "interval":5
        }"#;

        let _ = serde_json::from_str::<GithubAPIResponse>(payload).unwrap();
    }
}

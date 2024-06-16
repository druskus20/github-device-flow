#![feature(stmt_expr_attributes)]

// More info: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app#using-the-device-flow-to-generate-a-user-access-token

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
    ExpiredTokenError,
    // We want to show the erroneous response in the error message
    // thus we do not use #[from] here
    #[error("Bad refresh token")]
    BadRefreshToken,
    #[error("Unverified user email")]
    UnverifiedUserEmail,
    #[error("Slow down")]
    SlowDown,
    #[error("Authorization pending")]
    AuthorizationPending,
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
    #[error("This error should be unreachable")]
    UnreachableError,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct VerificationParams {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Credentials {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: String,
    pub refresh_token_expires_in: u64,
    pub scope: String,
    pub token_type: String,
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
    BadRefreshToken,
    UnverifiedUserEmail,
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

    pub async fn refresh_or_authorize(
        &self,
        retrive_refresh_token: impl FnOnce() -> Result<String, DeviceFlowError>,
    ) -> Result<Credentials, DeviceFlowError> {
        let authorize_and_verify = || async {
            let vp = self.verify_device().await?;
            eprintln!("Please enter the code: {}", vp.user_code);
            eprintln!("At the following URL in your browser:");
            eprintln!("{}", vp.verification_uri);
            self.authorize(&vp).await
        };

        match retrive_refresh_token() {
            Ok(token) => match self.refresh(token).await {
                Ok(credentials) => Ok(credentials),
                Err(e) => match e {
                    DeviceFlowError::ExpiredTokenError
                    | DeviceFlowError::IncorrectClientCredentials // Will be returned when the refresh token has been replaced with a new one
                    | DeviceFlowError::BadRefreshToken => authorize_and_verify().await,
                    e => Err(e),
                },
            },
            Err(DeviceFlowError::RefreshTokenNotFound) => authorize_and_verify().await,
            Err(e) => Err(e),
        }
    }

    async fn verify_device(&self) -> Result<VerificationParams, DeviceFlowError> {
        // TODO use serde to build request body
        let r = send_request(
            format!("https:/{}/login/device/code", self.host),
            format!("client_id={}&scope={}", self.client_id, self.scopes),
        )
        .await?;

        use GithubAPIErrorVariant::*;
        use GithubAPIResponse::*;
        #[rustfmt::skip]
        let vp_result = match r {
            VerificationParams(vp) => Ok(vp),
            Credentials(_) => Err(DeviceFlowError::UnreachableError),
            ErrorResponse(e) => match e.variant {
                IncorrectClientCredentials => Err(DeviceFlowError::IncorrectClientCredentials),
                DeviceFlowDisabled => Err(DeviceFlowError::DeviceFlowDisabled),
                _ => Err(DeviceFlowError::UnreachableError),
            },
        };
        vp_result
    }

    async fn authorize(&self, vp: &VerificationParams) -> Result<Credentials, DeviceFlowError> {
        let request_url = format!("https:/{}/login/oauth/access_token", self.host);
        let request_body = format!(
            "client_id={}&device_code={}&grant_type=urn:ietf:params:oauth:grant-type:device_code",
            self.client_id, vp.device_code
        );
        /*
         * Do not poll this endpoint at a higher frequency than the frequency indicated by interval. If
         * you do, you will hit the rate limit and receive a slow_down error. The slow_down error
         * response adds 5 seconds to the last interval.
         */
        let mut interval = vp.interval;

        let time_start = std::time::Instant::now();
        while time_start.elapsed().as_secs() < vp.expires_in {
            let r = request_access_token(request_url.clone(), request_body.clone()).await;
            match r {
                Ok(credentials) => return Ok(credentials),
                Err(DeviceFlowError::SlowDown) => interval += 5,
                Err(DeviceFlowError::AuthorizationPending) => {
                    time::sleep(Duration::from_secs(interval)).await;
                }
                r => return r,
            }
        }

        Err(DeviceFlowError::AuthRequestExpired)
    }

    async fn refresh(&self, refresh_token: String) -> Result<Credentials, DeviceFlowError> {
        let request_url = format!("https:/{}/login/oauth/access_token", self.host);
        let request_body = format!(
            "client_id={}&refresh_token={}&client_secret=&grant_type=refresh_token",
            self.client_id, refresh_token
        );

        request_access_token(request_url, request_body.to_string()).await
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
    String::from_utf8_lossy(&body_bytes).to_string();
    if let Ok(body) = serde_json::from_slice::<GithubAPIResponse>(&body_bytes) {
        return Ok(body);
    } else {
        let bytes_as_string: String = String::from_utf8_lossy(&body_bytes).to_string();
        return Err(DeviceFlowError::DeserializationError(bytes_as_string));
    }
}

async fn request_access_token(
    request_url: String,
    request_body: String,
) -> Result<Credentials, DeviceFlowError> {
    let r = send_request(&request_url, request_body.clone()).await?;

    use GithubAPIResponse::*;
    match r {
        Credentials(credentials) => Ok(credentials),
        VerificationParams(_) => Err(DeviceFlowError::UnreachableError),
        ErrorResponse(er) => Err(er.variant.into()),
    }
}

use GithubAPIErrorVariant::*;
impl Into<DeviceFlowError> for GithubAPIErrorVariant {
    fn into(self) -> DeviceFlowError {
        match self {
            AuthorizationPending => DeviceFlowError::AuthorizationPending,
            SlowDown => DeviceFlowError::SlowDown,
            ExpiredToken => DeviceFlowError::ExpiredTokenError,
            UnsupportedGrantType => DeviceFlowError::UnsupportedGrantType,
            IncorrectClientCredentials => DeviceFlowError::IncorrectClientCredentials,
            IncorrectDeviceCode => DeviceFlowError::IncorrectDeviceCode,
            AccessDenied => DeviceFlowError::AccessDenied,
            DeviceFlowDisabled => DeviceFlowError::DeviceFlowDisabled,
            BadRefreshToken => DeviceFlowError::BadRefreshToken,
            UnverifiedUserEmail => DeviceFlowError::UnverifiedUserEmail,
        }
    }
}

impl Credentials {
    pub fn try_to_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
    pub fn try_from_string(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
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

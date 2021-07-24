extern crate oauth2;
extern crate reqwest;
extern crate serde;
extern crate serde_json;

use std::error::Error;
use std::io::Write;

use serde::Deserialize;
// use serde_json;
// use anyhow;
use oauth2::basic::{BasicClient, BasicTokenType};
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, TokenResponse, TokenUrl,
};
// use url::Url;
use text_io::read;
// use futures;

// struct MediaMetadata {
// }
#[derive(Deserialize, Debug)]
struct MediaItem {
id: String,
    productUrl: String,
    baseUrl: String,
    mimeType: String,
    // mediaMetadata: String,
    filename: String,
}

#[derive(Deserialize, Debug)]
struct Response {
    mediaItems: Option<Vec<MediaItem>>,
    nextPageToken: Option<String>,
}

async fn auth() -> Result<impl TokenResponse<BasicTokenType>, Box<dyn Error>> {
    // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
    // token URL.
    let client_id = std::env::var("GOOGLE_CLIENT_ID")?;
    let client_secret = std::env::var("GOOGLE_CLIENT_SECRET")?;
    let client = BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new("https://accounts.google.com/o/oauth2/auth".to_string())?,
        Some(TokenUrl::new(
            "https://oauth2.googleapis.com/token".to_string(),
        )?),
    )
    // Set the URL the user will be redirected to after the authorization process.
    .set_redirect_uri(RedirectUrl::new("urn:ietf:wg:oauth:2.0:oob".to_string())?);

    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        // Set the desired scopes.
        .add_scope(Scope::new(
            "https://www.googleapis.com/auth/photoslibrary.readonly".to_string(),
        ))
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .url();

    // This is the URL you should redirect the user to, in order to trigger the authorization
    // process.
    println!("Browse to: {}", auth_url);

    // Once the user has been redirected to the redirect URL, you'll have access to the
    // authorization code. For security reasons, your code should verify that the `state`
    // parameter returned by the server matches `csrf_state`.

    print!("Paste authorization code here: ");
    std::io::stdout().flush().ok();
    let auth_code = read!("{}\n");

    // Now you can trade it for an access token.
    let token_result = client
        .exchange_code(AuthorizationCode::new(auth_code))
        // Set the PKCE code verifier.
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await?;

    // Unwrapping token_result will either produce a Token or a RequestTokenError.

    Ok(token_result)
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    println!("Hello world!");

    let result = auth().await?;
    let access_token = result.access_token();
    let rest_client = reqwest::Client::new();

    let mut count = 0;
    let mut next_page: Option<String> = None;
    loop {
        let mut request = rest_client
            .get("https://photoslibrary.googleapis.com/v1/mediaItems")
            .bearer_auth(access_token.secret());
        request = match next_page {
            Some(token) => request.query(&[("pageToken", token.as_str()), ("pageSize", "100")]),
            None => request.query(&[("pageSize", "100")])
        };
        let response = rest_client.execute(request.build()?).await?;
        let status = response.status();
        let bytes = response.bytes().await?;

        match serde_json::from_slice::<Response>(&bytes) {
            Ok(body) => {
                count = count + body.mediaItems.map_or(0, |items| items.len());
                next_page = body.nextPageToken;
                if next_page.is_none() {
                    break;
                }
            },
            Err(e) => {
                println!("Error requesting media items. code {}, error {}, text {}", status, e, std::str::from_utf8(&bytes)?);
                println!("Count so far: {}", count);
                break;
            },
        };
        println!("Next page token: {:?}", &next_page);
        println!("Count so far: {}", count);
    }
    println!("number of items in the media library: {}", count);
    Ok(())
}
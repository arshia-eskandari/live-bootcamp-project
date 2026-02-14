mod helpers;
mod login;
mod logout;
mod signup;
mod verify_2fa;
mod verify_token;

pub use login::*;
pub use logout::*;
pub use signup::*;
pub use verify_2fa::*;
pub use verify_token::*;

use crate::prelude::AppState;
use crate::utils::tracing::{make_span_with_request_id, on_request, on_response};
use axum::{routing::post, serve::Serve, Router};
use reqwest::Method;
use std::error::Error;
use tokio::net::TcpListener;
use tower_http::{cors::CorsLayer, services::ServeDir, trace::TraceLayer};

// This struct encapsulates our application-related logic.
pub struct Application {
    server: Serve<TcpListener, Router, Router>,
    // address is exposed as a public field
    // so we have access to it in tests.
    pub address: String,
}

impl Application {
    pub async fn build(app_state: AppState, address: &str) -> Result<Self, Box<dyn Error>> {
        let allowed_origins = [
            "http://localhost:8000".parse()?,
            "http://157.230.191.28:8000".parse()?,
        ];

        let cors = CorsLayer::new()
            // Allow GET and POST requests
            .allow_methods([Method::GET, Method::POST])
            // Allow cookies to be included in requests
            .allow_credentials(true)
            .allow_origin(allowed_origins);
        // Move the Router definition from `main.rs` to here.
        // Also, remove the `hello` route.
        // We don't need it at this point!
        let asset_dir = ServeDir::new("assets");
        let router = Router::new()
            .fallback_service(asset_dir)
            .route("/signup", post(signup))
            .route("/login", post(login))
            .route("/logout", post(logout))
            .route("/verify-2fa", post(verify_2fa))
            .route("/verify-token", post(verify_token))
            .with_state(app_state)
            .layer(cors)
            .layer(
                // New!
                // Add a TraceLayer for HTTP requests to enable detailed tracing
                // This layer will create spans for each request using the make_span_with_request_id function,
                // and log events at the start and end of each request using on_request and on_response functions.
                TraceLayer::new_for_http()
                    .make_span_with(make_span_with_request_id)
                    .on_request(on_request)
                    .on_response(on_response),
            );

        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        // Create a new Application instance and return it
        Ok(Self { server, address })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        tracing::info!("listening on {}", &self.address);
        self.server.await
    }
}

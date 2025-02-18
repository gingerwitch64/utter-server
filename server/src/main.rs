use argon2::{
    password_hash::{Salt, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use redis::{Commands, RedisResult};
use serde::{Deserialize, Serialize};

pub const PREFIX_LOG: &'static str = "[LOG]";
pub const PREFIX_ERROR: &'static str = "[ERROR]";

mod config;
mod util;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/hello_world", get(hello_world))
        // `POST /users` goes to `create_user`
        .route("/users", post(create_user))
        .fallback(handler_404);

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind(
        format!("{}:{}", config::SERVER_IP, config::SERVER_PORT).as_str(),
    )
    .await
    .unwrap();
    axum::serve(listener, app).await.unwrap();
}

// basic handler that responds with a static string
async fn hello_world() -> &'static str {
    "Hello, World!"
}

/// 404 page handler.
async fn handler_404() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "Error 404: Nothing to see here!")
}

// TODO: add actually decent error handling and recovery.
/// Handles password hashing and username based registration.
async fn create_user(
    // this argument tells axum to parse the request body
    // as JSON into a `CreateUser` type
    Json(payload): Json<CreateUserInput>,
) -> (StatusCode, Json<CreateUserOutput>) {
    // SPECIFICIALLY NEEDS rand_core=0.6.4 OsRng!
    let salt_str = SaltString::generate(&mut rand_core::OsRng);
    let salt: Salt = Salt::from(&salt_str);

    // Following RustCrypto guidelines from
    // https://rustcrypto.org/key-derivation/hashing-password.html
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(payload.password.as_str().as_bytes(), salt)
        .unwrap();
    let hash_string = hash.to_string();
    Argon2::default()
        .verify_password(
            payload.password.as_str().as_bytes(),
            &PasswordHash::parse(hash_string.as_str(), argon2::password_hash::Encoding::B64)
                .unwrap(),
        )
        .expect(format!("{} Password hash did not verify", PREFIX_ERROR).as_str());

    let user = CreateUserOutput {
        username: payload.username,
    };

    let client = redis::Client::open(config::REDIS_URL).unwrap();
    let mut con = client.get_connection().unwrap();
    // throw away the result, just make sure it does not fail
    let user_exists_res: RedisResult<isize> = con.hexists("login", &user.username);
    let user_exists: isize = user_exists_res.unwrap();
    match user_exists {
        0 => {
            // CRITICAL TODO: Should add result checking for the NX
            // operation to make sure that the same username didn't
            // just get registered by another operation. -gw
            let _user_add_res: RedisResult<isize> =
                con.hset_nx("login", &user.username, &hash_string);
            println!("{} Register request success!", PREFIX_LOG);
            return (StatusCode::CREATED, Json(user));
        }
        1 => {
            println!("{} Register failure: User exists", PREFIX_ERROR);
            return (StatusCode::CONFLICT, Json(user));
        }
        _ => {
            println!(
                "{} Register failure with RedisResult {}",
                PREFIX_ERROR, user_exists
            );
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(user));
        }
    }
}

/*
async fn generate_token(
    Json(payload): Json<UsernamePasswordInput>,
) -> (StatusCode, Json<GenerateTokenOutput>) {
}
*/

// the input to our `create_user` handler
#[derive(Deserialize)]
struct CreateUserInput {
    username: String,
    password: String,
}

// the output to our `create_user` handler
#[derive(Serialize)]
struct CreateUserOutput {
    username: String,
}

/// For anything that requires direct username and password auth.
#[derive(Deserialize)]
struct UsernamePasswordInput {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct GenerateTokenOutput {
    token: String,
}

use std::time::UNIX_EPOCH;

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

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use mysql::{prelude::*, *};
use serde::{Deserialize, Serialize};

pub const PREFIX_LOG: &'static str = "[LOG]";
pub const PREFIX_ERROR: &'static str = "[ERROR]";

mod config;
mod secret; // NEVER EVER EVER COMMIT YOUR `secret.rs`
mod util;

/// For anything that requires direct username and password auth.
#[derive(Serialize, Deserialize, Debug)]
struct User {
    username: String,
    password: String,
}

impl User {
    fn new(username: String, password: String) -> Self {
        User { username, password }
    }
}

/// Because we love using JSON for single-output use cases!
#[derive(Serialize)]
struct FancyString {
    output: String,
}

impl FancyString {
    fn new(output: String) -> Self {
        FancyString { output }
    }
}

#[derive(Deserialize, Serialize, Debug)]
struct Claims {
    custom_claim: String,
    iss: String,
    sub: String,
    exp: u64,
    iat: u64,
    user_id: u64,
}

fn trim_quotes(text: String) -> String {
    text.trim_matches('\'').to_string()
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/hello_world", get(hello_world))
        // `POST /users` goes to `create_user`
        .route("/users", post(create_user))
        .route("/login", post(generate_token))
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
    // as JSON into a `User` type
    Json(payload): Json<User>,
) -> (StatusCode, Json<User>) {
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

    let user = User::new(payload.username, payload.password);

    let pool = Pool::new(secret::DB_URL).unwrap();
    let mut conn = pool.get_conn().unwrap();
    let user_exists_res: Vec<_> = conn
        .exec(
            r"SELECT EXISTS(SELECT 1 FROM Login WHERE username = ? );",
            (&user.username,),
        )
        .unwrap();
    let user_exists: u8 = user_exists_res[0];
    println!("{}", user_exists);
    match user_exists {
        0 => {
            conn.exec_drop(
                r"INSERT INTO Login (username, password) VALUES (:username, :hash_string)",
                params! { "username" => &user.username, hash_string },
            )
            .unwrap();
            println!("{} Register request success!", PREFIX_LOG);
            return (StatusCode::CREATED, Json(user));
        }
        1 => {
            println!("{} Register failure: User exists", PREFIX_ERROR);
            return (StatusCode::CONFLICT, Json(user));
        }
        _ => {
            println!(
                "{} Register failure with Output {}",
                PREFIX_ERROR, user_exists
            );
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(user));
        }
    }
}

async fn generate_token(Json(payload): Json<User>) -> (StatusCode, Json<FancyString>) {
    let pool = Pool::new(secret::DB_URL).unwrap();
    let mut conn = pool.get_conn().unwrap();
    let user_exists_res: Vec<_> = conn
        .exec_iter(
            r"SELECT * FROM Login WHERE username = ?;",
            (&payload.username,),
        )
        .unwrap()
        .map(|x| x.unwrap())
        .collect();

    // Woah! Either you don't exist, or you exist too much. NEXTTT!!!
    if user_exists_res.len() != 1 {
        let error_string = format!(
            "{} Login returned count other than one user: {}",
            PREFIX_ERROR,
            user_exists_res.len()
        );
        println!("{}", error_string);
        return (StatusCode::CONFLICT, Json(FancyString::new(error_string)));
    }

    let parts: Vec<_> = user_exists_res[0]
        .clone()
        .unwrap()
        .iter()
        .map(|x| trim_quotes(x.as_sql(true)))
        .collect();
    let user = User::new(parts[0].to_string(), parts[1].to_string());

    let password_fail: bool = Argon2::default()
        .verify_password(
            payload.password.as_str().as_bytes(),
            &PasswordHash::parse(
                &user.password.as_str(),
                argon2::password_hash::Encoding::B64,
            )
            .unwrap(),
        )
        .is_err();
    if password_fail {
        let error_string = format!(
            "{} Password authentication failed for: {}",
            PREFIX_ERROR, &user.username
        );
        //println!("{}", error_string);
        return (
            StatusCode::UNAUTHORIZED,
            Json(FancyString::new(error_string)),
        );
    }

    // from article:
    // https://medium.com/@cuongta/how-to-encode-and-decode-jwt-using-rust-51f3b757e212
    // create exp time
    let now = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let now_plus_60_days = std::time::SystemTime::now()
        .checked_add(std::time::Duration::from_secs(60 * 60 * 60 * 24))
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // create the claim
    let c = Claims {
        custom_claim: "".to_owned(),
        iss: config::JWT_ISS.to_owned(),
        sub: user.username.to_owned(),
        iat: now,
        exp: now_plus_60_days,
        user_id: 0,
    };

    // create the header
    let header = jsonwebtoken::Header::default();

    // create the encoding key using the secret string
    let secret_key = jsonwebtoken::EncodingKey::from_secret(secret::JWT_SECRET);

    // encode token
    let res = jsonwebtoken::encode(&header, &c, &secret_key).unwrap();

    println!("{}", verify_token(res.clone()));

    return (StatusCode::OK, Json(FancyString::new(res)));
}

fn verify_token(token: String) -> bool {
    let token_message = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(secret::JWT_SECRET),
        &Validation::new(Algorithm::HS256),
    );
    token_message.is_ok()
}

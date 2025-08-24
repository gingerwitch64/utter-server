//use std::fs::{File, *};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;
use std::time::UNIX_EPOCH;
use std::{fs, fs::File};

use argon2::{
    password_hash::{Salt, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use axum::{
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Query},
    http::{
        header::{HeaderMap, AUTHORIZATION, CONTENT_TYPE},
        StatusCode,
    },
    response::{Html, IntoResponse},
    routing::{get, post, put},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use mysql::{prelude::*, *};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
        .route("/echo", post(echo))
        .route("/image/{*key}", get(serve_image))
        .route("/upload/image", put(upload_image))
        .layer(DefaultBodyLimit::max(config::MAX_UPLOAD_SIZE))
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

/// Echoes the body.
async fn echo(body: Bytes) -> impl IntoResponse {
    (StatusCode::OK, body)
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
    let header = Header::default();

    // create the encoding key using the secret string
    let secret_key = EncodingKey::from_secret(secret::JWT_SECRET);

    // encode token
    let res = encode(&header, &c, &secret_key).unwrap();

    println!("{}", verify_token(res.clone()));

    return (StatusCode::OK, Json(FancyString::new(res)));
}

async fn upload_image(headers: HeaderMap, body: Bytes) -> impl IntoResponse {
    if !headers.contains_key(AUTHORIZATION) {
        if !verify_token(headers[AUTHORIZATION].to_str().unwrap().to_string()) {
            return (StatusCode::UNAUTHORIZED, "Token is invalid.".to_string());
        }
    }
    // the following if statement is technically uneeded
    if body.len() > config::MAX_UPLOAD_SIZE {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "Payload too large. Max upload size is {} Bytes.",
                config::MAX_UPLOAD_SIZE
            ),
        );
    }
    if !headers.contains_key(CONTENT_TYPE) {
        return (StatusCode::BAD_REQUEST, "Missing Content-Type.".to_string());
    }
    let content_type_trim = headers[CONTENT_TYPE]
        .to_str()
        .unwrap()
        .trim_start_matches("image/");
    let file_extension = match content_type_trim {
        "apng" | "avif" | "gif" | "png" | "webp" => content_type_trim,
        "jpeg" | "jpg" => "jpg",
        "svg+xml" => "svg",
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                format!(
                    "Invalid Content-Type {}.",
                    headers[CONTENT_TYPE].to_str().unwrap()
                ),
            )
        }
    };
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let file_hash_b64 = URL_SAFE_NO_PAD.encode(hasher.finalize());
    let f_location = Path::new(config::UPLOAD_PATH)
        .join("images")
        .join(format!("{}.{}", file_hash_b64, file_extension));
    if f_location.exists() {
        return (StatusCode::CREATED, format!(""));
    }
    fs::create_dir_all(f_location.clone().parent().unwrap()).unwrap();
    let mut file = File::create(f_location).unwrap();
    file.write_all(&body).unwrap();

    return (StatusCode::CREATED, format!(""));
}

async fn serve_image(
    axum::extract::Path(path): axum::extract::Path<String>,
) -> axum::response::Response {
    let f_location = Path::new(config::UPLOAD_PATH)
        .join("images")
        .join(format!("{}", path));
    if !f_location.is_file() {
        return axum::response::Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(
                format!("{} was not found on this server.", path)
                    .try_into()
                    .unwrap(),
            )
            .unwrap();
    }
    let mut body_image: Vec<u8> = Vec::new();
    let f_loc_2 = f_location.clone();
    let file_extension = f_loc_2.extension().unwrap().to_str().unwrap();
    File::open(f_location).unwrap().read(&mut body_image);

    let file_type = format!(
        "image/{}",
        match file_extension {
            "apng" | "avif" | "gif" | "png" | "webp" => {
                file_extension
            }
            "jpeg" | "jpg" => "jpeg",
            "svg" => "svg+xml",
            _ => {
                return axum::response::Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header(CONTENT_TYPE, "text/plain; charset=utf-8")
                    .body(
                        format!("{} is not a valid image extension.", file_extension)
                            .try_into()
                            .unwrap(),
                    )
                    .unwrap();
            }
        }
    );
    return axum::response::Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, file_type)
        .body(body_image.try_into().unwrap())
        .unwrap();
}

/*
pub async fn upload(mut multipart: Multipart) -> impl IntoResponse {
    while let Some(field) = multipart.next_field().await.unwrap() {
        let filename = if let Some(filename) = field.file_name() {
            filename.to_string()
        } else {
            continue;
        };

        let body_with_io_error = field.map_err(|err| io::Error::new(io::ErrorKind::Other, err));

        let body_reader = StreamReader::new(body_with_io_error);

        futures::pin_mut!(body_reader);

        //put_file(bucket, &filename, body_reader);

        return (StatusCode::CREATED, "OK".to_string());
    }

    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Internal Server Error".to_string(),
    )
}
*/

/// Verifies a JWT token using the server's JWT secret. Will trim `Bearer` from any bearer token strings automatically.
/// Returns true if the token is valid.
fn verify_token(token: String) -> bool {
    let token_message = decode::<Claims>(
        &token.trim_start_matches("Bearer "),
        &DecodingKey::from_secret(secret::JWT_SECRET),
        &Validation::new(Algorithm::HS256),
    );
    token_message.is_ok()
}

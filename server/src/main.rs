use std::str::FromStr;

use argon2::{
    password_hash::{PasswordHashString, SaltString},
    Argon2, PasswordHasher, PasswordVerifier,
};
use axum::{
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use redis::{Commands, RedisResult};
use serde::{Deserialize, Serialize};

pub const PREFIX_LOG: &'static str = "[LOG]";
pub const PREFIX_ERROR: &'static str = "[ERROR]";

mod config;

/*
#[derive(Deserialize)]
struct Config {
    utter_server: ServerConfig,
    redis: RedisConfig,
}

#[derive(Deserialize)]
struct ServerConfig {
    ip: Option<String>,
    port: Option<u16>,
}

#[derive(Deserialize)]
struct RedisConfig {
    hostname: Option<String>,
    port: Option<u16>,
    username: Option<String>,
    password: Option<String>,
}

fn load_config(file_path: String) -> Config {
    let config_contents: String = fs::read_to_string(file_path.clone()).expect(
        format!(
            "{} Could not read config file from: {}",
            PREFIX_ERROR, file_path
        )
        .as_str(),
    );
    let mut config: Config = toml::from_str(config_contents.as_str()).unwrap();
    config
}
*/

#[tokio::main]
async fn main() {
    //let config = load_config("./utter.server.config.toml".to_string());
    let app = Router::new()
        .route("/hello_world", get(hello_world))
        // `POST /users` goes to `create_user`
        .route("/users", post(create_user));

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

async fn create_user(
    // this argument tells axum to parse the request body
    // as JSON into a `CreateUser` type
    Json(payload): Json<CreateUser>,
) -> (StatusCode, Json<User>) {
    // SPECIFICIALLY NEEDS rand_core=0.6.4 OsRng!
    let salt = SaltString::generate(&mut rand_core::OsRng).as_salt();

    // Following RustCrypto guidelines from
    // https://rustcrypto.org/key-derivation/hashing-password.html
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(payload.password.as_str().as_bytes(), salt)
        .unwrap();
    Argon2::default()
        .verify_password(
            payload.password.as_str().as_bytes(),
            &PasswordHashString::from_str(hash.to_string().as_str()),
        )
        .expect("msg");

    let user = User {
        username: payload.username,
        hash_str: hash.to_string(),
    };

    let client = redis::Client::open(config::REDIS_URL).unwrap();
    let mut con = client.get_connection().unwrap();
    // throw away the result, just make sure it does not fail
    let user_exists = con.hexists("login", user.username);
    let hres: RedisResult<isize> = con.hset_nx("login", user.username);
    // read back the key and return it.  Because the return value
    // from the function is a result for integer this will automatically
    // convert into one.
    //let _res: redis::RedisResult<isize> = con.get("my_key");

    // this will be converted into a JSON response
    // with a status code of `201 Created`
    (StatusCode::CREATED, Json(user))
}

// the input to our `create_user` handler
// Wait... why do we define a struct as our input?
// Nevermind, this is fine :p -gw
#[derive(Deserialize)]
struct CreateUser {
    username: String,
    password: String,
}

// the output to our `create_user` handler
#[derive(Serialize)]
struct User {
    username: String,
    hash_str: String,
}

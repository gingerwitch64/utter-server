use argon2::{
    password_hash::{Salt, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
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

// TODO: add actually decent error handling and recovery.
/// Handles password hashing and username based registration.
async fn create_user(
    // this argument tells axum to parse the request body
    // as JSON into a `CreateUser` type
    Json(payload): Json<CreateUser>,
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
    let pass_string_hash = hash.to_string();
    Argon2::default()
        .verify_password(
            payload.password.as_str().as_bytes(),
            &PasswordHash::parse(
                pass_string_hash.as_str(),
                argon2::password_hash::Encoding::B64,
            )
            .unwrap(),
        )
        .expect(format!("{} Password hash did not verify", PREFIX_ERROR).as_str());

    let user = User {
        username: payload.username,
        hash_str: hash.to_string(),
    };

    let client = redis::Client::open(config::REDIS_URL).unwrap();
    let mut con = client.get_connection().unwrap();
    // throw away the result, just make sure it does not fail
    let user_exists_res: RedisResult<isize> = con.hexists("login", &user.username);
    let user_exists: isize = user_exists_res.unwrap();
    match user_exists {
        0 => {
            let _user_add_res: RedisResult<isize> =
                con.hset_nx("login", &user.username, &user.hash_str);
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

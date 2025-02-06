use axum::{
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use redis::Commands;
use serde::{Deserialize, Serialize};
use std::fs;

pub const PREFIX_LOG: &'static str = "[LOG]";
pub const PREFIX_ERROR: &'static str = "[ERROR]";

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

#[tokio::main]
async fn main() {
    let config = load_config("./utter.server.config.toml".to_string());
    let app = Router::new()
        .route("/hello_world", get(hello_world))
        // `POST /users` goes to `create_user`
        .route("/users", post(create_user));

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind(
        format!(
            "{}:{}",
            config.utter_server.ip.unwrap_or("0.0.0.0".to_string()),
            config.utter_server.port.unwrap_or(3000)
        )
        .as_str(),
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
    // This is cryptographically secure.
    let mut rng = StdRng::from_os_rng();

    let user = User {
        id: rng.next_u64(),
        // Json items can be accessed using
        // this dot syntax. -gw
        username: payload.username,
        password: payload.password,
    };

    let client = redis::Client::open("redis://127.0.0.1/").unwrap();
    let mut con = client.get_connection().unwrap();
    // throw away the result, just make sure it does not fail
    let _: () = con.set("my_key", 42).unwrap();
    // read back the key and return it.  Because the return value
    // from the function is a result for integer this will automatically
    // convert into one.
    let _res: redis::RedisResult<isize> = con.get("my_key");

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
    id: u64,
    username: String,
    password: String,
}

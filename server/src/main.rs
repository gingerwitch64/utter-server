use axum::{
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/hello_world", get(hello_world))
        // `POST /users` goes to `create_user`
        .route("/users", post(create_user));

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
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

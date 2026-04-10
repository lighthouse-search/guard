//! Example websocket server.
//!
//! Run the server with
//! ```not_rust
//! cargo run -p example-websockets --bin example-websockets
//! ```
//!
//! Run a browser client with
//! ```not_rust
//! firefox http://localhost:3000
//! ```
//!
//! Alternatively you can run the rust client (showing two
//! concurrent websocket connections being established) with
//! ```not_rust
//! cargo run -p example-websockets --bin example-client
//! ```

use axum::{
    body::Bytes,
    extract::{
        ws::{Message, Utf8Bytes, WebSocket, WebSocketUpgrade},
        connect_info::ConnectInfo,
        Request,
        State,
    },
    http::{HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use axum_extra::{TypedHeader, extract::CookieJar, headers};

use std::ops::ControlFlow;
use std::net::SocketAddr;

use axum::extract::ws::CloseFrame;
use futures_util::{sink::SinkExt, stream::StreamExt};

use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;

use serde_json::{json, Value};

use crate::{CONFIG_VALUE, hostname::get_current_valid_hostname, users::user_authentication_pipeline};

pub async fn http_handler(State(client): State<Client<HttpConnector, axum::body::Body>>, jar: CookieJar, ConnectInfo(remote_addr): ConnectInfo<SocketAddr>, headers: axum::http::HeaderMap, mut req: Request) -> Response {
    let path = req.uri().path().to_string();

    // TODO: If no user credentials are provided, redirect to login.

    let mut header_to_use: String = "host".to_string();

    let req_headers = req.headers().clone();

    let hostname = match get_current_valid_hostname(req_headers.clone(), Some(header_to_use)).await {
        Some(h) => h,
        None => return (StatusCode::BAD_REQUEST, "Invalid or missing hostname.").into_response(),
    };

    let user_authentication = user_authentication_pipeline(vec!["access_applications"], &&crate::global::jar_to_indexmap(&jar), remote_addr.to_string(), hostname.domain_port.clone(), &req_headers.clone()).await;

    // TODO: In the future athentication_method won't be returned as optional from user_authentication_pipelne (user_authentication_pipeline will be changed to from truple to Result<>). This is a temporary fix :)
    if user_authentication.is_ok() == true {
        let user_authentication_unwrapped = user_authentication.unwrap();
        
        let user_result = user_authentication_unwrapped.user;
        let authentication_method_wrapped = user_authentication_unwrapped.authentication_method;
        let user = user_result.unwrap();
        let authentication_method = authentication_method_wrapped.unwrap();

        // let user_get_id_preference = user_get_id_preference(user.clone(), authentication_method.clone()).expect("Failed to get user_get_id_preference");

        // TODO: This is wildly messy, I'll fix it.

        let mut device: Option<Value> = None;
        if user_authentication_unwrapped.device.is_none() == false {
            let device_unwrapped = user_authentication_unwrapped.device.unwrap();
            device = Some(json!({
                "id": device_unwrapped.id
            }));
        }

        // TODO: Need to pass a JWT with authentication data in headers.

        let mut proxy_to = hostname.hostname.proxy_to.expect(&format!("Missing hostname.proxy_to in {}", hostname.hostname.host));

        if proxy_to.starts_with("https://") == false && proxy_to.starts_with("http://") == false {
            log::warn!("Appending https://. proxy_to doesn't specify protocol. Changed from {} to {}", proxy_to, format!("https://{}", proxy_to));
            proxy_to = format!("https://{}", proxy_to);
        }
        let mut proxy_to_url = url::Url::parse(
            &proxy_to
        ).expect("Failed to parse proxy_to url");
        proxy_to_url.set_path(&path);
        proxy_to_url.set_query(req.uri().query());

        if proxy_to_url.scheme() == "http" {
            log::warn!("Using http:// ({}) proxy destination. It's really important you use an HTTPS connection with a trusted certificate whenever possible otherwise you are vulnerable to man-in-the-middle attacks.", hostname.original_url)
        }

        *req.uri_mut() = Uri::try_from(proxy_to_url.as_str()).unwrap();

        // Check Max-Forwards to detect proxy loops.
        if let Some(max_forwards_val) = req.headers().get("max-forwards") {
            if let Ok(val_str) = max_forwards_val.to_str() {
                if let Ok(val) = val_str.trim().parse::<u32>() {
                    if val == 0 {
                        return (StatusCode::LOOP_DETECTED, "Loop detected: Max-Forwards limit reached.").into_response();
                    }
                    req.headers_mut().insert(
                        axum::http::header::HeaderName::from_static("max-forwards"),
                        HeaderValue::from_str(&(val - 1).to_string()).unwrap(),
                    );
                }
            }
        }

        // Set X-Forwarded-For, appending the client IP to any existing chain.
        let client_ip = remote_addr.ip().to_string();
        let xff = match req.headers().get("x-forwarded-for") {
            Some(existing) => format!("{}, {}", existing.to_str().unwrap_or(""), client_ip),
            None => client_ip,
        };
        req.headers_mut().insert(
            axum::http::header::HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_str(&xff).unwrap_or_else(|_| HeaderValue::from_static("unknown")),
        );

        // TODO: Remove Guard authentication data.

        // TODO: Check max-forwards header in the client response here.
        return client
            .request(req)
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY).expect("Something went wrong with the upstream")
            .into_response();
    } else if user_authentication.is_err() {
        return user_authentication.err().unwrap();
    }
    
    // This should never happen because user_authentication should always return an error if not successful.
    return (
        axum::http::StatusCode::UNAUTHORIZED,
        "Unauthorized.",
    ).into_response();
}

// /// The handler for the HTTP request (this gets called when the HTTP request lands at the start
// /// of websocket negotiation). After this completes, the actual switching from HTTP to
// /// websocket protocol will occur.
// /// This is the last point where we can extract TCP/IP metadata such as IP address of the client
// /// as well as things from HTTP headers such as user-agent of the browser etc.
// pub async fn ws_handler(
//     ws: WebSocketUpgrade,
//     user_agent: Option<TypedHeader<headers::UserAgent>>,
//     ConnectInfo(addr): ConnectInfo<SocketAddr>,
// ) -> impl IntoResponse {
//     let user_agent = if let Some(TypedHeader(user_agent)) = user_agent {
//         user_agent.to_string()
//     } else {
//         String::from("Unknown browser")
//     };
//     println!("`{user_agent}` at {addr} connected.");
//     // finalize the upgrade process by returning upgrade callback.
//     // we can customize the callback by sending additional info such as address.
//     ws.on_upgrade(move |socket| handle_socket(socket, addr))
// }

// /// Actual websocket statemachine (one will be spawned per connection)
// async fn handle_socket(mut socket: WebSocket, who: SocketAddr) {
//     // send a ping (unsupported by some browsers) just to kick things off and get a response
//     if socket
//         .send(Message::Ping(Bytes::from_static(&[1, 2, 3])))
//         .await
//         .is_ok()
//     {
//         println!("Pinged {who}...");
//     } else {
//         println!("Could not send ping {who}!");
//         // no Error here since the only thing we can do is to close the connection.
//         // If we can not send messages, there is no way to salvage the statemachine anyway.
//         return;
//     }

//     // receive single message from a client (we can either receive or send with socket).
//     // this will likely be the Pong for our Ping or a hello message from client.
//     // waiting for message from a client will block this task, but will not block other client's
//     // connections.
//     if let Some(msg) = socket.recv().await {
//         if let Ok(msg) = msg {
//             if process_message(msg, who).is_break() {
//                 return;
//             }
//         } else {
//             println!("client {who} abruptly disconnected");
//             return;
//         }
//     }

//     // Since each client gets individual statemachine, we can pause handling
//     // when necessary to wait for some external event (in this case illustrated by sleeping).
//     // Waiting for this client to finish getting its greetings does not prevent other clients from
//     // connecting to server and receiving their greetings.
//     for i in 1..5 {
//         if socket
//             .send(Message::Text(format!("Hi {i} times!").into()))
//             .await
//             .is_err()
//         {
//             println!("client {who} abruptly disconnected");
//             return;
//         }
//         tokio::time::sleep(std::time::Duration::from_millis(100)).await;
//     }

//     // By splitting socket we can send and receive at the same time. In this example we will send
//     // unsolicited messages to client based on some sort of server's internal event (i.e .timer).
//     let (mut sender, mut receiver) = socket.split();

//     // Spawn a task that will push several messages to the client (does not matter what client does)
//     let mut send_task = tokio::spawn(async move {
//         let n_msg = 20;
//         for i in 0..n_msg {
//             // In case of any websocket error, we exit.
//             if sender
//                 .send(Message::Text(format!("Server message {i} ...").into()))
//                 .await
//                 .is_err()
//             {
//                 return i;
//             }

//             tokio::time::sleep(std::time::Duration::from_millis(300)).await;
//         }

//         println!("Sending close to {who}...");
//         if let Err(e) = sender
//             .send(Message::Close(Some(CloseFrame {
//                 code: axum::extract::ws::close_code::NORMAL,
//                 reason: Utf8Bytes::from_static("Goodbye"),
//             })))
//             .await
//         {
//             println!("Could not send Close due to {e}, probably it is ok?");
//         }
//         n_msg
//     });

//     // This second task will receive messages from client and print them on server console
//     let mut recv_task = tokio::spawn(async move {
//         let mut cnt = 0;
//         while let Some(Ok(msg)) = receiver.next().await {
//             cnt += 1;
//             // print message and break if instructed to do so
//             if process_message(msg, who).is_break() {
//                 break;
//             }
//         }
//         cnt
//     });

//     // If any one of the tasks exit, abort the other.
//     tokio::select! {
//         rv_a = (&mut send_task) => {
//             match rv_a {
//                 Ok(a) => println!("{a} messages sent to {who}"),
//                 Err(a) => println!("Error sending messages {a:?}")
//             }
//             recv_task.abort();
//         },
//         rv_b = (&mut recv_task) => {
//             match rv_b {
//                 Ok(b) => println!("Received {b} messages"),
//                 Err(b) => println!("Error receiving messages {b:?}")
//             }
//             send_task.abort();
//         }
//     }

//     // returning from the handler closes the websocket connection
//     println!("Websocket context {who} destroyed");
// }

// /// helper to print contents of messages to stdout. Has special treatment for Close.
// fn process_message(msg: Message, who: SocketAddr) -> ControlFlow<(), ()> {
//     match msg {
//         Message::Text(t) => {
//             println!(">>> {who} sent str: {t:?}");
//         }
//         Message::Binary(d) => {
//             println!(">>> {who} sent {} bytes: {d:?}", d.len());
//         }
//         Message::Close(c) => {
//             if let Some(cf) = c {
//                 println!(
//                     ">>> {who} sent close with code {} and reason `{}`",
//                     cf.code, cf.reason
//                 );
//             } else {
//                 println!(">>> {who} somehow sent close message without CloseFrame");
//             }
//             return ControlFlow::Break(());
//         }

//         Message::Pong(v) => {
//             println!(">>> {who} sent pong with {v:?}");
//         }
//         // You should never need to manually handle Message::Ping, as axum's websocket library
//         // will do so for you automagically by replying with Pong and copying the v according to
//         // spec. But if you need the contents of the pings you can see them here.
//         Message::Ping(v) => {
//             println!(">>> {who} sent ping with {v:?}");
//         }
//     }
//     ControlFlow::Continue(())
// }
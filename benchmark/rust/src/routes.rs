use actix_web::{web, HttpResponse, Responder};
use crate::services::*;
use smallvec;
use hyper;
use regex;
use time;
use tokio;

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .route("/user", web::get().to(get_user))
            .route("/ping", web::get().to(ping))
            .route("/read", web::get().to(read_file))
            .route("/fetch", web::get().to(fetch_url))
            .route("/hash", web::get().to(hash_data))
            .route("/buy", web::post().to(buy_item))
            .route("/profile", web::get().to(view_profile))
            .route("/unsafe", web::post().to(unsafe_op))
            .route("/parse", web::post().to(parse_json))
            .route("/sca", web::get().to(sca_op))
    );
}

async fn get_user(req: web::Query<std::collections::HashMap<String, String>>) -> impl Responder {
    let id = req.get("id").unwrap();
    db::fetch_user(id);
    HttpResponse::Ok().body("User fetched")
}

async fn ping(req: web::Query<std::collections::HashMap<String, String>>) -> impl Responder {
    let ip = req.get("ip").unwrap();
    system::run_ping(ip);
    HttpResponse::Ok().body("Ping executed")
}

async fn read_file(req: web::Query<std::collections::HashMap<String, String>>) -> impl Responder {
    let file = req.get("file").unwrap();
    file::read(file);
    HttpResponse::Ok().body("File read")
}

async fn fetch_url(req: web::Query<std::collections::HashMap<String, String>>) -> impl Responder {
    let url = req.get("url").unwrap();
    http::fetch(url).await;
    HttpResponse::Ok().body("URL fetched")
}

async fn hash_data(req: web::Query<std::collections::HashMap<String, String>>) -> impl Responder {
    let data = req.get("data").unwrap();
    crypto::hash(data);
    crypto::encrypt_data(data);
    HttpResponse::Ok().body("Hashed")
}

async fn buy_item(req: web::Query<std::collections::HashMap<String, String>>) -> impl Responder {
    let quantity: i32 = req.get("quantity").unwrap().parse().unwrap();
    logic::buy(quantity);
    HttpResponse::Ok().body("Bought")
}

async fn view_profile(req: web::Query<std::collections::HashMap<String, String>>) -> impl Responder {
    let profile_id = req.get("id").unwrap();
    logic::profile(profile_id);
    HttpResponse::Ok().body("Profile viewed")
}

async fn unsafe_op(body: web::Bytes) -> impl Responder {
    unsafe_mem::process_data(&body);
    HttpResponse::Ok().body("Processed")
}

async fn parse_json(body: web::Bytes) -> impl Responder {
    deserialize::load_data(&body);
    HttpResponse::Ok().body("Parsed")
}

async fn sca_op(req: web::Query<std::collections::HashMap<String, String>>) -> impl Responder {
    let payload = req.get("payload").unwrap_or(&String::from("")).to_string();
    
    // smallvec
    let _ = smallvec::SmallVec::<[u8; 8]>::from_vec(payload.clone().into_bytes());
    
    // hyper
    let _ = hyper::Uri::builder().authority(payload.as_str()).build();
    
    // regex
    let _ = regex::Regex::new(&payload);
    
    // time
    // using time 0.2 syntax or whatever is imported, assume parse
    let _ = time::Date::parse(&payload, time::macros::format_description!("%Y-%m-%d")); // Fallback if old version
    
    // tokio
    let _ = tokio::fs::read_to_string(&payload);
    
    HttpResponse::Ok().body("SCA Executed")
}

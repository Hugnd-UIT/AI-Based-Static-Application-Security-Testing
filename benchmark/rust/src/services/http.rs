pub async fn fetch(url: &str) {
    // Server-Side Request Forgery [CWE-918]
    let _ = reqwest::get(url).await;
}

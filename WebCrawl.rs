use clap::{App, Arg};
use reqwest::header::HeaderMap;
use url::Url;
use scraper::{Html, Selector};
use std::collections::{HashSet, HashMap};
use tokio::{task, sync::{Semaphore, Mutex}};
use std::sync::Arc;
use regex::Regex;

// Function to extract HTTP & HTTPS headers
async fn get_headers(url: &str) -> Result<HeaderMap, reqwest::Error> {
    let client = reqwest::Client::new();
    let response = client.get(url).send().await?;
    Ok(response.headers().clone())
}

// Function to extract links from the HTML content
fn extract_links(body: &str) -> Vec<String> {
    let document = Html::parse_document(body);
    let selector = Selector::parse("a[href]").unwrap();
    let mut links = Vec::new();

    for element in document.select(&selector) {
        if let Some(link) = element.value().attr("href") {
            links.push(link.to_string());
        }
    }
    links
}

// Check for common vulnerabilities in HTTP headers
fn check_for_vulnerabilities(headers: &HeaderMap, url: &str) {
    // Check for missing security headers
    if headers.get("X-Content-Type-Options").is_none() {
        println!("[!] Missing X-Content-Type-Options header on {}", url);
    }

    if headers.get("Strict-Transport-Security").is_none() {
        println!("[!] Missing Strict-Transport-Security header on {}", url);
    }

    if headers.get("Content-Security-Policy").is_none() {
        println!("[!] Missing Content-Security-Policy header on {}", url);
    }

    if let Some(server) = headers.get("Server") {
        let server_value = server.to_str().unwrap_or("");
        if server_value.contains("Apache/2.4") {
            println!("[!] Outdated Apache server detected on {}", url);
        }
    }

    if let Some(x_powered_by) = headers.get("X-Powered-By") {
        let version = x_powered_by.to_str().unwrap_or("");
        if version.contains("PHP/7") {
            println!("[!] Possible outdated PHP version detected on {}", url);
        }
    }
}

// Asynchronous function to crawl a page and process its content
async fn crawl_page(url: &str, semaphore: Arc<Semaphore>, visited: &mut HashSet<String>, depth: u32) {
    let _permit = semaphore.acquire().await.unwrap();

    // Use Arc<Mutex<HashSet<String>>> for concurrency safety
    let visited_mutex = visited.clone();
    let mut visited_guard = visited_mutex.lock().await;
    if visited_guard.contains(url) || depth == 0 {
        return;
    }
    visited_guard.insert(url.to_string());
    drop(visited_guard);

    println!("[*] Crawling: {}", url);

    // Fetch page content and headers
    match reqwest::get(url).await {
        Ok(res) => {
            let body = match res.text().await {
                Ok(b) => b,
                Err(_) => {
                    println!("[!] Error reading body: {}", url);
                    return;
                }
            };
            let headers = res.headers().clone();

            // Check for vulnerabilities in headers
            check_for_vulnerabilities(&headers, url);

            // Extract links from the page
            let links = extract_links(&body);

            // Crawl each link concurrently
            let next_depth = depth - 1;
            for link in links {
                // Use url crate for proper link resolution
                let full_url = match Url::parse(url) {
                    Ok(base) => base.join(&link).map(|u| u.to_string()).unwrap_or(link),
                    Err(_) => link,
                };

                let semaphore_clone = semaphore.clone();
                let visited_clone = visited.clone();
                task::spawn(async move {
                    crawl_page(&full_url, semaphore_clone, visited_clone, next_depth).await;
                });
            }
        }
        Err(_) => {
            println!("[!] Error fetching: {}", url);
        }
    }
}

// Parse command-line arguments
fn parse_args() -> (String, u32) {
    let matches = App::new("VulnCrawler")
        .version("1.0")
        .author("Your Name")
        .about("A simple web crawler to check for security vulnerabilities")
        .arg(
            Arg::new("url")
                .short('u')
                .long("url")
                .takes_value(true)
                .required(true)
                .help("Starting URL to crawl"),
        )
        .arg(
            Arg::new("depth")
                .short('d')
                .long("depth")
                .takes_value(true)
                .default_value("2")
                .help("Depth of crawling (default is 2)"),
        )
        .get_matches();

    let url = matches.value_of("url").unwrap().to_string();
    let depth: u32 = matches.value_of_t("depth").unwrap();

    (url, depth)
}

#[tokio::main]
async fn main() {
    // Parse the command-line arguments
    let (start_url, crawl_depth) = parse_args();

    // Set a limit for concurrent tasks (to avoid overwhelming the target site)
    let semaphore = Arc::new(Semaphore::new(10)); // Limit to 10 concurrent tasks

    // Track visited URLs to avoid revisiting the same page (thread-safe)
    let visited = Arc::new(Mutex::new(HashSet::new()));

    // Start crawling from the specified site URL
    crawl_page(&start_url, semaphore.clone(), visited.clone(), crawl_depth).await;

    println!("[*] Crawling complete!");
}

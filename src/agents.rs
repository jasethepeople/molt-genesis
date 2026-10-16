use crate::store::TaskDraft;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use std::io::Read;
use std::time::Duration;

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: [Message<'a>; 2],
    temperature: f32,
    response_format: Value,
}

#[derive(Serialize)]
struct Message<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ResponseMessage,
}

#[derive(Deserialize)]
struct ResponseMessage {
    content: Option<String>,
}

#[derive(Deserialize)]
struct PlanResponse {
    tasks: Vec<PlanTask>,
}

#[derive(Deserialize)]
struct PlanTask {
    description: String,
    role: String,
    #[serde(default)]
    depends_on: Vec<usize>,
}

#[derive(Deserialize)]
pub struct CodeResponse {
    pub source: String,
    pub tests: String,
    pub limitation: Option<String>,
}

pub fn plan(objective: &str) -> Result<Vec<TaskDraft>> {
    if objective.trim().is_empty() || objective.len() > 2000 {
        bail!("Objective must be between 1 and 2,000 characters");
    }
    let system = "You are the planning role in a local Rust implementation system. Decompose the operator's objective into 1 to 8 small, verifiable Rust implementation tasks. Return only a JSON object: {\"tasks\":[{\"description\":\"...\",\"role\":\"Engineer\",\"depends_on\":[]}]} . Every task role must be Engineer; Architect planning and Auditor checks are runtime responsibilities, not generated tasks. Dependencies are zero-based indices into earlier tasks only; task 0 has no dependencies. Do not claim to run tools or tests.";
    let raw = chat(system, objective)?;
    let parsed: PlanResponse = serde_json::from_str(&raw)
        .context("Architect response was not valid JSON for a task plan")?;
    if parsed.tasks.is_empty() || parsed.tasks.len() > 8 {
        bail!("Architect returned an unsupported number of tasks");
    }
    let drafts: Vec<TaskDraft> = parsed
        .tasks
        .into_iter()
        .map(|t| TaskDraft {
            description: t.description,
            role: t.role,
            dependencies: t.depends_on,
        })
        .collect();
    for (i, task) in drafts.iter().enumerate() {
        if task.dependencies.iter().any(|&dep| dep >= i) {
            bail!("Architect returned a dependency that is not an earlier task; rejected the plan");
        }
    }
    Ok(drafts)
}

pub fn generate_code(description: &str) -> Result<CodeResponse> {
    let system = "You are the Engineer role. Return only a JSON object with string fields `source`, `tests`, and optional `limitation`. `source` must be a self-contained Rust 2021 module using only the standard library, with no crate-level attributes, no dependencies, no build scripts, and no unsafe code. Implement the requested behavior for real; never return mocks, simulations, stubs, or placeholders. `tests` must contain meaningful Rust #[test] functions that exercise the public items in source; these items are appended at crate root, so do not use `use super::*`. Do not include Markdown fences. If the task cannot be implemented honestly within these constraints, return empty source and tests and explain the blocker in `limitation`; do not invent a substitute.";
    let user = format!("Implement this approved-scope task as a Rust module and meaningful unit tests:\n\n{description}");
    let raw = chat(system, &user)?;
    let result: CodeResponse = serde_json::from_str(&raw)
        .context("Engineer response was not valid JSON with source and tests")?;
    if let Some(limitation) = result
        .limitation
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        bail!("Engineer could not implement this task: {limitation}");
    }
    if result.source.trim().is_empty() || result.tests.trim().is_empty() {
        bail!("Engineer returned empty source or tests; no placeholder patch was saved");
    }
    Ok(result)
}

fn chat(system: &str, user: &str) -> Result<String> {
    let base = env::var("MOLT_OPENAI_BASE_URL")
        .unwrap_or_else(|_| "https://api.openai.com/v1".to_string());
    let base_url = url::Url::parse(&base).context("MOLT_OPENAI_BASE_URL is not a valid URL")?;
    let local_host = base_url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if base_url.username() != ""
        || base_url.password().is_some()
        || base_url.query().is_some()
        || base_url.fragment().is_some()
        || !(base_url.scheme() == "https" || (base_url.scheme() == "http" && local_host))
    {
        bail!("MOLT_OPENAI_BASE_URL must use HTTPS (plain HTTP is allowed only for loopback hosts; URL credentials/query/fragment are forbidden)");
    }
    let base = base_url.as_str().trim_end_matches('/').to_string();
    let model = env::var("MOLT_MODEL").unwrap_or_else(|_| "gpt-4.1-mini".to_string());
    let key = env::var("MOLT_API_KEY")
        .or_else(|_| env::var("OPENAI_API_KEY"))
        .ok();
    if key.is_none() && !local_host {
        bail!(
            "No model credential found. Set MOLT_API_KEY or OPENAI_API_KEY in your secret store."
        );
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let body = ChatRequest {
        model: &model,
        messages: [
            Message {
                role: "system",
                content: system,
            },
            Message {
                role: "user",
                content: user,
            },
        ],
        temperature: 0.0,
        response_format: json!({"type": "json_object"}),
    };
    let mut request = client.post(format!("{base}/chat/completions")).json(&body);
    if let Some(key) = key.as_deref() {
        request = request.bearer_auth(key);
    }
    let response = request.send().context("Model API request failed")?;
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > 2_000_000)
    {
        bail!("Model API response exceeds the 2 MB limit");
    }
    let mut bytes = Vec::new();
    response
        .take(2_000_001)
        .read_to_end(&mut bytes)
        .context("Could not read model response")?;
    if bytes.len() > 2_000_000 {
        bail!("Model API response exceeds the 2 MB limit");
    }
    let text = String::from_utf8(bytes).context("Model API response was not UTF-8")?;
    if !status.is_success() {
        let excerpt: String = text.chars().take(1000).collect();
        bail!("Model API returned HTTP {status}: {excerpt}");
    }
    let response: ChatResponse =
        serde_json::from_str(&text).context("Model API returned malformed response JSON")?;
    let content = response
        .choices
        .into_iter()
        .next()
        .and_then(|choice| choice.message.content)
        .context("Model API returned no message content")?;
    let content = content.trim();
    let content = content
        .strip_prefix("```json")
        .and_then(|s| s.strip_suffix("```"))
        .or_else(|| {
            content
                .strip_prefix("```")
                .and_then(|s| s.strip_suffix("```"))
        })
        .unwrap_or(content)
        .trim();
    Ok(content.to_string())
}

//! The hostnames the proxy engine needs before it can do anything.
//!
//! The engine cannot start without an address for each of its own nodes, and it
//! cannot be used to fetch a subscription it has not fetched yet. Those hostnames
//! therefore have to resolve through a path that does not depend on the engine -
//! otherwise the dependency is circular and the tunnel simply never comes up,
//! which looks like "the proxy is broken" rather than "a domain is routed wrong".
//!
//! This only collects the requirements. Deciding whether they *are* satisfied
//! needs the DNS rule engine, so the check itself lives with the leak report.

use std::net::IpAddr;

use serde_json::Value;

/// One hostname the engine must resolve, and where the requirement comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineHostname {
    pub hostname: String,
    /// What needs it: a node, a provider, a subscription. Several nodes sharing a
    /// hostname produce separate entries, so the report can say which.
    pub source: String,
}

/// Whether a `server` field is a name rather than an address.
///
/// An IP literal needs no resolution, so it is not a bootstrap requirement.
fn is_hostname(value: &str) -> bool {
    !value.is_empty() && value.parse::<IpAddr>().is_err()
}

/// The host out of a URL, if it has one.
fn host_of(url: &str) -> Option<String> {
    url::Url::parse(url).ok().and_then(|parsed| parsed.host_str().map(str::to_string))
}

/// Collect every hostname the engine has to resolve.
///
/// `generated_config` is the engine's own rendered configuration - the thing it
/// will actually read - rather than the plugin's inputs, because the two can
/// differ and it is the rendered one that decides whether the engine starts.
/// `subscription_urls` come from the plugin configuration, since fetching them is
/// what does not require the engine.
pub fn engine_hostnames(
    generated_config: Option<&Value>,
    subscription_urls: &[(String, String)],
) -> Vec<EngineHostname> {
    let mut found: Vec<EngineHostname> = Vec::new();
    let mut note = |hostname: String, source: String| {
        let entry = EngineHostname { hostname, source };
        if !found.contains(&entry) {
            found.push(entry);
        }
    };

    if let Some(config) = generated_config {
        for proxy in config.get("proxies").and_then(Value::as_array).unwrap_or(&Vec::new()) {
            let Some(server) = proxy.get("server").and_then(Value::as_str) else { continue };
            if is_hostname(server) {
                let name = proxy.get("name").and_then(Value::as_str).unwrap_or("unnamed");
                note(server.to_string(), format!("node {name:?}"));
            }
        }

        // A provider's URL is fetched by the engine, so its host is a requirement
        // for the same reason a node's is.
        for (name, provider) in
            config.get("proxy-providers").and_then(Value::as_object).into_iter().flatten()
        {
            if let Some(host) = provider.get("url").and_then(Value::as_str).and_then(host_of) {
                note(host, format!("provider {name:?}"));
            }
        }
    }

    for (name, url) in subscription_urls {
        if let Some(host) = host_of(url) {
            note(host, format!("subscription {name:?}"));
        }
    }

    found.sort_by(|a, b| (&a.hostname, &a.source).cmp(&(&b.hostname, &b.source)));
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Value {
        serde_json::json!({
            "proxies": [
                {"name": "node-a", "server": "a.example.com"},
                {"name": "node-b", "server": "1.2.3.4"},
                {"name": "node-c", "server": "b.example.com"},
                {"name": "node-d", "server": "b.example.com"}
            ],
            "proxy-providers": {
                "sub": {"url": "https://sub.example.net/list?token=x"}
            }
        })
    }

    #[test]
    fn ip_literals_are_not_requirements() {
        // An address needs no resolution, so requiring one would be noise.
        let found = engine_hostnames(Some(&config()), &[]);
        assert!(!found.iter().any(|entry| entry.hostname == "1.2.3.4"));
    }

    #[test]
    fn every_hostname_is_reported_with_its_source() {
        let found = engine_hostnames(
            Some(&config()),
            &[("my-sub".to_string(), "https://sub.example.org/feed".to_string())],
        );
        let pairs: Vec<(&str, &str)> =
            found.iter().map(|entry| (entry.hostname.as_str(), entry.source.as_str())).collect();
        assert_eq!(
            pairs,
            vec![
                ("a.example.com", "node \"node-a\""),
                ("b.example.com", "node \"node-c\""),
                ("b.example.com", "node \"node-d\""),
                ("sub.example.net", "provider \"sub\""),
                ("sub.example.org", "subscription \"my-sub\""),
            ]
        );
    }

    #[test]
    fn a_missing_or_unreadable_config_yields_no_requirements() {
        // The caller reports that it could not read the rendered config rather
        // than pretending the engine needs nothing.
        assert!(engine_hostnames(None, &[]).is_empty());
    }
}

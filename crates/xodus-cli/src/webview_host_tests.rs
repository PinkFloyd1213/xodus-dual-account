use super::*;

#[test]
fn hosted_signin_both_legs_keep_all_nine_headers_and_exact_targets() {
    let first = login_request("synthetic-client".into(), "en-US".into());
    let url = "https://login.live.com/ppsecure/inlineconnect.srf?synthetic=quoted%20value";
    let second = finalize_request(url.into());
    assert_eq!(first.url, "https://login.live.com/ppsecure/InlineLogin.srf?id=80604&scid=3&mkt=en-US&Platform=Windows10&clientid=synthetic-client&hosted=1");
    assert_eq!(second.url, url);
    assert_eq!(first.headers.len(), 9);
    assert_eq!(second.headers.len(), 9);
    for name in ["cxh-capabilities", "cxh-msabinaryversion", "cxh-identityclientbinaryversion",
        "cxh-osversioninfo", "cxh-platform", "cxh-protocol", "cxh-source", "hostapp"] {
        assert!(first.headers.contains_key(name), "missing first-leg {name}");
        assert_eq!(first.headers[name], second.headers[name], "second-leg {name}");
    }
    assert_eq!(second.headers["hostapp"], "CloudExperienceHost");
    assert_eq!(second.headers["cxh-protocol"], "TokenBroker");
    assert_eq!(second.headers["cxh-source"], "TokenBroker");
}

#[test]
fn hosted_signin_correlation_is_a_fresh_uuid_for_every_request() {
    let first = login_request("synthetic-client".into(), "en-US".into());
    let second = finalize_request("https://login.live.com/finish".into());
    let third = finalize_request("https://login.live.com/finish".into());
    let ids = [&first, &second, &third].map(|request| {
        let value = request.headers["cxh-correlationid"].to_str().unwrap();
        let id = uuid::Uuid::parse_str(value).unwrap();
        assert_eq!(id.get_version_num(), 4);
        id
    });
    assert_ne!(ids[0], ids[1]);
    assert_ne!(ids[1], ids[2]);
    assert_ne!(ids[0], ids[2]);
}

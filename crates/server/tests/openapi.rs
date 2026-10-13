//! `docs/openapi.json` is the generated spec, committed: rewrite it with
//! `UPDATE_GOLDEN=1` (`make golden`) and review the diff.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

#[test]
fn the_committed_spec_matches_the_code() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/openapi.json");
    let actual = format!("{}\n", wgate_server::openapi().to_pretty_json().unwrap());
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, &actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path).expect("docs/openapi.json (UPDATE_GOLDEN=1)");
    assert!(
        actual == expected,
        "docs/openapi.json is stale: run `make golden`"
    );
}

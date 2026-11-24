use super::*;
use std::io::Write;

/// Build a fictional OSV all.zip.
fn make_zip(path: &Path, advisories: &[serde_json::Value]) {
    let f = std::fs::File::create(path).unwrap();
    let mut z = zip::ZipWriter::new(f);
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for a in advisories {
        z.start_file(format!("{}.json", a["id"].as_str().unwrap()), opts)
            .unwrap();
        z.write_all(a.to_string().as_bytes()).unwrap();
    }
    z.finish().unwrap();
}

fn fixtures() -> Vec<serde_json::Value> {
    use serde_json::json;
    vec![
        json!({"id": "GHSA-fake-0001", "summary": "Prototype pollution (fictional)", "aliases": ["CVE-2099-0001"],
               "database_specific": {"severity": "HIGH"},
               "affected": [{"package": {"ecosystem": "npm", "name": "fakelib"},
                             "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]}),
        json!({"id": "GHSA-fake-0002", "summary": "RCE in 2.x (fictional)", "database_specific": {"severity": "CRITICAL"},
               "affected": [{"package": {"ecosystem": "npm", "name": "fakelib"},
                             "ranges": [{"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"last_affected": "2.3.1"}]}]}]}),
        json!({"id": "MAL-2099-1", "summary": "Malicious code in evil-pkg (fictional)",
               "affected": [{"package": {"ecosystem": "npm", "name": "Evil-Pkg"}, "versions": ["1.0.0", "1.0.1"]}]}),
        json!({"id": "MAL-2099-2", "summary": "Malicious package (all versions, fictional)",
               "affected": [{"package": {"ecosystem": "npm", "name": "always-evil"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]}),
        json!({"id": "GHSA-fake-0003", "summary": "withdrawn", "withdrawn": "2099-01-01T00:00:00Z",
               "affected": [{"package": {"ecosystem": "npm", "name": "withdrawnlib"}, "versions": ["1.0.0"]}]}),
    ]
}

#[test]
fn version_compare() {
    use Ordering::*;
    assert_eq!(compare_versions("1.2.3", "1.2.3"), Equal);
    assert_eq!(compare_versions("1.2", "1.2.0"), Equal);
    assert_eq!(compare_versions("1.10.0", "1.9.9"), Greater);
    assert_eq!(compare_versions("1.0.0-rc1", "1.0.0"), Less);
    assert_eq!(compare_versions("1.0.0-alpha", "1.0.0-beta"), Less);
    assert_eq!(compare_versions("v2.0.0", "2.0.0"), Equal);
    assert_eq!(compare_versions("4.17.20", "4.17.21"), Less);
    assert_eq!(compare_versions("2.0.0+build5", "2.0.0"), Equal);
    assert_eq!(
        compare_versions("1.0.post1", "1.0"),
        Less,
        "approximation: alpha suffix sorts below (documented)"
    );
}

#[test]
fn exact_versions() {
    for v in ["1.2.3", "v4.17.21", "=2.0.0", "0.27"] {
        assert!(is_exact_version(v), "{v}");
    }
    for v in ["^4.0", "~1.2", ">=1", "1.x", "latest", "*", ""] {
        assert!(!is_exact_version(v), "{v}");
    }
}

#[test]
fn import_and_lookup() {
    let dir = tempfile::tempdir().unwrap();
    let zip = dir.path().join("all.zip");
    make_zip(&zip, &fixtures());
    let mut db = OsvDb::open(&dir.path().join("osv.db")).unwrap();
    assert_eq!(
        db.import_zip("npm", &zip).unwrap(),
        4,
        "withdrawn advisory skipped"
    );
    // Affected pinned version.
    let a = db.lookup("npm", "fakelib", Some("4.17.20")).unwrap();
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].id, "GHSA-fake-0001");
    assert_eq!(a[0].fixed_in, vec!["4.17.21"]);
    // Fixed version.
    assert!(
        db.lookup("npm", "fakelib", Some("4.17.21"))
            .unwrap()
            .is_empty()
    );
    // last_affected range.
    let b = db.lookup("npm", "fakelib", Some("2.3.1")).unwrap();
    assert!(b.iter().any(|x| x.id == "GHSA-fake-0002"));
    assert!(
        !db.lookup("npm", "fakelib", Some("2.3.2"))
            .unwrap()
            .iter()
            .any(|x| x.id == "GHSA-fake-0002")
    );
    // Malicious: exact listed version, case-insensitive name.
    assert!(db.lookup("npm", "evil-pkg", Some("1.0.1")).unwrap()[0].malicious);
    // Malicious regardless of version (unpinned install).
    assert!(db.lookup("npm", "always-evil", None).unwrap()[0].malicious);
    assert!(db.lookup("npm", "evil-pkg", None).unwrap()[0].malicious);
    // Unpinned install of a package whose advisories are all fixed: nothing reported.
    assert!(db.lookup("npm", "fakelib", None).unwrap().is_empty());
    // Range constraint is not an exact version -> treated as unpinned.
    assert!(
        db.lookup("npm", "fakelib", Some("^4.0"))
            .unwrap()
            .is_empty()
    );
    // Unknown package.
    assert!(
        db.lookup("npm", "left-pad-fake", Some("1.0.0"))
            .unwrap()
            .is_empty()
    );
    let st = db.status(dir.path()).unwrap();
    assert!(st.enabled && !st.stale);
    assert_eq!(
        st.ecosystems
            .iter()
            .find(|e| e.ecosystem == "npm")
            .unwrap()
            .advisories,
        4
    );
    // Re-import replaces, doesn't duplicate.
    db.import_zip("npm", &zip).unwrap();
    assert_eq!(db.status(dir.path()).unwrap().ecosystems[0].advisories, 4);
}

#[test]
fn findings_text_and_scores() {
    let mal = Advisory {
        id: "MAL-1".into(),
        summary: String::new(),
        severity: "unknown".into(),
        malicious: true,
        aliases: vec![],
        fixed_in: vec![],
    };
    let f = findings("npm", "x", None, &[mal], Some("2099-01-01"));
    assert_eq!(f[0].id, "supply.known_malicious_package");
    assert!(f[0].score >= 95);
    let v = Advisory {
        id: "GHSA-1".into(),
        summary: String::new(),
        severity: "high".into(),
        malicious: false,
        aliases: vec!["CVE-2099-1".into()],
        fixed_in: vec!["1.2.4".into()],
    };
    let f = findings("npm", "x", Some("1.2.3"), &[v], None);
    assert_eq!(f[0].id, "supply.known_vulnerability");
    assert_eq!(f[0].score, 75);
    assert!(f[0].explanation.contains("CVE-2099-1"));
    assert!(f[0].mitigation.as_deref().unwrap().contains("1.2.4"));
}

#[test]
fn pypi_name_normalization() {
    assert_eq!(normalize_name("PyPI", "Foo_Bar.baz"), "foo-bar-baz");
    assert_eq!(normalize_name("npm", "@Scope/Pkg"), "@scope/pkg");
}

#[test]
fn shared_advisory_survives_reimport_of_other_ecosystem() {
    use serde_json::json;
    let dir = tempfile::tempdir().unwrap();
    let mut db = OsvDb::open(&dir.path().join("osv.db")).unwrap();
    // One advisory affecting packages in two ecosystems (fictional).
    let shared = json!({"id": "GHSA-shared-1", "summary": "fictional", "affected": [
        {"package": {"ecosystem": "npm", "name": "dual"}, "versions": ["1.0.0"]},
        {"package": {"ecosystem": "PyPI", "name": "dual"}, "versions": ["1.0.0"]}]});
    db.import_advisories("npm", std::slice::from_ref(&shared))
        .unwrap();
    db.import_advisories("PyPI", std::slice::from_ref(&shared))
        .unwrap();
    // Re-import PyPI without the advisory: npm must still find it.
    db.import_advisories("PyPI", &[]).ok();
    assert_eq!(db.lookup("npm", "dual", Some("1.0.0")).unwrap().len(), 1);
    let st = db.status(dir.path()).unwrap();
    assert_eq!(
        st.ecosystems
            .iter()
            .find(|e| e.ecosystem == "npm")
            .unwrap()
            .advisories,
        1
    );
}

#[test]
fn old_schema_is_rebuilt() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("osv.db");
    {
        let c = rusqlite::Connection::open(&p).unwrap();
        c.execute_batch("CREATE TABLE adv (id TEXT PRIMARY KEY, ecosystem TEXT); INSERT INTO adv VALUES ('x','npm');").unwrap();
    }
    let db = OsvDb::open(&p).unwrap();
    assert!(!db.status(dir.path()).unwrap().enabled);
}

#[test]
fn aliases_are_deduplicated() {
    use serde_json::json;
    let dir = tempfile::tempdir().unwrap();
    let mut db = OsvDb::open(&dir.path().join("osv.db")).unwrap();
    db.import_advisories("PyPI", &[
        json!({"id": "GHSA-dup-1", "aliases": ["CVE-2099-5"], "database_specific": {"severity": "HIGH"}, "affected": [{"package": {"ecosystem": "PyPI", "name": "pkg"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}]}),
        json!({"id": "PYSEC-dup-1", "aliases": ["CVE-2099-5", "GHSA-dup-1"], "affected": [{"package": {"ecosystem": "PyPI", "name": "pkg"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}]}),
    ]).unwrap();
    let a = db.lookup("PyPI", "pkg", Some("1.0")).unwrap();
    assert_eq!(a.len(), 1, "{a:?}");
    assert_eq!(a[0].severity, "high");
}

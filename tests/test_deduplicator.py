from implementation.processors.deduplicator import _ioc_key, _merge_cves, _merge_iocs


def test_url_host_is_case_insensitive():
    assert _ioc_key({'type': 'url', 'value': 'https://EXAMPLE.COM/Path?q=A'}) == _ioc_key(
        {'type': 'url', 'value': 'https://example.com/Path?q=A'})


def test_url_path_query_and_credentials_preserve_case():
    original = 'https://User:Secret@example.com/Path?q=A'
    for changed in [original.replace('/Path', '/path'), original.replace('q=A', 'q=a'),
                    original.replace('Secret', 'secret')]:
        assert _ioc_key({'type': 'url', 'value': original}) != _ioc_key(
            {'type': 'url', 'value': changed})


def test_domains_and_hashes_are_case_insensitive():
    for kind in ['domain', 'hash_sha256']:
        assert _ioc_key({'type': kind, 'value': ' ABC '}) == _ioc_key(
            {'type': kind, 'value': 'abc'})


def test_distinct_url_paths_are_not_merged():
    records = [{'type': 'url', 'value': url} for url in
               ['https://example.com/A', 'https://example.com/a']]
    assert len(_merge_iocs(records)) == 2


def test_sources_are_sorted_and_existing_provenance_survives():
    records = [
        {'type': 'domain', 'value': 'example.com', 'source': 'z', 'sources': ['a']},
        {'type': 'domain', 'value': 'example.com', 'source': 'b'},
    ]
    merged = _merge_iocs(records)[0]
    assert merged['sources'] == ['a', 'b', 'z']
    assert merged['source'] == 'a'


def test_cves_without_sources_do_not_crash():
    assert _merge_cves([{'id': 'CVE-2026-1234'}, {'id': 'CVE-2026-1234'}])[0]['sources'] == []


def test_cve_provenance_keeps_kev_confirmation():
    merged = _merge_cves([
        {'id': 'CVE-2026-1234', 'source': 'nvd', 'sources': ['cisa_kev']},
        {'id': 'CVE-2026-1234', 'source': 'other'},
    ])[0]
    assert merged['sources'] == ['cisa_kev', 'nvd', 'other']
    assert merged['kev_confirmed'] is True

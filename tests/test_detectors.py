from proveit.detectors import MAX_SCANNED_LINES, detector_names, scan_added_lines


def test_clean_lines_pass():
    result = scan_added_lines([("diff", 1, "def public_func(): return 1")])
    assert result.findings == ()
    assert result.lines_scanned == 1


def test_curated_detector_matches_without_leaking_content():
    result = scan_added_lines([("diff", 7, 'api_key = "AKIA\x49OSFODNN7EXAMPLE"')])
    assert len(result.findings) == 1
    evidence = result.as_evidence()
    assert evidence[0]["kind"] == "aws_access_key"
    assert evidence[0]["origin"] == "diff"
    assert evidence[0]["line"] == 7
    assert "AKIA\x49OSFODNN7EXAMPLE" not in str(evidence)


def test_high_entropy_token():
    result = scan_added_lines([("untracked:a.txt", 3, "value = aZ9pQ2xLmN8vR4tY6wB1kS5dF0hJ")])
    assert any(f.kind == "high_entropy_token" for f in result.findings)


def test_hex_token_is_not_flagged():
    result = scan_added_lines([("diff", 1, "digest = 0123456789abcdef0123456789abcdef")])
    assert result.findings == ()


def test_line_count_is_bounded():
    lines = (("diff", i, "x = 1") for i in range(100_000))
    result = scan_added_lines(lines)
    assert result.lines_scanned == MAX_SCANNED_LINES + 1


def test_finding_count_is_bounded():
    lines = [(f"untracked:f{i}.txt", 1, 'api_key = "AKIA\x49OSFODNN7EXAMPLE"') for i in range(200)]
    result = scan_added_lines(lines)
    assert len(result.findings) == 64


def test_detector_catalog_is_explicit():
    assert "high_entropy_token" in detector_names()
    assert "private_key" in detector_names()

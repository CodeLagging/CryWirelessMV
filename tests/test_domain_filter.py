"""Behaviour tests for DomainFilter matching against seeded block-list files."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.APCC.domain_filter import DomainFilter


def _seed(tmp_path, name, lines):
    (tmp_path / name).write_text("\n".join(lines) + "\n")
    return DomainFilter(tmp_path)


def test_is_filtered_exact_and_subdomain(tmp_path):
    df = _seed(tmp_path, "block.txt", ["ads.example.com", "*.tracker.com"])
    assert df.is_filtered("ads.example.com") is True
    assert df.is_filtered("sub.tracker.com") is True          # bare-wildcard match
    assert df.is_filtered("notblocked.com") is False


def test_is_filtered_matches_parent_suffix(tmp_path):
    df = _seed(tmp_path, "block.txt", ["doubleclick.net"])
    # a subdomain is filtered because a parent suffix is blocked
    assert df.is_filtered("ad.doubleclick.net") is True


def test_hosts_file_lines_are_parsed(tmp_path):
    df = _seed(tmp_path, "hosts.txt", ["0.0.0.0 malware.test", "# a comment", ""])
    assert df.is_filtered("malware.test") is True


def test_disabled_file_does_not_match(tmp_path):
    df = _seed(tmp_path, "block.txt", ["ads.example.com"])
    df.set_file_enabled("block.txt", False)
    assert df.is_filtered("ads.example.com") is False


def test_describe_files_reports_counts(tmp_path):
    df = _seed(tmp_path, "block.txt", ["a.com", "b.com", "c.com"])
    files = {f[0]: f for f in df.describe_files()}
    assert "block.txt" in files
    # describe_files row: (name, enabled, count, errors)
    assert files["block.txt"][2] == 3


def test_raw_patterns_for_file(tmp_path):
    df = _seed(tmp_path, "block.txt", ["a.com", "*.b.com"])
    raws = df.raw_patterns_for_file("block.txt")
    assert "a.com" in raws and "*.b.com" in raws


def test_empty_domain_is_not_filtered(tmp_path):
    df = _seed(tmp_path, "block.txt", ["a.com"])
    assert df.is_filtered("") is False

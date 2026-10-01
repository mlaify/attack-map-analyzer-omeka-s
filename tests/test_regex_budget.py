"""Every module-level regex in this analyzer stays linear on hostile input
(mlaify/AttackMap#236): one long line in a scanned repo must not stall CI."""

from __future__ import annotations

import re
import time

import pytest

from attackmap_analyzer_omeka_s import analyzer

PAYLOADS = {
    "long_word": "a" * 50_000,
    "long_namespace": "A\\" * 25_000,
    "long_quote": '"' + "A" * 50_000,
    "dotted": "a." * 25_000,
    "url_like": "https://" + "a" * 50_000,
}


def _patterns():
    found = []
    for attr, value in vars(analyzer).items():
        values = value if isinstance(value, (list, tuple)) else [value]
        found += [(f"{attr}[{i}]", v) for i, v in enumerate(values) if isinstance(v, re.Pattern)]
    return found


@pytest.mark.parametrize("name,pattern", _patterns(), ids=[n for n, _ in _patterns()])
def test_pattern_within_budget(name: str, pattern: re.Pattern[str]) -> None:
    for label, payload in PAYLOADS.items():
        start = time.perf_counter()
        list(pattern.finditer(payload))
        elapsed = time.perf_counter() - start
        assert elapsed < 0.1, f"{name} backtracks on {label}: {elapsed:.2f}s"


def test_service_class_refs_still_detected() -> None:
    sample = "'factories' => [Application\\Service\\MailService::class => Factory::class, Foo::class]"
    names = [m.group(1) for m in analyzer.SERVICE_PATTERN.finditer(sample) if analyzer._SERVICE_WORD.search(m.group(1))]
    assert names == ["Application\\Service\\MailService"]

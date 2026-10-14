import sys
import threading
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE.parents[1]))

from config import Settings  # noqa: E402
from llm import LLMClient, LLMResult  # noqa: E402
from projects.prj_03_deal_closer import b2b_sniper as bs  # noqa: E402
from projects.prj_03_deal_closer.pipeline import start_fixture_server  # noqa: E402

BAD = (HERE / "fixtures" / "bad_site.html").read_text()
GOOD = (HERE / "fixtures" / "good_site.html").read_text()


def fake_fr(html, ttfb=0.1, total=0.2, compressed=True):
    return bs.FetchResult("https://x.test/", 200, ttfb, total, len(html), len(html), compressed, True, {}, html)


def test_parse_bad_page():
    p = bs.parse_page(BAD)
    assert p["h1_count"] == 2 and p["blocking_scripts"] == 4 and not p["viewport"] and not p["meta_description"]
    assert p["images"] == 5 and p["images_missing_alt"] == 4
    assert max(p["form_fields"]) == 10 and len(p["generic_ctas"]) >= 3 and not p["social_proof"]


def test_parse_good_page():
    p = bs.parse_page(GOOD)
    assert p["viewport"] and p["meta_description"] and p["h1_count"] == 1 and p["social_proof"] and p["has_structured_data"]
    assert p["blocking_scripts"] == 0 and p["has_phone_or_email_link"]


def test_diagnose_flags_and_ranks():
    f, s = bs.diagnose(fake_fr(BAD, ttfb=1.3), bs.parse_page(BAD))
    kws = {x.keyword for x in f}
    assert {"server", "mobile", "form", "social proof", "meta description"} <= kws
    assert [x.severity for x in f] == sorted((x.severity for x in f), reverse=True)
    assert s["overall"] < 40
    g, gs = bs.diagnose(fake_fr(GOOD), bs.parse_page(GOOD))
    assert gs["overall"] > 90 and len(g) <= 1


def test_template_outreach_under_limit_and_valid():
    f, _ = bs.diagnose(fake_fr(BAD, ttfb=1.3), bs.parse_page(BAD))
    t = bs.template_outreach("Dana", "Northwind", f, "Alex")
    assert bs.word_count(t) < bs.MAX_WORDS
    assert bs.validate_outreach(t, "Dana", f) == []


def test_template_trims_when_findings_are_long():
    long = [bs.Finding("seo", 3, "k", "d", " ".join(["word"] * 40)) for _ in range(3)]
    assert bs.word_count(bs.template_outreach("Dana", "Co", long, "A")) <= bs.MAX_WORDS


def test_validation_rejects_bad_drafts():
    f = [bs.Finding("seo", 3, "mobile", "d", "no viewport")]
    assert any("words" in e for e in bs.validate_outreach("Dana " + "w " * 120 + "?", "Dana", f))
    assert any("CEO" in e for e in bs.validate_outreach("Hello mobile?", "Dana", f))
    assert any("placeholder" in e for e in bs.validate_outreach("Hi Dana [Company] mobile?", "Dana", f))
    assert any("question" in e for e in bs.validate_outreach("Hi Dana, mobile broken.", "Dana", f))


class BadLLM:
    """Returns an over-long draft first, then a valid one."""
    def __init__(self):
        self.calls = 0

    def complete(self, prompt, system="", fallback="", max_tokens=0):
        self.calls += 1
        text = "Hi Dana " + "blah " * 150 + "?" if self.calls == 1 else "Hi Dana, your site has no mobile viewport tag. Worth a look? - Alex"
        return LLMResult(text, "fake", "m", live=True)


def test_llm_retry_then_accept():
    f = [bs.Finding("seo", 3, "mobile", "No viewport", "there is no mobile viewport tag")]
    llm = BadLLM()
    text, meta = bs.generate_outreach(llm, "https://x.test", "Dana", "X", f)
    assert llm.calls == 2 and meta["source"] == "llm" and bs.word_count(text) < 110


def test_llm_never_valid_falls_back_to_template():
    class Always:
        def complete(self, *a, **k):
            return LLMResult("nope " * 300, "fake", "m", live=True)
    f = [bs.Finding("seo", 3, "mobile", "No viewport", "there is no mobile viewport tag")]
    text, meta = bs.generate_outreach(Always(), "https://x.test", "Dana", "X", f)
    assert meta["source"] == "template" and bs.word_count(text) < 110


@pytest.mark.parametrize("url", ["ftp://example.com", "http://127.0.0.1/", "http://169.254.169.254/latest", "http://localhost:8080"])
def test_ssrf_guard(url):
    with pytest.raises(bs.UnsafeURL):
        bs.check_url_safe(url)


def test_end_to_end_against_local_fixture():
    srv, base = start_fixture_server()
    try:
        offline = LLMClient(Settings(provider="offline"))
        r = bs.run_sniper(f"{base}/good", "Priya", "Contoso", llm=offline, allow_private=True)
        assert r["status"] == 200 and r["performance"]["compressed"] and r["scores"]["overall"] > 90
        assert r["outreach_words"] < 110
    finally:
        srv.shutdown()

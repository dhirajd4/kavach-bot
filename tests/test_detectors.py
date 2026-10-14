import pytest

from kavach.detectors.text.intents import detect_intents
from kavach.detectors.types import Reason
from kavach.detectors.url.extract import extract_phones, extract_upi_ids, extract_urls
from kavach.detectors.url.lexical import lexical_findings
from kavach.intel.allowlist import is_official


def reasons(text: str) -> set[Reason]:
    return {f.reason for f in detect_intents(text)}


def test_digital_arrest_hinglish() -> None:
    r = reasons("CBI se bol raha hoon, aap digital arrest mein hain")
    assert {Reason.DIGITAL_ARREST, Reason.AUTHORITY_CLAIM} <= r


def test_digital_arrest_devanagari() -> None:
    assert Reason.DIGITAL_ARREST in reasons("आप डिजिटल अरेस्ट में हैं")


def test_authority_plus_fear_adds_combo() -> None:
    r = reasons("Mumbai police: warrant issued against you")
    assert Reason.DIGITAL_ARREST in r


def test_otp_request() -> None:
    assert Reason.OTP_REQUEST in reasons("please share the OTP you just received")
    assert Reason.OTP_REQUEST in reasons("OTP batao jaldi")


def test_benign_police_mention_is_weak() -> None:
    findings = detect_intents("Police station ke paas wali dukaan se sabzi le aana")
    assert sum(f.weight for f in findings) < 3


def test_bare_abhi_is_not_urgency() -> None:
    assert Reason.URGENCY not in reasons("abhi ghar aa raha hoon")


def test_extract_urls_with_and_without_scheme() -> None:
    urls = extract_urls(
        "Go to http://sbi-kyc.xyz/login, or www.hdfc-help.top and paytm-refund.online/x."
    )
    hosts = [u.host for u in urls]
    assert hosts == ["sbi-kyc.xyz", "www.hdfc-help.top", "paytm-refund.online"]
    assert urls[0].explicit_scheme and not urls[2].explicit_scheme


def test_extract_ignores_emails_and_non_domains() -> None:
    assert extract_urls("mail me at ram@gmail.com about file.txt e.g. this") == []


def test_extract_upi_and_phone() -> None:
    text = "Pay to fraudster99@okaxis or call +91 98765 43210 / 9123456789. mail a@b.com"
    assert extract_upi_ids(text) == ["fraudster99@okaxis"]
    assert extract_phones(text) == ["+919123456789", "+919876543210"]


@pytest.mark.parametrize(
    ("host", "registered"),
    [
        ("www.onlinesbi.sbi", "onlinesbi.sbi"),
        ("netbanking.hdfcbank.com", "hdfcbank.com"),
        ("www.incometax.gov.in", "incometax.gov.in"),
        ("x.sbi.bank.in", "bank.in"),
    ],
)
def test_official(host: str, registered: str) -> None:
    assert is_official(host, registered)


def test_shared_host_never_official() -> None:
    assert not is_official("docs.google.com", "google.com")


def test_brand_impersonation_and_risky_tld() -> None:
    (pu,) = extract_urls("http://sbi-kyc-update.xyz/login")
    r = {f.reason for f in lexical_findings(pu)}
    assert {Reason.BRAND_IMPERSONATION, Reason.RISKY_TLD, Reason.NO_HTTPS} <= r


def test_short_brand_token_needs_label_boundary() -> None:
    (pu,) = extract_urls("https://www.usbig.com")  # contains "sbi" but not as a label part
    assert Reason.BRAND_IMPERSONATION not in {f.reason for f in lexical_findings(pu)}


def test_official_domain_short_circuits() -> None:
    (pu,) = extract_urls("https://www.hdfcbank.com/personal")
    assert [f.reason for f in lexical_findings(pu)] == [Reason.OFFICIAL_DOMAIN]


def test_apk_link() -> None:
    (pu,) = extract_urls("https://pmkisan-list.online/PM_Kisan.apk")
    assert Reason.APK_LINK in {f.reason for f in lexical_findings(pu)}


def test_advance_fee_combo() -> None:
    r = reasons("KBC lucky draw mein 25 lakh jeete hain, registration fee Rs 12500 pay karein")
    assert {Reason.LOTTERY_PRIZE, Reason.PAYMENT_ASK, Reason.ADVANCE_FEE} <= r
    assert Reason.ADVANCE_FEE not in reasons("Rs 450 pay kar dena doodh wale ko")


def test_apk_filename_in_text() -> None:
    assert Reason.REMOTE_ACCESS_APP in reasons(
        "Wedding card dekhiye: shaadi-card.apk download karein"
    )
    assert Reason.REMOTE_ACCESS_APP in reasons("yeh apk install karo")

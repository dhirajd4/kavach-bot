"""Official Indian domains (banks, UPI, government, big platforms).

Suffix rules use zones whose registration is restricted to the real owners
(.gov.in, .nic.in, .bank.in, .fin.in), so anything under them is official.
"""

from importlib import resources

OFFICIAL_SUFFIXES: tuple[str, ...] = (
    ".gov.in",
    ".nic.in",
    ".bank.in",
    ".fin.in",
    ".mil.in",
    ".sbi",  # .sbi is SBI's brand TLD
)


def _load(name: str) -> frozenset[str]:
    text = resources.files("kavach.data").joinpath(name).read_text("utf-8")
    return frozenset(
        line.strip().lower()
        for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    )


OFFICIAL_DOMAINS = _load("official_domains.txt")
SHARED_HOSTS = _load("shared_hosts.txt")


def is_official(host: str, registered_domain: str) -> bool:
    host = host.lower()
    if is_shared_host(registered_domain) or is_shared_host(host):
        return False  # docs.google.com/forms/... can be anyone's phishing form
    if registered_domain.lower() in OFFICIAL_DOMAINS:
        return True
    return any(host.endswith(sfx) or host == sfx[1:] for sfx in OFFICIAL_SUFFIXES)


def is_shared_host(registered_domain: str) -> bool:
    """Platforms where anyone can host a page (sites.google.com, *.web.app …).
    A bad URL there must never taint the whole domain."""
    return registered_domain.lower() in SHARED_HOSTS

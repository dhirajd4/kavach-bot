"""Static APK fact extraction. The APK is NEVER installed or executed: we only read its
zip directory, its manifest and its signing certificate.

Runs inside the isolated sandbox container, in a child process with a CPU-time and memory
limit (see `run_isolated`), because parsers of untrusted files are a classic attack surface.

    python -m kavach.apk.extract < some.apk     # prints facts as JSON
"""

import asyncio
import contextlib
import hashlib
import io
import json
import sys
import zipfile
from typing import Any

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

MAX_ENTRIES = 20_000
MAX_TOTAL_UNCOMPRESSED = 1_500 * 1024 * 1024  # 1.5 GB
MAX_RATIO = 250  # per-entry compression ratio; zip bombs are in the thousands
CHILD_CPU_SECONDS = 25
CHILD_MEMORY_BYTES = 1_536 * 1024 * 1024


class UnsafeArchive(ValueError):
    pass


def check_zip(data: bytes) -> None:
    """Reject zip bombs and non-APKs before any parser touches the contents."""
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise UnsafeArchive("not a zip archive") from exc
    infos = z.infolist()
    if len(infos) > MAX_ENTRIES:
        raise UnsafeArchive("too many files")
    total = 0
    for info in infos:
        total += info.file_size
        if info.compress_size and info.file_size / info.compress_size > MAX_RATIO:
            raise UnsafeArchive("suspicious compression ratio (zip bomb)")
        if info.flag_bits & 0x1:
            raise UnsafeArchive("encrypted entries")
    if total > MAX_TOTAL_UNCOMPRESSED:
        raise UnsafeArchive("uncompressed size too large")
    if "AndroidManifest.xml" not in {i.filename for i in infos}:
        raise UnsafeArchive("no AndroidManifest.xml")


def extract_facts(data: bytes) -> dict[str, Any]:
    """Facts only, no judgement. Imports androguard lazily (sandbox image only)."""
    facts: dict[str, Any] = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "error": "",
    }
    try:
        check_zip(data)
    except UnsafeArchive as exc:
        facts["error"] = f"unsafe: {exc}"
        return facts

    from loguru import logger

    logger.remove()  # androguard logs at DEBUG by default
    from androguard.core.apk import APK

    try:
        apk = APK(data, raw=True)
        manifest = apk.get_android_manifest_xml()
    except Exception as exc:  # noqa: BLE001 - any parser failure = unreadable APK
        facts["error"] = f"parse: {type(exc).__name__}"
        return facts
    if manifest is None:
        facts["error"] = "parse: unreadable manifest"
        return facts

    components: list[dict[str, Any]] = []
    for tag in ("service", "receiver", "activity", "provider"):
        for el in manifest.iter(tag):
            components.append(
                {
                    "tag": tag,
                    "name": (el.get(ANDROID_NS + "name") or "")[:200],
                    "permission": el.get(ANDROID_NS + "permission") or "",
                    "actions": [a.get(ANDROID_NS + "name") or "" for a in el.iter("action")][:20],
                }
            )
            if len(components) >= 500:
                break

    signers: list[str] = []
    with contextlib.suppress(Exception):  # unreadable signature block: report unsigned
        signers = [c.subject.human_friendly[:200] for c in apk.get_certificates()]

    facts.update(
        package=(apk.get_package() or "")[:200],
        label=_safe(apk.get_app_name)[:200],
        permissions=sorted(set(apk.get_permissions()))[:300],
        components=components,
        min_sdk=_safe(apk.get_min_sdk_version),
        target_sdk=_safe(apk.get_target_sdk_version),
        signed=bool(_safe(apk.is_signed, False)),
        signers=signers[:5],
        has_dex=any(n.endswith(".dex") for n in apk.get_files()),
        native_libs=sum(1 for n in apk.get_files() if n.endswith(".so")),
    )
    return facts


def _safe(fn: Any, default: Any = "") -> Any:
    try:
        value = fn()
    except Exception:  # noqa: BLE001
        return default
    return default if value is None else value


def _limit_child() -> None:
    """CPU-time + address-space caps. Enforced in the (Linux) sandbox; macOS ignores RLIMIT_AS,
    which only matters for local test runs."""
    import resource

    for limit, value in (
        (resource.RLIMIT_CPU, CHILD_CPU_SECONDS),
        (resource.RLIMIT_AS, CHILD_MEMORY_BYTES),
    ):
        with contextlib.suppress(ValueError, OSError):
            resource.setrlimit(limit, (value, value))


async def run_isolated(data: bytes, timeout_s: float = 30.0) -> dict[str, Any]:
    """Parse in a separate, resource-limited process; a parser crash or hang can't take the
    service down."""
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "kavach.apk.extract",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        preexec_fn=_limit_child,  # noqa: PLW1509
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(data), timeout=timeout_s)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        return {
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "error": "parse: timeout",
        }
    try:
        result: dict[str, Any] = json.loads(out)
    except json.JSONDecodeError:
        result = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "error": f"parse: crashed (exit {proc.returncode})",
        }
    return result


if __name__ == "__main__":
    print(json.dumps(extract_facts(sys.stdin.buffer.read())))

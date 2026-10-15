"""Write harmless, code-free test APKs (tests/apkgen.py specs) to tests/fixtures/apks/.
Nothing is downloaded; the folder is gitignored.

    .venv/bin/python scripts/make_apk_fixtures.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests.apkgen import SPECS, build_apk  # noqa: E402

OUT = ROOT / "tests" / "fixtures" / "apks"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, spec in SPECS.items():
        path = OUT / f"{name}.apk"
        path.write_bytes(build_apk(spec))
        print("wrote", path.relative_to(ROOT), f"({path.stat().st_size} bytes, no code)")
    broken = OUT / "warn_broken_disguised.apk"
    broken.write_bytes(b"this is not really an app, just bytes pretending to be one")
    print("wrote", broken.relative_to(ROOT))


if __name__ == "__main__":
    main()

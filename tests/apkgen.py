"""Build harmless, code-free test APKs in memory: a binary AndroidManifest.xml (AXML) plus a
v1 signature with a throwaway self-signed certificate. No classes.dex, nothing executable.
Used by tests and scripts/make_apk_fixtures.py, so no real APK is ever downloaded.
"""

import hashlib
import io
import struct
import zipfile
from base64 import b64encode
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

ANDROID_NS = "http://schemas.android.com/apk/res/android"
NO_INDEX = 0xFFFFFFFF
TYPE_STRING, TYPE_INT, TYPE_BOOL = 0x03, 0x10, 0x12


@dataclass
class Component:
    tag: str  # service | receiver | activity
    name: str
    permission: str = ""
    actions: list[str] = field(default_factory=list)


@dataclass
class ApkSpec:
    package: str
    label: str
    permissions: list[str] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    signer_cn: str = "Test Signer"
    min_sdk: int = 21
    target_sdk: int = 30


# ---- minimal AXML writer -------------------------------------------------------------------


class _Strings:
    def __init__(self) -> None:
        self.items: list[str] = []

    def idx(self, s: str) -> int:
        if s not in self.items:
            self.items.append(s)
        return self.items.index(s)

    def chunk(self) -> bytes:
        offsets, data = [], b""
        for s in self.items:
            offsets.append(len(data))
            enc = s.encode("utf-16-le")
            data += struct.pack("<H", len(s)) + enc + b"\x00\x00"
        data += b"\x00" * (-len(data) % 4)
        header_size = 28
        strings_start = header_size + 4 * len(self.items)
        size = strings_start + len(data)
        head = struct.pack(
            "<HHIIIIII", 0x0001, header_size, size, len(self.items), 0, 0, strings_start, 0
        )
        return head + b"".join(struct.pack("<I", o) for o in offsets) + data


def _manifest(spec: ApkSpec) -> bytes:
    sp = _Strings()
    ns = sp.idx(ANDROID_NS)
    prefix = sp.idx("android")
    body: list[bytes] = []
    line = 1

    def attr(name: str, value: str | int | bool, android: bool = True) -> bytes:
        name_i = sp.idx(name)
        if isinstance(value, bool):
            raw, dtype, data = NO_INDEX, TYPE_BOOL, 0xFFFFFFFF if value else 0
        elif isinstance(value, int):
            raw, dtype, data = NO_INDEX, TYPE_INT, value
        else:
            raw = sp.idx(value)
            dtype, data = TYPE_STRING, raw
        return struct.pack("<IIIHBBI", ns if android else NO_INDEX, name_i, raw, 8, 0, dtype, data)

    def start(tag: str, attrs: list[bytes]) -> None:
        nonlocal line
        line += 1
        body.append(
            struct.pack(
                "<HHIIIIIHHHHHH",
                0x0102,
                16,
                36 + 20 * len(attrs),
                line,
                NO_INDEX,
                NO_INDEX,
                sp.idx(tag),
                20,
                20,
                len(attrs),
                0,
                0,
                0,
            )
            + b"".join(attrs)
        )

    def end(tag: str) -> None:
        nonlocal line
        line += 1
        body.append(struct.pack("<HHIIIII", 0x0103, 16, 24, line, NO_INDEX, NO_INDEX, sp.idx(tag)))

    start(
        "manifest",
        [
            attr("package", spec.package, android=False),
            attr("versionCode", 1),
            attr("versionName", "1.0"),
        ],
    )
    start(
        "uses-sdk", [attr("minSdkVersion", spec.min_sdk), attr("targetSdkVersion", spec.target_sdk)]
    )
    end("uses-sdk")
    for perm in spec.permissions:
        start("uses-permission", [attr("name", perm)])
        end("uses-permission")
    start("application", [attr("label", spec.label)])
    for comp in spec.components:
        attrs = [attr("name", comp.name), attr("exported", True)]
        if comp.permission:
            attrs.append(attr("permission", comp.permission))
        start(comp.tag, attrs)
        if comp.actions:
            start("intent-filter", [])
            for action in comp.actions:
                start("action", [attr("name", action)])
                end("action")
            end("intent-filter")
        end(comp.tag)
    end("application")
    end("manifest")

    ns_start = struct.pack("<HHIIIII", 0x0100, 16, 24, 1, NO_INDEX, prefix, ns)
    ns_end = struct.pack("<HHIIIII", 0x0101, 16, 24, line + 1, NO_INDEX, prefix, ns)
    chunks = sp.chunk() + ns_start + b"".join(body) + ns_end
    return struct.pack("<HHI", 0x0003, 8, 8 + len(chunks)) + chunks


# ---- v1 signing with a throwaway certificate -------------------------------------------------


def _signer(cn: str) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    return cert, key


def build_apk(spec: ApkSpec, *, signed: bool = True) -> bytes:
    files = {
        "AndroidManifest.xml": _manifest(spec),
        "res/raw/readme.txt": b"Kavach test fixture. Contains no code.",
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
        if signed:

            def digest(b: bytes) -> str:
                return b64encode(hashlib.sha256(b).digest()).decode()

            mf = "Manifest-Version: 1.0\r\n\r\n" + "".join(
                f"Name: {n}\r\nSHA-256-Digest: {digest(d)}\r\n\r\n" for n, d in files.items()
            )
            sf = f"Signature-Version: 1.0\r\nSHA-256-Digest-Manifest: {digest(mf.encode())}\r\n\r\n"
            cert, key = _signer(spec.signer_cn)
            sig = (
                pkcs7.PKCS7SignatureBuilder()
                .set_data(sf.encode())
                .add_signer(cert, key, hashes.SHA256())
                .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature])
            )
            z.writestr("META-INF/MANIFEST.MF", mf)
            z.writestr("META-INF/CERT.SF", sf)
            z.writestr("META-INF/CERT.RSA", sig)
    return buf.getvalue()


# ---- ready-made specs ----------------------------------------------------------------------

P = "android.permission."

SPECS: dict[str, ApkSpec] = {
    # Banking-trojan pattern seen in Indian "KYC update" APK campaigns.
    "scam_sbi_kyc_update": ApkSpec(
        package="com.sbi.kycupdate.online",
        label="SBI YONO KYC Update",
        permissions=[
            P + "RECEIVE_SMS",
            P + "READ_SMS",
            P + "SEND_SMS",
            P + "INTERNET",
            P + "SYSTEM_ALERT_WINDOW",
            P + "READ_PHONE_STATE",
        ],
        components=[
            Component(
                "service",
                "com.sbi.kycupdate.online.Acc",
                permission=P + "BIND_ACCESSIBILITY_SERVICE",
                actions=["android.accessibilityservice.AccessibilityService"],
            ),
            Component(
                "service",
                "com.sbi.kycupdate.online.Notif",
                permission=P + "BIND_NOTIFICATION_LISTENER_SERVICE",
                actions=["android.service.notification.NotificationListenerService"],
            ),
            Component(
                "receiver",
                "com.sbi.kycupdate.online.SmsIn",
                actions=["android.provider.Telephony.SMS_RECEIVED"],
            ),
        ],
        signer_cn="Android Debug",
    ),
    # "Wedding invitation" APK that steals SMS and spreads to contacts.
    "scam_wedding_invite": ApkSpec(
        package="com.invitation.card.view",
        label="Wedding Invitation Card",
        permissions=[
            P + "RECEIVE_SMS",
            P + "READ_SMS",
            P + "SEND_SMS",
            P + "READ_CONTACTS",
            P + "INTERNET",
        ],
        components=[
            Component(
                "receiver",
                "com.invitation.card.view.R",
                actions=["android.provider.Telephony.SMS_RECEIVED"],
            )
        ],
    ),
    # Fake government-scheme app with device admin + call forwarding powers.
    "scam_pm_kisan": ApkSpec(
        package="com.pmkisan.status.check",
        label="PM Kisan Status 2026",
        permissions=[
            P + "CALL_PHONE",
            P + "READ_CALL_LOG",
            P + "INTERNET",
            P + "REQUEST_INSTALL_PACKAGES",
        ],
        components=[
            Component(
                "receiver",
                "com.pmkisan.status.check.Admin",
                permission=P + "BIND_DEVICE_ADMIN",
                actions=["android.app.action.DEVICE_ADMIN_ENABLED"],
            )
        ],
    ),
    # Harmless app: still ⚠️, because apps shared on WhatsApp skip Play Store checks.
    "warn_simple_calculator": ApkSpec(
        package="org.example.calculator",
        label="Simple Calculator",
        permissions=[],
    ),
}

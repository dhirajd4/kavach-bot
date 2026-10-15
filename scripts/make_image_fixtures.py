"""Render labelled test images (scam_*/safe_*) for the image pipeline, using headless Chrome
so Devanagari is shaped correctly. Output: tests/fixtures/images/*.png

    .venv/bin/python scripts/make_image_fixtures.py
"""

import base64
import io
import subprocess
import tempfile
from pathlib import Path

import segno

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
OUT = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "images"

CSS = """
body{margin:0;background:#e5ddd5;font-family:'Kohinoor Devanagari','Noto Sans Devanagari',
'Helvetica Neue',sans-serif;}
.phone{width:380px;padding:14px;}
.bar{background:#075e54;color:#fff;padding:10px 12px;font-weight:600;border-radius:6px 6px 0 0}
.msg{background:#fff;border-radius:8px;padding:10px 12px;margin:10px 0;font-size:17px;
line-height:1.45;box-shadow:0 1px 1px rgba(0,0,0,.15)}
.doc{width:520px;margin:14px;background:#fffef6;border:3px double #7a1f1f;padding:22px;
font-size:18px;line-height:1.6;color:#222}
.doc h1{font-size:24px;text-align:center;margin:0 0 8px;color:#7a1f1f}
.doc h2{font-size:20px;text-align:center;margin:0 0 14px}
.seal{float:right;width:90px;height:90px;border:3px solid #a33;border-radius:50%;color:#a33;
display:flex;align-items:center;justify-content:center;font-size:12px;text-align:center;
transform:rotate(-12deg)}
.card{width:380px;margin:14px;background:#fff;border-radius:12px;padding:18px;text-align:center;
font-size:18px}
.card .big{font-size:26px;font-weight:700;color:#0a7d34}
.photo{width:420px;height:300px;background:linear-gradient(135deg,#7ab,#dca 60%,#963);}
"""


def qr_data_uri(payload: str) -> str:
    buf = io.BytesIO()
    segno.make(payload, error="m").save(buf, kind="png", scale=7, border=2)
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


FIXTURES: dict[str, str] = {
    "scam_fake_fir_hi": """<div class="doc"><div class="seal">केंद्रीय अन्वेषण<br>ब्यूरो</div>
<h1>केंद्रीय अन्वेषण ब्यूरो (CBI)</h1><h2>गिरफ्तारी वारंट</h2>
आपके आधार कार्ड से जुड़े खाते में मनी लॉन्ड्रिंग का केस दर्ज है।
आप डिजिटल अरेस्ट में हैं। जाँच पूरी होने तक वीडियो कॉल पर बने रहें
और किसी को न बताएँ। सहयोग न करने पर तुरंत गिरफ्तार किया जाएगा।</div>""",
    "scam_sms_screenshot_en": """<div class="phone"><div class="bar">VM-SBIUPD</div>
<div class="msg">Dear Customer, your SBI YONO account will be blocked today.
Update your PAN card immediately to avoid suspension:<br>http://sbi-yono-kyc.xyz/update</div></div>""",
    "scam_qr_cashback": f"""<div class="card"><div class="big">Congratulations!</div>
You have won Rs 25,000 cashback from PhonePe.<br>Scan this QR to receive money in your account.
<br><img src="{qr_data_uri("upi://pay?pa=cashback.offer@ybl&pn=Cashback&am=4999&cu=INR")}"></div>""",
    "scam_excess_payment_hinglish": """<div class="phone"><div class="bar">+91 98xxx xxx21</div>
<div class="msg">Bhai maine galti se 5000 zyada bhej diye aapke account mein.
Please jaldi return kar do, urgent hai. Screenshot bheja hai upar.</div></div>""",
    "scam_job_task_en": """<div class="phone"><div class="bar">HR Team</div>
<div class="msg">Part time job! Work from home and earn Rs 3000 daily by liking YouTube videos.
Pay registration fee Rs 499 to start. Join our Telegram task group now.</div></div>""",
    "safe_bhajan_hi": """<div class="phone"><div class="bar">परिवार</div>
<div class="msg">आज शाम 6 बजे मंदिर में भजन संध्या है। सभी आमंत्रित हैं।
प्रसाद के बाद भोजन की व्यवस्था है।</div></div>""",
    "safe_school_notice_en": """<div class="doc"><h1>Saraswati Public School</h1>
<h2>Notice</h2>The school will remain closed on Friday for the annual function rehearsal.
Parents are requested to attend the function on Saturday at 10 am. Thank you.</div>""",
    "safe_shop_qr": f"""<div class="card"><div class="big">Sharma General Store</div>
Pay here for groceries<br><img src="{qr_data_uri("upi://pay?pa=sharmastore@okicici&pn=Sharma%20Store")}"></div>""",
    "blank_photo": """<div class="photo"></div>""",
}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        for name, body in FIXTURES.items():
            html = Path(tmp) / f"{name}.html"
            html.write_text(
                f"<!doctype html><meta charset=utf-8><style>{CSS}</style>{body}", encoding="utf-8"
            )
            png = OUT / f"{name}.png"
            subprocess.run(
                [
                    CHROME,
                    "--headless=new",
                    "--disable-gpu",
                    "--hide-scrollbars",
                    "--window-size=600,620",
                    f"--screenshot={png}",
                    html.as_uri(),
                ],
                check=True,
                capture_output=True,
            )
            print("wrote", png.relative_to(OUT.parent.parent.parent))


if __name__ == "__main__":
    main()

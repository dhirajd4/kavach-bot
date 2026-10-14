"""Reply copy in Hindi (Devanagari), Hinglish and English. Short, plain, elder-friendly."""

from kavach.detectors.types import Reason
from kavach.verdict.rules import Verdict

LANGS = ("hi", "hinglish", "en")
DEFAULT_LANG = "hinglish"

HEADLINE: dict[Verdict, dict[str, str]] = {
    Verdict.SCAM: {
        "hi": "🚨 *यह धोखा (स्कैम) लग रहा है — रुकिए!*",
        "hinglish": "🚨 *Yeh SCAM lag raha hai — ruk jaiye!*",
        "en": "🚨 *This looks like a SCAM — stop!*",
    },
    Verdict.SUSPICIOUS: {
        "hi": "⚠️ *सावधान — इसमें शक वाली बातें हैं*",
        "hinglish": "⚠️ *Savdhaan — isme shak wali baatein hain*",
        "en": "⚠️ *Careful — this has warning signs*",
    },
    Verdict.LOOKS_SAFE: {
        "hi": "✅ *लिंक आधिकारिक वेबसाइट का लग रहा है*",
        "hinglish": "✅ *Link official website ka lag raha hai*",
        "en": "✅ *The link points to an official website*",
    },
    Verdict.NO_RISK_FOUND: {
        "hi": "ℹ️ *कोई जाना-पहचाना खतरा नहीं मिला*",
        "hinglish": "ℹ️ *Koi jaana-pehchana khatra nahi mila*",
        "en": "ℹ️ *No known danger found*",
    },
}

REASON: dict[Reason, dict[str, str]] = {
    Reason.OPENPHISH_LISTED: {
        "hi": "यह लिंक फ़िशिंग (धोखे) की सूची में है: {e}",
        "hinglish": "Yeh link phishing (dhokhe) ki list mein hai: {e}",
        "en": "This link is on a known phishing list: {e}",
    },
    Reason.REPUTATION_SCAM: {
        "hi": "यह लिंक पहले भी धोखे में इस्तेमाल हुआ है: {e}",
        "hinglish": "Yeh link pehle bhi fraud mein use hua hai: {e}",
        "en": "This link has been used in scams before: {e}",
    },
    Reason.REPUTATION_SUSPICIOUS: {
        "hi": "इस लिंक के बारे में पहले भी शिकायतें आई हैं: {e}",
        "hinglish": "Is link ke baare mein pehle bhi shikayatein aayi hain: {e}",
        "en": "This link has been reported before: {e}",
    },
    Reason.BRAND_IMPERSONATION: {
        "hi": "लिंक किसी बड़े बैंक/कंपनी का नाम इस्तेमाल करता है, पर उसकी असली वेबसाइट नहीं है ({e})",
        "hinglish": "Link kisi bank/company ka naam use karta hai, par asli website nahi hai ({e})",
        "en": "The link uses a bank/brand name but is not its real website ({e})",
    },
    Reason.IP_ADDRESS_HOST: {
        "hi": "लिंक में वेबसाइट के नाम की जगह सिर्फ नंबर हैं ({e})",
        "hinglish": "Link mein website ke naam ki jagah sirf number hain ({e})",
        "en": "The link uses a bare IP address instead of a name ({e})",
    },
    Reason.PUNYCODE_HOST: {
        "hi": "लिंक में असली जैसे दिखने वाले नकली अक्षर हैं ({e})",
        "hinglish": "Link mein asli jaise dikhne wale nakli akshar hain ({e})",
        "en": "The link uses look-alike characters ({e})",
    },
    Reason.RISKY_TLD: {
        "hi": "वेबसाइट का अंत ({e}) अक्सर धोखे वाली साइटों में दिखता है",
        "hinglish": "Website ka ending ({e}) aksar fraud sites mein dikhta hai",
        "en": "The site ending ({e}) is common on scam sites",
    },
    Reason.SHORTENED_URL: {
        "hi": "छोटा किया हुआ लिंक ({e}) — असली पता छुपा है",
        "hinglish": "Chhota kiya hua link ({e}) — asli pata chhupa hai",
        "en": "Shortened link ({e}) hides the real address",
    },
    Reason.NO_HTTPS: {
        "hi": "लिंक सुरक्षित (https) नहीं है",
        "hinglish": "Link secure (https) nahi hai",
        "en": "The link is not secure (no https)",
    },
    Reason.APK_LINK: {
        "hi": "लिंक से ऐप (APK) डाउनलोड होगा — Play Store के बाहर के ऐप फ़ोन पर कब्ज़ा कर सकते हैं",
        "hinglish": "Link se app (APK) download hoga — Play Store ke bahar ke apps phone hack kar sakte hain",
        "en": "The link downloads an app (APK) — apps outside Play Store can take over your phone",
    },
    Reason.DIGITAL_ARREST: {
        "hi": "'डिजिटल अरेस्ट' जैसा डर — पुलिस/CBI कभी वीडियो कॉल पर गिरफ्तार नहीं करती",
        "hinglish": "'Digital arrest' jaisa darr — Police/CBI kabhi video call par giraftaar nahi karti",
        "en": "'Digital arrest' threat — police/CBI never arrest anyone over a video call",
    },
    Reason.AUTHORITY_CLAIM: {
        "hi": 'सरकारी अफ़सर/एजेंसी होने का दावा ("{e}")',
        "hinglish": 'Sarkari officer/agency hone ka daava ("{e}")',
        "en": 'Claims to be an officer/agency ("{e}")',
    },
    Reason.FEAR_THREAT: {
        "hi": 'डराने वाली बातें ("{e}")',
        "hinglish": 'Darane wali baatein ("{e}")',
        "en": 'Threatening language ("{e}")',
    },
    Reason.URGENCY: {
        "hi": 'जल्दबाज़ी का दबाव ("{e}")',
        "hinglish": 'Jaldbaazi ka dabaav ("{e}")',
        "en": 'Pressure to act fast ("{e}")',
    },
    Reason.KYC_BLOCK: {
        "hi": "KYC/खाता बंद होने का डर — बैंक ऐसे मैसेज से KYC नहीं करवाते",
        "hinglish": "KYC/account band hone ka darr — bank aise message se KYC nahi karwate",
        "en": "KYC/account-block threat — banks don't do KYC through such messages",
    },
    Reason.OTP_REQUEST: {
        "hi": "OTP/PIN माँगा गया — असली बैंक या कंपनी कभी OTP नहीं माँगती",
        "hinglish": "OTP/PIN maanga gaya — asli bank ya company kabhi OTP nahi maangti",
        "en": "Asks for OTP/PIN — real banks and companies never ask for it",
    },
    Reason.LOTTERY_PRIZE: {
        "hi": "लॉटरी/इनाम का लालच — बिना खेले कोई इनाम नहीं मिलता",
        "hinglish": "Lottery/inaam ka laalach — bina khele koi inaam nahi milta",
        "en": "Lottery/prize bait — you can't win something you never entered",
    },
    Reason.JOB_TASK: {
        "hi": "घर बैठे कमाई/टास्क वाली नौकरी — ऐसे ऑफ़र में पहले पैसे जमा करवाए जाते हैं",
        "hinglish": "Ghar baithe kamai/task job — aise offer mein pehle paise jama karwate hain",
        "en": "Work-from-home/task job — these end with you paying a 'deposit'",
    },
    Reason.INVESTMENT_RETURNS: {
        "hi": "पक्के/बहुत ज़्यादा मुनाफ़े का वादा — असली निवेश में गारंटी नहीं होती",
        "hinglish": "Pakke/bahut zyada munafe ka vaada — asli investment mein guarantee nahi hoti",
        "en": "Promises guaranteed/high returns — real investments never guarantee",
    },
    Reason.REFUND_BILL: {
        "hi": "रिफंड/बिजली कनेक्शन कटने की बात — अक्सर धोखे की शुरुआत",
        "hinglish": "Refund/bijli connection katne ki baat — aksar fraud ki shuruaat",
        "en": "Refund or bill-disconnection story — a common scam opener",
    },
    Reason.PAYMENT_ASK: {
        "hi": 'पैसे भेजने/फ़ीस जमा करने को कहा गया ("{e}")',
        "hinglish": 'Paise bhejne/fees jama karne ko kaha gaya ("{e}")',
        "en": 'Asks you to pay or send money ("{e}")',
    },
    Reason.REMOTE_ACCESS_APP: {
        "hi": "ऐप इंस्टॉल/स्क्रीन शेयर करने को कहा — इससे फ़ोन और बैंक पर कब्ज़ा हो सकता है",
        "hinglish": "App install/screen share karne ko kaha — isse phone aur bank par kabza ho sakta hai",
        "en": "Asks you to install an app or share your screen — this gives control of your phone",
    },
    Reason.ADVANCE_FEE: {
        "hi": 'पहले लालच, फिर "पहले फ़ीस भरो" — यही धोखे का तरीका है। असली इनाम/नौकरी/रिफंड के लिए पैसे नहीं माँगे जाते',
        "hinglish": 'Pehle laalach, phir "pehle fees bharo" — yahi fraud ka tareeka hai. Asli inaam/naukri/refund ke liye paise nahi maange jaate',
        "en": 'A reward, then "pay a fee first" — that\'s the scam. Real prizes, jobs or refunds never ask you to pay',
    },
    Reason.SEXTORTION: {
        "hi": "वीडियो वायरल करने की धमकी — पैसे न दें, 1930 पर शिकायत करें",
        "hinglish": "Video viral karne ki dhamki — paise na dein, 1930 par shikayat karein",
        "en": "Threat to leak a video — don't pay, report on 1930",
    },
}

ADVICE: dict[Verdict, dict[str, str]] = {
    Verdict.SCAM: {
        "hi": "👉 लिंक न खोलें, पैसे न भेजें, OTP/PIN किसी को न बताएं।\n"
        "👉 पैसे चले गए हों तो *तुरंत 1930* पर कॉल करें या cybercrime.gov.in पर शिकायत करें।",
        "hinglish": "👉 Link na kholein, paise na bhejein, OTP/PIN kisi ko na batayein.\n"
        "👉 Paise chale gaye hon to *turant 1930* par call karein ya cybercrime.gov.in par report karein.",
        "en": "👉 Don't open the link, don't pay, never share OTP/PIN.\n"
        "👉 If money is gone, call *1930 immediately* or report at cybercrime.gov.in.",
    },
    Verdict.SUSPICIOUS: {
        "hi": "👉 कुछ भी करने से पहले रुकें। बैंक/कंपनी के *असली नंबर* पर खुद कॉल करके पूछें।",
        "hinglish": "👉 Kuch bhi karne se pehle rukein. Bank/company ke *asli number* par khud call karke poochhein.",
        "en": "👉 Pause before acting. Call the bank/company on its *official number* yourself.",
    },
    Verdict.LOOKS_SAFE: {
        "hi": "👉 फिर भी OTP/PIN कभी किसी को न बताएं।",
        "hinglish": "👉 Phir bhi OTP/PIN kabhi kisi ko na batayein.",
        "en": "👉 Still, never share your OTP/PIN with anyone.",
    },
    Verdict.NO_RISK_FOUND: {
        "hi": "👉 नया धोखा भी हो सकता है। पैसे, OTP या ऐप इंस्टॉल की बात हो तो रुककर जाँचें।",
        "hinglish": "👉 Naya fraud bhi ho sakta hai. Paise, OTP ya app install ki baat ho to ruk kar jaanchein.",
        "en": "👉 It could still be a new scam. If it asks for money, OTP or an app install, pause and verify.",
    },
}

WELCOME = {
    "hi": "🙏 *कवच* में आपका स्वागत है!\n"
    "कोई भी शक वाला मैसेज, लिंक, फ़ोटो या ऐप (APK) यहाँ *फ़ॉरवर्ड* करें — हम बताएँगे कि यह धोखा है या नहीं।\n\n"
    "🔒 हम आपका मैसेज जाँच के बाद मिटा देते हैं; सिर्फ़ नतीजा रखते हैं।\n"
    "भाषा बदलने के लिए लिखें: *Hindi*, *Hinglish* या *English*",
    "hinglish": "🙏 *Kavach* mein aapka swagat hai!\n"
    "Koi bhi shak wala message, link, photo ya app (APK) yahan *forward* karein — hum batayenge ki yeh fraud hai ya nahi.\n\n"
    "🔒 Hum aapka message jaanch ke baad mita dete hain; sirf result rakhte hain.\n"
    "Bhasha badalne ke liye likhein: *Hindi*, *Hinglish* ya *English*",
    "en": "🙏 Welcome to *Kavach*!\n"
    "Forward any suspicious message, link, photo or app (APK) here — we'll tell you if it's a scam.\n\n"
    "🔒 We delete your message after checking; only the result is kept.\n"
    "To change language, type: *Hindi*, *Hinglish* or *English*",
}

LANG_SET = {
    "hi": "✅ भाषा हिंदी कर दी गई। अब कोई भी शक वाला मैसेज फ़ॉरवर्ड करें।",
    "hinglish": "✅ Bhasha Hinglish kar di gayi. Ab koi bhi shak wala message forward karein.",
    "en": "✅ Language set to English. Forward any suspicious message to check it.",
}

UNSUPPORTED = {
    "hi": "🙏 अभी हम टेक्स्ट मैसेज और लिंक जाँच सकते हैं। फ़ोटो और ऐप (APK) की जाँच जल्द आ रही है।",
    "hinglish": "🙏 Abhi hum text message aur link check kar sakte hain. Photo aur app (APK) check jald aa raha hai.",
    "en": "🙏 Right now we can check text messages and links. Photo and app (APK) checks are coming soon.",
}

RATE_LIMITED = {
    "hi": "🙏 आपने बहुत सारे मैसेज भेजे हैं। कृपया थोड़ी देर बाद फिर कोशिश करें।",
    "hinglish": "🙏 Aapne bahut saare message bheje hain. Thodi der baad phir try karein.",
    "en": "🙏 You've sent a lot of messages. Please try again in a little while.",
}

ERROR = {
    "hi": "🙏 माफ़ कीजिए, अभी जाँच नहीं हो पाई। थोड़ी देर बाद फिर भेजें। शक हो तो पैसे न भेजें।",
    "hinglish": "🙏 Maaf kijiye, abhi check nahi ho paaya. Thodi der baad phir bhejein. Shak ho to paise na bhejein.",
    "en": "🙏 Sorry, we couldn't check this right now. Please resend in a while. If in doubt, don't pay.",
}

FOOTER = {
    "hi": "— कवच 🛡️ भेज के चेक करो",
    "hinglish": "— Kavach 🛡️ Bhej ke check karo",
    "en": "— Kavach 🛡️ Forward to check",
}

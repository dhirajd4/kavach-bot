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
    Reason.WEBRISK_LISTED: {
        "hi": "Google की ख़तरनाक वेबसाइटों की सूची में है: {e}",
        "hinglish": "Google ki khatarnak websites ki list mein hai: {e}",
        "en": "Listed by Google as dangerous: {e}",
    },
    Reason.NEW_DOMAIN: {
        "hi": "यह वेबसाइट सिर्फ़ {e} दिन पहले बनी है — धोखे वाली साइटें अक्सर नई होती हैं",
        "hinglish": "Yeh website sirf {e} din pehle bani hai — fraud sites aksar nayi hoti hain",
        "en": "This website was created only {e} days ago — scam sites are usually new",
    },
    Reason.LOOKALIKE_DOMAIN: {
        "hi": "नाम असली वेबसाइट जैसा दिखता है पर अलग है ({e})",
        "hinglish": "Naam asli website jaisa dikhta hai par alag hai ({e})",
        "en": "The name imitates a real website ({e})",
    },
    Reason.REDIRECT_CHAIN: {
        "hi": "लिंक असल में यहाँ ले जाता है: {e}",
        "hinglish": "Link asal mein yahan le jaata hai: {e}",
        "en": "The link actually leads to: {e}",
    },
    Reason.URL_LEXICAL_RISK: {
        "hi": "लिंक का पता अजीब है ({e})",
        "hinglish": "Link ka pata ajeeb hai ({e})",
        "en": "The link address looks odd ({e})",
    },
    Reason.PAGE_ASKS_CREDENTIALS: {
        "hi": "वेबसाइट खोलने पर {e} माँगा जा रहा है",
        "hinglish": "Website kholne par {e} maanga ja raha hai",
        "en": "The website asks for your {e}",
    },
    Reason.PAGE_IMPERSONATES_BRAND: {
        "hi": "वेबसाइट ख़ुद को {e} बताती है, पर यह {e} की असली वेबसाइट नहीं है",
        "hinglish": "Website khud ko {e} batati hai, par yeh {e} ki asli website nahi hai",
        "en": "The website pretends to be {e}, but it is not {e}'s real site",
    },
    Reason.PAGE_DOWNLOADS_APK: {
        "hi": "वेबसाइट खुलते ही ऐप (APK) डाउनलोड करवाती है — इसे इंस्टॉल न करें",
        "hinglish": "Website khulte hi app (APK) download karwati hai — ise install na karein",
        "en": "The website pushes an app (APK) download — do not install it",
    },
    Reason.QR_UPI_PAYMENT: {
        "hi": "फ़ोटो में UPI QR है — इसे स्कैन करने से आपके खाते से पैसे जाएँगे ({e})",
        "hinglish": "Photo mein UPI QR hai — ise scan karne se aapke account se paise JAAYENGE ({e})",
        "en": "The photo has a UPI QR — scanning it SENDS money from your account ({e})",
    },
    Reason.QR_RECEIVE_TRICK: {
        "hi": '"QR स्कैन करके पैसे पाइए" — यह झूठ है। पैसे पाने के लिए कभी QR स्कैन या PIN नहीं डालना होता',
        "hinglish": '"QR scan karke paise paaiye" — yeh jhooth hai. Paise PAANE ke liye kabhi QR scan ya PIN nahi daalna hota',
        "en": '"Scan the QR to receive money" is a lie. You never scan a QR or enter a PIN to RECEIVE money',
    },
    Reason.APK_FILE: {
        "hi": "यह एक ऐप फ़ाइल (APK) है — {e}। WhatsApp पर आए ऐप Play Store की जाँच से नहीं गुज़रते",
        "hinglish": "Yeh ek app file (APK) hai — {e}. WhatsApp par aaye apps Play Store ki jaanch se nahi guzarte",
        "en": "This is an app file (APK) — {e}. Apps sent on WhatsApp skip Play Store safety checks",
    },
    Reason.APK_UNREADABLE: {
        "hi": "यह ऐप फ़ाइल खुल नहीं रही / टूटी या छुपाई गई है — इसे इंस्टॉल न करें",
        "hinglish": "Yeh app file khul nahi rahi / tooti ya chhupayi gayi hai — ise install na karein",
        "en": "This app file is damaged or disguised and can't be checked — don't install it",
    },
    Reason.APK_IMPERSONATES: {
        "hi": "ऐप ख़ुद को बैंक/सरकारी सेवा बताता है ({e}) — बैंक और सरकार कभी WhatsApp पर ऐप नहीं भेजते",
        "hinglish": "App khud ko bank/sarkari seva batata hai ({e}) — bank aur sarkar kabhi WhatsApp par app nahi bhejte",
        "en": "The app poses as a bank/government service ({e}) — they never send apps on WhatsApp",
    },
    Reason.APK_KNOWN_LURE: {
        "hi": '"{e}" — शादी कार्ड/फ़ोटो जैसे नाम वाले ऐप आम धोखा हैं',
        "hinglish": '"{e}" — shaadi card/photo jaise naam wale apps aam fraud hain',
        "en": '"{e}" — wedding-card/photo style app names are a common scam trick',
    },
    Reason.APK_READS_SMS: {
        "hi": "यह ऐप आपके SMS पढ़ सकता है — यानी बैंक के OTP चुरा सकता है",
        "hinglish": "Yeh app aapke SMS padh sakta hai — yaani bank ke OTP chura sakta hai",
        "en": "It can read your SMS — meaning it can steal bank OTPs",
    },
    Reason.APK_ACCESSIBILITY: {
        "hi": "यह ऐप Accessibility माँगता है — इससे वह आपकी स्क्रीन देख और फ़ोन चला सकता है",
        "hinglish": "Yeh app Accessibility maangta hai — isse woh aapki screen dekh aur phone chala sakta hai",
        "en": "It asks for Accessibility — letting it see your screen and control your phone",
    },
    Reason.APK_NOTIFICATION_ACCESS: {
        "hi": "यह ऐप आपकी सारी नोटिफ़िकेशन (OTP समेत) पढ़ सकता है",
        "hinglish": "Yeh app aapki saari notifications (OTP samet) padh sakta hai",
        "en": "It can read all your notifications, including OTPs",
    },
    Reason.APK_DEVICE_ADMIN: {
        "hi": "यह ऐप Device Admin बनना चाहता है — फिर इसे हटाना मुश्किल होता है",
        "hinglish": "Yeh app Device Admin banna chahta hai — phir ise hatana mushkil hota hai",
        "en": "It wants Device Admin rights — making it hard to remove",
    },
    Reason.APK_OVERLAY: {
        "hi": "यह ऐप दूसरे ऐप के ऊपर नकली स्क्रीन दिखा सकता है (जैसे नकली बैंक लॉगिन)",
        "hinglish": "Yeh app doosre apps ke upar nakli screen dikha sakta hai (jaise nakli bank login)",
        "en": "It can draw fake screens over other apps (like a fake bank login)",
    },
    Reason.APK_SENDS_SMS: {
        "hi": "यह ऐप आपके नाम से SMS भेज सकता है ({e})",
        "hinglish": "Yeh app aapke naam se SMS bhej sakta hai ({e})",
        "en": "It can send SMS from your number ({e})",
    },
    Reason.APK_CALL_CONTROL: {
        "hi": "यह ऐप कॉल कर सकता है / कॉल लॉग पढ़ सकता है — कॉल फ़ॉरवर्डिंग धोखे में इस्तेमाल",
        "hinglish": "Yeh app call kar sakta hai / call log padh sakta hai — call forwarding fraud mein use hota hai",
        "en": "It can make calls / read call logs — used in call-forwarding fraud",
    },
    Reason.APK_INSTALLS_APPS: {
        "hi": "यह ऐप चुपके से और ऐप इंस्टॉल करवा सकता है",
        "hinglish": "Yeh app chupke se aur apps install karwa sakta hai",
        "en": "It can install more apps",
    },
    Reason.APK_OTP_STEALER: {
        "hi": "OTP पढ़ना + बाहर भेजना: यह बैंकिंग चोर ऐप का पैटर्न है",
        "hinglish": "OTP padhna + bahar bhejna: yeh banking chor app ka pattern hai",
        "en": "Reads OTPs and can send them out: the banking-trojan pattern",
    },
    Reason.APK_UNSIGNED: {
        "hi": "ऐप पर डेवलपर का हस्ताक्षर नहीं है",
        "hinglish": "App par developer ka signature nahi hai",
        "en": "The app has no developer signature",
    },
    Reason.APK_DEBUG_SIGNED: {
        "hi": "ऐप पर टेस्ट वाला (debug) हस्ताक्षर है — असली कंपनियाँ ऐसा नहीं करतीं",
        "hinglish": "App par test wala (debug) signature hai — asli companies aisa nahi karti",
        "en": "Signed with a test (debug) certificate — real companies don't ship that",
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
    "hi": "🙏 हम टेक्स्ट, लिंक, फ़ोटो और ऐप (APK) फ़ाइलें जाँच सकते हैं। यह फ़ाइल प्रकार अभी नहीं।",
    "hinglish": "🙏 Hum text, link, photo aur app (APK) files check kar sakte hain. Yeh file type abhi nahi.",
    "en": "🙏 We can check text, links, photos and app (APK) files. Not this file type yet.",
}

APK_ADVICE = {
    "hi": "📱 इंस्टॉल न करें। अगर कर लिया है: इंटरनेट बंद करें, ऐप हटाएँ, बैंक को फ़ोन करें और 1930 पर शिकायत करें।",
    "hinglish": "📱 Install na karein. Agar kar liya hai: internet band karein, app hatayein, bank ko call karein aur 1930 par shikayat karein.",
    "en": "📱 Don't install it. If you already did: turn off internet, uninstall it, call your bank and report on 1930.",
}

IMAGE_UNREADABLE = {
    "hi": "🙏 इस फ़ोटो में हमें कोई लिखावट, लिंक या QR कोड नहीं मिला। साफ़ फ़ोटो या स्क्रीनशॉट भेजें, या मैसेज का टेक्स्ट फ़ॉरवर्ड करें।",
    "hinglish": "🙏 Is photo mein humein koi likhawat, link ya QR code nahi mila. Saaf photo ya screenshot bhejein, ya message ka text forward karein.",
    "en": "🙏 We couldn't find any text, link or QR code in this photo. Send a clearer photo or screenshot, or forward the message text.",
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

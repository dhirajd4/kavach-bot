"""Seed evaluation corpus: synthetic scam messages modelled on public CERT-In / I4C / police
advisories, plus everyday benign messages for false-positive checks. Grows with labelled data."""

SCAMS: list[tuple[str, str]] = [
    # (scenario, text)
    (
        "digital_arrest_hinglish",
        "Main CBI officer bol raha hoon. Aapke Aadhaar se ek illegal parcel mila hai jisme drugs hain. "
        "Aap digital arrest mein hain, video call par rahiye warna turant giraftaar honge.",
    ),
    (
        "digital_arrest_hi",
        "मैं मुंबई पुलिस से बोल रहा हूँ। आपके नाम पर मनी लॉन्ड्रिंग का केस है, आप डिजिटल अरेस्ट में हैं।",
    ),
    (
        "fedex_parcel",
        "This is FedEx. Your parcel to Taiwan is seized by customs, it contains drugs. "
        "Mumbai Police cyber crime branch will register FIR. Connect now.",
    ),
    (
        "kyc_block",
        "Dear customer your SBI account will be blocked today. Update KYC immediately: "
        "http://sbi-kyc-update.xyz/login",
    ),
    (
        "kyc_hinglish",
        "Aapka bank account band ho jayega, PAN card update karein turant. Link: hdfc-netbanking.top/pan",
    ),
    (
        "otp_ask",
        "Sir aapke account mein refund aaya hai, process karne ke liye OTP share karein jo abhi aaya hai.",
    ),
    (
        "electricity",
        "Dear consumer your electricity connection will be disconnected tonight at 9.30 pm because "
        "previous month bill was not updated. Call officer 9876543210 immediately.",
    ),
    (
        "lottery",
        "Congratulations! KBC lucky draw mein aapne 25 lakh jeete hain. Prize money ke liye "
        "registration fee Rs 12,500 pay karein.",
    ),
    (
        "job_task",
        "Part time job! Work from home and earn Rs 3000 daily by liking YouTube videos. "
        "Contact on Telegram task group.",
    ),
    (
        "investment",
        "Join our VIP stock group. Guaranteed returns 30% monthly profit, paisa double in 3 months. "
        "IPO allotment through institutional account.",
    ),
    (
        "remote_access",
        "Your refund is pending. Please install AnyDesk app and share the code so our executive "
        "can help you.",
    ),
    (
        "apk_link",
        "PM Kisan new list jaari. Apna naam check karein: https://pmkisan-list.online/PM_Kisan.apk",
    ),
    (
        "sextortion",
        "Your private video will be viral on YouTube and sent to your family. Pay Rs 50000 to delete.",
    ),
]

BENIGN: list[str] = [
    "Kal shaam 6 baje mandir chalenge, mummy ko bhi le aana.",
    "Happy birthday beta! Bahut saara pyaar aur aashirwad.",
    "Doodh khatam ho gaya hai, aate hue 2 packet le aana.",
    "Meeting moved to 3 pm tomorrow, please update the agenda doc.",
    "आज बारिश बहुत हो रही है, ध्यान से आना।",
    "Check out this recipe https://www.youtube.com/watch?v=abc123",
    "Your Amazon order has been delivered. Track at https://www.amazon.in/your-orders",
    "School ki fees is mahine ki 15 tareekh tak jama karni hai.",
    "Dadi ki dawai ka time ho gaya, unko yaad dila dena.",
    "Cricket match dekhne chaloge? India vs Australia kal hai.",
    "Payment of Rs 450 received from Ramesh via UPI. Thank you for shopping!",
    "Police station ke paas wali dukaan se sabzi le aana.",
    "Please read the circular at https://www.rbi.org.in/Scripts/NotificationUser.aspx",
    "Train ka ticket book ho gaya hai, irctc.co.in par PNR check kar lena.",
]

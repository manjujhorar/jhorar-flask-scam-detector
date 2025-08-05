
from flask import Flask, render_template, request
from dotenv import load_dotenv
load_dotenv()
from translations import translations
import os
import re
import requests  # 🔧 MISSING IMPORT
from werkzeug.utils import secure_filename
from PIL import Image
import pytesseract
from pdf2image import convert_from_path
import speech_recognition as sr
from pydub import AudioSegment

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

google_api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'mp3', 'wav'}

official_domains = [
    "gmail.com", "yahoo.com", "outlook.com",
    "airindia.com", "spicejet.com", "indigo.in",
    "goindigo.in", "airvistara.com", "jetairways.com"
]

indian_number_pattern = re.compile(r'^(?:\+91|91|0)?[6-9]\d{9}$')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def check_number_validity(input_text):
    number_pattern = re.compile(r'(\+91)?[6-9]\d{9}')
    flagged_numbers = []

    for match in re.finditer(number_pattern, input_text):
        number = match.group()
        clean_number = number[-10:]
        if len(set(clean_number)) == 1:
            flagged_numbers.append((number, "⚠️ Repeated digits – possible spam"))
        else:
            flagged_numbers.append((number, "ℹ️ Please verify this number on Truecaller"))
    return flagged_numbers

def check_url_with_google_safe_browsing(api_key, url_to_check):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    body = {
        "client": {
            "clientId": "truthguard-ai",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url_to_check}]
        }
    }

    try:
        response = requests.post(api_url, json=body)  # 🔧 FIXED VARIABLE NAME (was: safe_browsing_url)
        if response.status_code == 200:
            result = response.json()
            if "matches" in result:
                return "❌ This link is potentially dangerous (malware/phishing)."
            else:
                return "✅ This link appears safe."
        else:
            return "⚠️ Could not check the link. Try again."
    except Exception:
        return "⚠️ Error checking link with Google Safe Browsing."

def transcribe_audio(file_path):
    r = sr.Recognizer()
    audio = AudioSegment.from_file(file_path)
    audio.export("temp.wav", format="wav")
    with sr.AudioFile("temp.wav") as source:
        audio_data = r.record(source)
        try:
            return r.recognize_google(audio_data)
        except sr.UnknownValueError:
            return ""

@app.route('/', methods=['GET', 'POST'])
def home():
    lang = request.args.get('lang', 'en')
    labels = translations.get(lang, translations['en'])

    result = ""
    user_input = ""
    cybercrime_info = False
    offer_text = ""

    if request.method == 'POST':
        if 'email' in request.form:
            user_input = request.form['email'].strip()
            if '@' in user_input:
                domain = user_input.split('@')[-1]
                if domain in official_domains:
                    result = labels['result_verified']
                else:
                    result = labels['result_fake']
                    cybercrime_info = True
            elif indian_number_pattern.match(user_input):
                number_results = check_number_validity(user_input)
                result = "<br>".join(f"{num}: {note}" for num, note in number_results)
                cybercrime_info = any("⚠️" in note for _, note in number_results)
            else:
                result = labels['result_invalid_number']
                cybercrime_info = True

        if 'offer_file' in request.files:
            file = request.files['offer_file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(path)

                extension = filename.rsplit('.', 1)[1].lower()
                suspicious_keywords = ['lottery', 'you have won', 'urgent', 'click here', 'verify now', 'limited offer']
                verified_keywords = ['thank you for your application', 'your interview is scheduled', 'we appreciate your interest']

                try:
                    if extension == "pdf":
                        images = convert_from_path(path)
                        for img in images:
                            offer_text += pytesseract.image_to_string(img)

                    elif extension in ['png', 'jpg', 'jpeg']:
                        img = Image.open(path)
                        offer_text = pytesseract.image_to_string(img)

                    elif extension in ['mp3', 'wav']:
                        offer_text = transcribe_audio(path)

                    if offer_text and any(word in offer_text.lower() for word in suspicious_keywords):
                        result = "❌ This file may contain SCAM content!"
                        cybercrime_info = True
                    elif offer_text and any(word in offer_text.lower() for word in verified_keywords):
                        result = labels['offer_real']
                    elif offer_text:
                        result = labels['offer_fake']
                        cybercrime_info = True
                    else:
                        result = "⚠️ Could not read the content. Try another file."
                        cybercrime_info = True

                except Exception:
                    result = labels['offer_error']
                    cybercrime_info = True

        if 'user_message' in request.form:
            message = request.form['user_message'].lower()
            suspicious_keywords = ['congratulations', 'lottery', 'click the link', 'urgent', 'bank account', 'you have won', 'limited offer', 'verify now']
            real_keywords = ['thank you for your application', 'your interview is scheduled', 'we appreciate your interest']

            url_pattern = re.compile(r'https?://[^\s]+')
            urls = url_pattern.findall(message)

            if urls:
                result = ""
                for url in urls:
                    result += check_url_with_google_safe_browsing(google_api_key, url) + "<br>"
                cybercrime_info = True
            elif any(word in message for word in suspicious_keywords):
                result = "❌ This message may be a SCAM. Be careful!"
                cybercrime_info = True
            elif any(word in message for word in real_keywords):
                result = "✅ This message seems genuine."
            else:
                result = "⚠️ Could not determine. Please verify manually."

    return render_template("index.html",
        labels=labels,
        lang=lang,
        result=result,
        user_input=user_input,
        cybercrime_info=cybercrime_info,
        offer_text=offer_text,
        download_poster="Download Poster",
        offer_result=result if 'offer_file' in request.files else "")

if __name__ == "__main__":
    app.run(debug=True)

=======
from flask import Flask, render_template, request
import os
import re
from werkzeug.utils import secure_filename
from PIL import Image
import pytesseract
from pdf2image import convert_from_path

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

official_domains = [
    "gmail.com", "yahoo.com", "outlook.com",
    "airindia.com", "spicejet.com", "indigo.in",
    "goindigo.in", "airvistara.com", "jetairways.com"
]

verified_keywords = ['airindia.com', 'Government of India', 'IndiGo', 'Jet Airways', 'Ministry of', 'Air Vistara']

indian_number_pattern = re.compile(r'^(?:\+91|91|0)?[6-9]\d{9}$')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def check_number_validity(input_text):
    number_pattern = re.compile(r'(\+91)?[6-9]\d{9}')
    flagged_numbers = []

    for match in re.finditer(number_pattern, input_text):
        number = match.group()
        clean_number = number[-10:]
        if len(set(clean_number)) == 1:
            flagged_numbers.append((number, "⚠️ Repeated digits – possible spam"))
        else:
            flagged_numbers.append((number, "ℹ️ Please verify this number on Truecaller"))

    return flagged_numbers

# 🌐 Translation Dictionary
translations = {
    'en': {
        'tool_name': "TRUTHGUARD AI – Scam Detector",
        'header_tagline': "Online scams are smarter than ever—but so are we.",
        'input_label': "Enter email or mobile number",
        'submit': "Check",
        'upload_label': "Upload Offer Letter (PDF/JPG/PNG)",
        'offer_title': "📝 Upload Offer Letter or Screenshot",
        'offer_subtitle': "Check if your offer letter is real or fake (AI-based check)",
        'upload_button': "Verify Offer Letter",
        'offer_result': "Offer Letter Scan Result",
        'result': "Result",
        'cybercrime_info': "🚨 Suspicious? Report: 1930 | cybercrime.gov@nic.in",
        'result_verified': "✅ This is a verified official email.",
        'result_fake': "❌ This email may be FAKE. Do not trust it.",
        'result_valid_number': "✅ Possibly valid Indian number (format matched).",
        'result_invalid_number': "⚠️ Invalid number format or suspected pattern.",
        'offer_real': "✅ This offer letter appears authentic and from verified source.",
        'offer_fake': "⚠️ This offer letter seems suspicious or fake. Please verify manually.",
        'offer_error': "❌ Could not scan the uploaded file. Error occurred.",
        'benefits_title': "Benefits of Using TRUTHGUARD AI",
        'benefit_1': "✔️ Real-time scam detection",
        'benefit_2': "✔️ Multi-language awareness",
        'benefit_3': "✔️ 100% free educational tool",
        'benefit_4': "✔️ No user data stored",
        'benefit_5': "✔️ WhatsApp, email, and link scanner",
        'benefit_6': "✔️ Cybercrime info if fraud found",
        'benefit_7': "✔️ Compliant with all policies",
        'other_tools_title': "Other AI Scam Detection Tools",
        'tool_1': "🛡️ ScamAdviser",
        'tool_2': "🛡️ Norton Safe Web",
        'tool_3': "🛡️ VirusTotal",
        'footer_disclaimer': "This tool provides basic scam detection and does not store any user data.",
        'founder_line': "Founder: Manju Jhorar | 2025 | Contact: 8930765334",
        'legal_1': "Information Technology Act, 2000 (India)",
        'legal_2': "Indian Penal Code (IPC)",
        'legal_3': "General Data Protection Regulation (GDPR)",
        'legal_4': "Cyber Crime Guidelines, Govt of India",
        'legal_5': "AI Ethics & Transparency Principles"
    },
    'hi': {
        'tool_name': "ट्रुथगार्ड एआई – स्कैम डिटेक्टर",
        'header_tagline': "ऑनलाइन ठगी पहले से होशियार है—but अब हम भी।",
        'input_label': "ईमेल या मोबाइल नंबर दर्ज करें",
        'submit': "जांचें",
        'upload_label': "ऑफर लेटर अपलोड करें (PDF/JPG/PNG)",
        'offer_title': "📝 ऑफर लेटर या स्क्रीनशॉट अपलोड करें",
        'offer_subtitle': "जांचें कि आपका ऑफर लेटर असली है या नकली (AI आधारित)",
        'upload_button': "ऑफर लेटर जांचें",
        'offer_result': "ऑफर लेटर स्कैन परिणाम",
        'result': "परिणाम",
        'cybercrime_info': "🚨 संदिग्ध? रिपोर्ट करें: 1930 | cybercrime.gov@nic.in",
        'result_verified': "✅ यह सत्यापित आधिकारिक ईमेल है।",
        'result_fake': "❌ यह ईमेल फर्जी हो सकता है।",
        'result_valid_number': "✅ यह एक वैध मोबाइल नंबर जैसा लग रहा है।",
        'result_invalid_number': "⚠️ नंबर गलत है या पैटर्न संदिग्ध है।",
        'offer_real': "✅ यह ऑफर लेटर असली लग रहा है।",
        'offer_fake': "⚠️ यह ऑफर लेटर फर्जी हो सकता है। कृपया जांचें।",
        'offer_error': "❌ अपलोड फाइल स्कैन नहीं हो पाई।",
        'benefits_title': "ट्रुथगार्ड एआई के लाभ",
        'benefit_1': "✔️ रियल टाइम स्कैम डिटेक्शन",
        'benefit_2': "✔️ बहुभाषा समर्थन",
        'benefit_3': "✔️ 100% मुफ़्त टूल",
        'benefit_4': "✔️ कोई यूजर डेटा स्टोर नहीं होता",
        'benefit_5': "✔️ ईमेल, नंबर, लिंक स्कैनर",
        'benefit_6': "✔️ फ्रॉड मिलने पर साइबर जानकारी",
        'benefit_7': "✔️ सभी नीतियों के अनुरूप",
        'other_tools_title': "अन्य AI स्कैम टूल",
        'tool_1': "🛡️ ScamAdviser",
        'tool_2': "🛡️ Norton Safe Web",
        'tool_3': "🛡️ VirusTotal",
        'footer_disclaimer': "यह टूल उपयोगकर्ता डेटा स्टोर नहीं करता।",
        'founder_line': "संस्थापक: मंजू झोरड़ | 2025 | संपर्क: 8930765334",
        'legal_1': "सूचना प्रौद्योगिकी अधिनियम, 2000 (भारत)",
        'legal_2': "भारतीय दंड संहिता (IPC)",
        'legal_3': "GDPR नीति",
        'legal_4': "भारत सरकार के साइबर क्राइम दिशा-निर्देश",
        'legal_5': "AI नैतिकता और पारदर्शिता सिद्धांत"
    },
    'ha': {
        'tool_name': "TRUTHGUARD एआई – ठगी पकड़न वाला टूल",
        'header_tagline': "ऑनलाइन चोर अब चालाक हो लिए—but अब हम भी चालाक सै।",
        'input_label': "ईमेल या नंबर डालो",
        'submit': "जांच करो",
        'upload_label': "ऑफर लेटर चढ़ाओ (PDF/JPG/PNG)",
        'offer_title': "📝 ऑफर लैटर या फोटो अपलोड करो",
        'offer_subtitle': "देखो असली ऑफर लैटर है या नकली",
        'upload_button': "ऑफर लैटर जांचो",
        'offer_result': "ऑफर लैटर स्कैन का नतीजा",
        'result': "नतीजा",
        'cybercrime_info': "🚨 शक हो तो बताओ: 1930 | cybercrime.gov@nic.in",
        'result_verified': "✅ यो ऑफिशियल ईमेल सै।",
        'result_fake': "❌ यो ईमेल नकली लागे सै।",
        'result_valid_number': "✅ यो नंबर बढ़िया लागे सै।",
        'result_invalid_number': "⚠️ नंबर गड़बड़ लागे सै।",
        'offer_real': "✅ यो ऑफर लैटर सही लागे सै।",
        'offer_fake': "⚠️ यो लैटर नकली हो सके सै।",
        'offer_error': "❌ फाइल समझ ना आई।",
        'benefits_title': "TRUTHGUARD के फायदे",
        'benefit_1': "✔️ फटाफट स्कैम पकड़ण",
        'benefit_2': "✔️ भाषा सपोर्ट",
        'benefit_3': "✔️ बिल्कुल फ्री टूल",
        'benefit_4': "✔️ डेटा ना स्टोर होवे",
        'benefit_5': "✔️ नंबर-ईमेल स्कैनर",
        'benefit_6': "✔️ धोखा मिले तो रिपोर्ट",
        'benefit_7': "✔️ नियम अनुसार टूल",
        'other_tools_title': "दूसरे AI टूल",
        'tool_1': "🛡️ ScamAdviser",
        'tool_2': "🛡️ Norton Safe Web",
        'tool_3': "🛡️ VirusTotal",
        'footer_disclaimer': "डेटा स्टोर कोणी, साधारण जांच।",
        'founder_line': "फाउंडर: मंजू झोरड़ | 2025 | मोबाइल: 8930765334",
        'legal_1': "IT एक्ट 2000",
        'legal_2': "भारतीय दंड संहिता (IPC)",
        'legal_3': "GDPR",
        'legal_4': "साइबर क्राइम गाइडलाइन",
        'legal_5': "AI नीति और ईमानदारी"
    }
}

@app.route('/', methods=['GET', 'POST'])
def home():
    lang = request.args.get('lang', 'en')
    labels = translations.get(lang, translations['en'])

    result = ""
    user_input = ""
    cybercrime_info = False
    offer_text = ""

    if request.method == 'POST':
        if 'email' in request.form:
            user_input = request.form['email'].strip()

            if '@' in user_input:
                domain = user_input.split('@')[-1]
                if domain in official_domains:
                    result = labels['result_verified']
                else:
                    result = labels['result_fake']
                    cybercrime_info = True
            elif indian_number_pattern.match(user_input):
                number_results = check_number_validity(user_input)
                result = "<br>".join(f"{num}: {note}" for num, note in number_results)
                cybercrime_info = any("⚠️" in note for _, note in number_results)
            else:
                result = labels['result_invalid_number']
                cybercrime_info = True

        if 'offer_file' in request.files:
            file = request.files['offer_file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(path)

                try:
                    if filename.lower().endswith("pdf"):
                        images = convert_from_path(path)
                        for img in images:
                            offer_text += pytesseract.image_to_string(img)
                    else:
                        img = Image.open(path)
                        offer_text = pytesseract.image_to_string(img)

                    if any(word.lower() in offer_text.lower() for word in verified_keywords):
                        result = labels['offer_real']
                    else:
                        result = labels['offer_fake']
                        cybercrime_info = True

                except Exception:
                    result = labels['offer_error']
                    cybercrime_info = True

    return render_template("index.html",
                           labels=labels,
                           lang=lang,
                           result=result,
                           user_input=user_input,
                           cybercrime_info=cybercrime_info,
                           offer_text=offer_text)

if __name__ == '__main__':
    app.run(debug=True)
93469b1b73e907cfe88f4756c1bbe1dd763b61a3

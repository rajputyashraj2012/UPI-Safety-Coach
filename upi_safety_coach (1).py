# ================================================================
# UPI SAFETY COACH  v2.0  —  one-file, multi-page Streamlit app
#
# An offline, privacy-first awareness tool for UPI / digital-payment safety
# in India. It never connects to a bank, never initiates a payment and never
# stores what you type on disk.
#
# Install (Python 3.9+):
#   python -m pip install "streamlit>=1.30" pandas numpy scikit-learn plotly reportlab
#
# Run:
#   streamlit run upi_safety_coach.py
# ================================================================

from __future__ import annotations

import html
import random
import re
import warnings
from datetime import date, datetime
from io import BytesIO
from urllib.parse import urlparse

warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    REPORTLAB_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    REPORTLAB_AVAILABLE = False


# ----------------------------------------------------------------
# PAGE CONFIG + GLOBALS
# ----------------------------------------------------------------
st.set_page_config(
    page_title="UPI Safety Coach | Digital Payment Protection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

APP_NAME = "UPI Safety Coach"
APP_VERSION = "2.0"


def _streamlit_version() -> tuple[int, int]:
    parts = []
    try:
        for p in str(st.__version__).split(".")[:2]:
            m = re.match(r"\d+", p)
            parts.append(int(m.group()) if m else 0)
    except Exception:
        pass
    while len(parts) < 2:
        parts.append(0)
    return parts[0], parts[1]


# Newer Streamlit deprecates `use_container_width` in favour of `width="stretch"`.
STRETCH = {"width": "stretch"} if _streamlit_version() >= (1, 50) else {"use_container_width": True}

HELPLINE = "1930"
PORTAL = "https://www.cybercrime.gov.in"


# ----------------------------------------------------------------
# CONTENT: SCAM LIBRARY, FAQ, QUIZ, RULES
# ----------------------------------------------------------------
SCAMS = [
    {
        "name": "Fake QR code / receive-money trick",
        "category": "QR code",
        "risk": "High",
        "signals": ["scan this qr to receive", "scan qr to get money", "receive your refund by scanning",
                    "enter pin to receive", "cashback qr", "prize qr", "scan to receive"],
        "explanation": "A QR code can initiate a payment. Scanning it is never a way to receive money safely.",
        "action": "Do not scan it or enter your UPI PIN. Ask the sender to use a legitimate payment/refund process.",
        "example": "Scan this QR and enter your UPI PIN to receive ₹5,000.",
    },
    {
        "name": "Unexpected collect request",
        "category": "Collect request",
        "risk": "High",
        "signals": ["collect request", "approve to receive", "payment request pending",
                    "accept request to get", "approve payment request"],
        "explanation": "Approving a collect request and entering your PIN may authorise money to leave your account.",
        "action": "Decline requests you do not recognise. Never approve a request just to receive money.",
        "example": "You have received a collect request. Approve it to receive your refund.",
    },
    {
        "name": "Fake customer-care agent",
        "category": "Impersonation",
        "risk": "High",
        "signals": ["customer care", "support agent", "share otp", "tell me your pin", "otp batao",
                    "pin batao", "install anydesk", "screen sharing", "remote access"],
        "explanation": "A fraudster may impersonate bank or app support and ask for confidential details or remote access.",
        "action": "End the call. Never share PIN/OTP or screen access. Contact support from the official app or bank website.",
        "example": "I am from UPI support. Tell me your OTP to solve your failed transaction.",
    },
    {
        "name": "Phishing link / fake KYC",
        "category": "Phishing",
        "risk": "High",
        "signals": ["kyc expired", "account blocked", "verify immediately", "click this link",
                    "update kyc", "suspend your account", "kyc update karo"],
        "explanation": "Urgent messages may use fake links to steal login or banking information.",
        "action": "Do not click the link. Open your official bank app independently and verify with the bank.",
        "example": "Your bank account will be blocked today. Click this link to update KYC.",
    },
    {
        "name": "Fake payment screenshot",
        "category": "Fake proof",
        "risk": "Medium",
        "signals": ["payment screenshot", "sent screenshot", "payment successful screenshot",
                    "check screenshot", "showed transaction screenshot"],
        "explanation": "Screenshots and edited SMS messages can be forged and do not prove that money reached your account.",
        "action": "Check your own UPI app transaction history and bank account before handing over goods.",
        "example": "The buyer shows a payment success screenshot and asks you to give the product.",
    },
    {
        "name": "Refund / cashback scam",
        "category": "Refund scam",
        "risk": "High",
        "signals": ["refund fee", "cashback fee", "pay to receive refund", "refund qr",
                    "enter pin for refund", "prize money", "processing fee"],
        "explanation": "A genuine refund should not require you to send money or reveal your UPI PIN.",
        "action": "Do not pay a fee or approve a payment to receive a refund. Verify through the merchant's official channel.",
        "example": "Pay ₹10 processing fee and enter your PIN to receive your refund.",
    },
    {
        "name": "Remote-access app scam",
        "category": "Remote access",
        "risk": "High",
        "signals": ["install app", "share your screen", "remote access", "screen control",
                    "download apk", "anydesk", "teamviewer", "quicksupport"],
        "explanation": "Remote-control or screen-sharing access can expose sensitive information and payment activity.",
        "action": "Do not install unknown apps or share your screen during banking. Remove suspicious apps and contact your bank if exposed.",
        "example": "Install this APK and share your screen so I can fix your UPI.",
    },
    {
        "name": "Impersonation / urgent money request",
        "category": "Impersonation",
        "risk": "High",
        "signals": ["urgent payment", "i am your relative", "police officer", "send money immediately",
                    "emergency transfer", "new number", "paise bhej do"],
        "explanation": "A scammer may pretend to be a relative or official and pressure you to transfer money quickly.",
        "action": "Pause and verify using a known phone number or a separate trusted channel before paying.",
        "example": "I changed my number. I am in an emergency. Transfer money immediately.",
    },
    {
        "name": "Fake seller / advance payment",
        "category": "Online shopping",
        "risk": "Medium",
        "signals": ["advance payment", "too good to be true", "guaranteed profit",
                    "pay first", "unbelievable discount", "investment return"],
        "explanation": "Fraudulent sellers or promoters may demand advance UPI transfers for fake goods or unrealistic returns.",
        "action": "Check the seller independently, avoid pressure, and do not transfer money to unverified accounts.",
        "example": "Pay in advance to get a phone at 80% discount. Offer expires in five minutes.",
    },
    {
        "name": "Wrong-transfer 'please send it back' trick",
        "category": "Wrong transfer",
        "risk": "Medium",
        "signals": ["sent by mistake", "wrongly transferred", "please return the money", "send it back",
                    "mistakenly sent", "refund me"],
        "explanation": "A stranger credits your account, then pleads for the money back (often to a different number). The credit may be the proceeds of another fraud, or the 'return' request itself may be the scam.",
        "action": "Do not send money to a new number. Tell your bank about the unexpected credit and let the bank handle any reversal.",
        "example": "I sent ₹5,000 to you by mistake. Please send it back to this other UPI ID right now.",
    },
    {
        "name": "Fake job / task-based earning",
        "category": "Job / task scam",
        "risk": "High",
        "signals": ["work from home", "part time job", "complete tasks", "like and subscribe to earn",
                    "earn daily", "deposit to unlock", "task commission"],
        "explanation": "Fraudsters promise easy income for simple online tasks, pay small amounts at first, then demand larger 'deposits' to unlock earnings.",
        "action": "Never pay to get a job or to withdraw 'earnings'. Verify the employer through official channels.",
        "example": "Earn ₹3,000 daily by rating products. Deposit ₹2,000 to unlock your next task.",
    },
    {
        "name": "Utility disconnection threat",
        "category": "Utility scam",
        "risk": "Medium",
        "signals": ["electricity will be disconnected", "power will be cut", "bill not updated",
                    "disconnect tonight", "sim will be blocked", "pay immediately to avoid disconnection"],
        "explanation": "Fake electricity, gas or telecom messages threaten disconnection tonight unless you call a number or pay through a link.",
        "action": "Do not call the number or click the link. Check your bill in the provider's official app or website.",
        "example": "Your electricity will be disconnected tonight. Call this number and pay the pending bill.",
    },
    {
        "name": "Fake police / 'digital arrest' call",
        "category": "Fake authority",
        "risk": "High",
        "signals": ["digital arrest", "cbi officer", "narcotics", "customs parcel", "money laundering case",
                    "stay on video call", "safe account", "arrest warrant"],
        "explanation": "Callers pose as police, customs or CBI officers, claim you are linked to a crime, keep you on a video call and demand money to a 'safe account'. No genuine agency does this.",
        "action": "Hang up. Genuine agencies do not arrest people over video call or ask for payments. Report on 1930.",
        "example": "A parcel in your name had illegal items. You are under digital arrest. Stay on video and transfer money to a safe account.",
    },
]

FAQ = [
    ("What is UPI?", "UPI stands for Unified Payments Interface. It enables instant bank-to-bank payments through supported apps in India."),
    ("What is a UPI ID?", "A UPI ID (VPA) is a payment address such as name@bank. Always check the name shown for a UPI ID before you pay."),
    ("What is a UPI PIN?", "A UPI PIN is a secret code used to authorise UPI payments. Never share it with anyone, including bank or app staff."),
    ("Do I need a UPI PIN to receive money?", "No. Receiving money never requires your UPI PIN. If a screen asks for your PIN, you are about to authorise a payment out of your account."),
    ("Can I scan a QR code to receive money?", "No. Scanning a QR code is used to pay. Never scan a code on the claim that it will deliver money to you."),
    ("Is it safe to scan a QR code?", "Scanning a merchant's QR to pay is fine if you check the payee name and amount before entering your PIN. Never scan a QR to 'receive' money, a refund or a prize."),
    ("What is a collect request?", "A collect request asks you to approve a payment. If you approve it and enter your PIN, money may be debited."),
    ("I got a collect request. What should I do?", "Decline it unless you recognise the sender and expect to pay. Never approve a request to 'receive' a refund or prize, because approval sends money out."),
    ("A buyer showed a payment screenshot.", "Do not rely on screenshots or forwarded SMS messages, as they can be forged. Open your own UPI app or bank statement and confirm the credit before handing over goods."),
    ("Is a payment screenshot proof?", "No. Screenshots can be edited. Check your own UPI app and bank account to confirm the credit."),
    ("What should I do if I shared my OTP?", "Contact your bank immediately through official channels and secure the affected account. Check recent transactions. If money was lost, call 1930 and report at cybercrime.gov.in."),
    ("Can a bank employee ask for my OTP or PIN?", "No. Genuine bank and UPI-app staff never ask for your PIN, OTP, CVV or password. End the call and contact the bank from its official app or website."),
    ("What if my payment is pending?", "Do not repeat the payment immediately. Check the status in your official UPI app and bank statement, note the transaction ID, and contact official support if it does not resolve."),
    ("What if I sent money to the wrong person?", "Contact your bank and UPI app immediately with the transaction ID and raise a complaint in the app. Recovery is not guaranteed; if the bank does not resolve it you can escalate to the RBI Ombudsman at cms.rbi.org.in."),
    ("Someone sent me money by mistake and wants it back. What should I do?", "Do not send money to a new number or UPI ID. Inform your bank about the unexpected credit and let the bank handle any reversal; the credit can be linked to fraud."),
    ("How do I report UPI fraud?", "Call 1930 immediately, report at https://www.cybercrime.gov.in, contact your bank and UPI app through official channels, and preserve evidence."),
    ("How do I contact customer care?", "Use the Help/Support section inside your official UPI or banking app, or the contact details on the bank's official website. Avoid numbers found through random search results."),
    ("How can I stay safe from UPI scams? How do I avoid being scammed?", "Follow the golden rules: never share your PIN or OTP, never enter a PIN to receive money, check the payee name before paying, decline unexpected collect requests, and verify credits in your own app rather than from screenshots."),
    ("How do I choose a safe UPI PIN?", "Avoid birthdays, phone numbers, repeated or sequential digits. Never write it down or save it in notes, and change it if you suspect anyone has seen it."),
]

QUIZ = [
    {"q": "A stranger says you must enter your UPI PIN to receive ₹2,000. What should you do?",
     "options": ["Enter the PIN quickly", "Decline and do not share the PIN", "Send your OTP instead", "Scan their QR code"],
     "answer": 1, "topic": "QR code",
     "why": "A UPI PIN is used to authorise a payment, not to receive money."},
    {"q": "A buyer shows you a payment success screenshot. What is the safest verification?",
     "options": ["Trust the screenshot", "Ask them to forward an SMS", "Check your own UPI app and bank account", "Hand over the item immediately"],
     "answer": 2, "topic": "Fake proof",
     "why": "Screenshots can be edited. Verify the credit in your own account."},
    {"q": "You receive an unexpected collect request. What should you do?",
     "options": ["Approve it", "Decline if you do not recognise it", "Enter PIN to check", "Forward it to friends"],
     "answer": 1, "topic": "Collect request",
     "why": "Approving a collect request may authorise money to leave your account."},
    {"q": "A caller claiming to be bank support asks for your OTP. What should you do?",
     "options": ["Share it", "Share only half", "End the call and contact the bank officially", "Send your UPI ID and PIN"],
     "answer": 2, "topic": "Impersonation",
     "why": "Never share OTPs, PINs or passwords with callers."},
    {"q": "You suspect money has been stolen through UPI. Which action should be taken immediately?",
     "options": ["Wait for a week", "Call 1930 and contact your bank", "Delete all messages", "Pay a recovery agent"],
     "answer": 1, "topic": "Reporting",
     "why": "Report financial cyber fraud quickly using 1930, the cybercrime portal and your bank."},
    {"q": "A message says your KYC will expire and provides a suspicious link. What is safest?",
     "options": ["Click and enter details", "Forward the link", "Open your official bank app independently", "Reply with OTP"],
     "answer": 2, "topic": "Phishing",
     "why": "Do not use unsolicited links. Verify directly through the official bank channel."},
    {"q": "Someone asks you to install a remote-access app to fix a payment. What should you do?",
     "options": ["Install it", "Share your screen", "Refuse and contact official support", "Open your banking app while sharing"],
     "answer": 2, "topic": "Remote access",
     "why": "Remote access can expose your device and payment activity."},
    {"q": "A payment is pending. Should you immediately pay again?",
     "options": ["Yes, always", "No, first verify status in the app and bank statement", "Pay twice to be safe", "Share OTP with the recipient"],
     "answer": 1, "topic": "Reporting",
     "why": "Check the first transaction's status before trying again."},
    {"q": "A stranger credits ₹5,000 to your account 'by mistake' and asks you to send it to a different UPI ID. What is the safest step?",
     "options": ["Send it back immediately", "Tell your bank and let it handle any reversal", "Send double to be polite", "Share your OTP so they can reverse it"],
     "answer": 1, "topic": "Wrong transfer",
     "why": "The credit may come from another fraud. Do not pay a new account; involve your bank."},
    {"q": "A caller says you are under 'digital arrest' and must stay on a video call and move money to a 'safe account'. What is true?",
     "options": ["Genuine agencies do this for serious cases", "No genuine agency does this; hang up and report on 1930",
                 "Pay quickly to avoid jail", "Install the app they suggest"],
     "answer": 1, "topic": "Fake authority",
     "why": "There is no such thing as a 'digital arrest', and no agency asks for money to a safe account."},
]

GOLDEN_RULES = [
    "Never share your UPI PIN, OTP, CVV or password with anyone.",
    "Never enter your UPI PIN to receive money, a refund, a prize or cashback.",
    "Check the payee name, UPI ID and amount before you authorise a payment.",
    "Decline collect requests you did not expect.",
    "Verify credits in your own UPI app or bank account, never from screenshots.",
]

MYTHS = [
    ("I must enter my PIN to receive money.", "Receiving money never needs your PIN. A PIN screen means money is leaving."),
    ("Scanning a QR code can credit my account.", "A QR scan sets up a payment from you. Nothing is received by scanning."),
    ("A payment screenshot proves I was paid.", "Screenshots are easily forged. Only your own app or statement counts."),
    ("Bank staff may ask for an OTP to 'verify' me.", "Genuine staff never ask for OTP, PIN, CVV or passwords."),
    ("Paying a small fee will release my refund or prize.", "Genuine refunds never need advance fees. This is a standard scam."),
    ("The caller knew my name, so they must be genuine.", "Scammers buy leaked data. Knowing your details proves nothing."),
]

LESSONS = [
    ("What is UPI?", "UPI stands for Unified Payments Interface. It enables instant bank-to-bank payments through supported apps in India."),
    ("UPI ID / VPA", "A UPI ID is a payment address, often shown in a format such as name@bank. Check the displayed recipient before sending money."),
    ("UPI PIN", "A secret code used to authorise a UPI payment. Never share it with another person, including someone claiming to be bank support."),
    ("QR code", "A QR code can contain payment details. Scanning it and approving the transaction can send money. A QR code is not a way to receive money."),
    ("Collect request", "A request asking you to approve a payment. If you approve it and enter your UPI PIN, money may be debited."),
    ("OTP", "A one-time password used for authentication in some services. Treat it as secret and never read it out to callers."),
    ("Payment verification", "Open your own payment app and bank account to confirm a credit or debit. Do not rely only on screenshots or forwarded SMS messages."),
]

INCIDENT_STEPS = [
    "End the suspicious call or chat. Do not approve any pending request.",
    f"Call **{HELPLINE}** as soon as possible.",
    f"Report the incident at **{PORTAL}** and keep the acknowledgement/reference number.",
    "Contact your bank and UPI app through official channels. Ask how to secure the account and payment access.",
    "Save transaction ID/UTR, date/time, amount, beneficiary details shown, bank messages, phone numbers, chats and screenshots.",
    "Do not delete evidence and do not pay anyone who promises guaranteed recovery.",
    "If credentials were exposed, secure the account and reset affected credentials through the official bank/app process.",
]

QUICK_QUESTIONS = [
    "Do I need a PIN to receive money?",
    "I got a collect request. What should I do?",
    "How can I report UPI fraud?",
    "A buyer showed a payment screenshot.",
    "Is it safe to scan a QR code?",
    "What if I sent money to the wrong person?",
]

SAMPLE_MESSAGES = [
    "Scan this QR and enter your UPI PIN to receive ₹5,000 cashback.",
    "Your KYC expires today. Click this link to avoid account blocking: http://sbi-kyc-update.xyz/login",
    "I am from bank support. Share the OTP so I can reverse your payment.",
]

TOPIC_TO_CATEGORY = {c: c for c in {s["category"] for s in SCAMS}}

# ----------------------------------------------------------------
# SESSION STATE
# ----------------------------------------------------------------
NAV_ITEMS = [
    "🏠 Overview",
    "🔎 Scam Checker",
    "📚 Learn UPI",
    "🚨 Scam Library",
    "🧠 Safety Quiz",
    "🆘 Emergency Help",
    "💬 Safety Assistant",
    "📊 Reports & Settings",
]
WELCOME = ("Hi! I'm UPI Safety Coach. Ask me about UPI safety, suspicious messages, scams or reporting fraud. "
           "Never share your UPI PIN or OTP here.")


def init_state() -> None:
    defaults = {
        "dark_mode": False,
        "nav": NAV_ITEMS[0],
        "activity": [],
        "quiz_round": 0,
        "quiz_result": None,
        "quiz_best": None,
        "chat_history": [{"role": "assistant", "content": WELCOME}],
        "checker_input": "",
        "incident_summary": "",
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def goto(page_name: str) -> None:
    st.session_state.nav = page_name


def log_activity(kind: str, detail: str) -> None:
    """Session-only log. Detail is redacted and truncated; nothing is written to disk."""
    safe, _ = redact_sensitive(detail)
    st.session_state.activity.append(
        {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "activity": kind, "detail": safe[:200]}
    )
    del st.session_state.activity[:-200]


# ----------------------------------------------------------------
# DESIGN SYSTEM
# ----------------------------------------------------------------
CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Plus+Jakarta+Sans:wght@600;700;800&display=swap');
html, body, [class*="css"] { font-family: Inter, sans-serif; }
.stApp { background:@@BG@@; color:@@TEXT@@; min-height:100vh; }
.block-container { max-width:1400px; padding:1.4rem 2rem 4rem; }

.hero { position:relative; overflow:hidden; padding:38px 42px; margin-bottom:24px; border-radius:30px; color:white;
  background:linear-gradient(115deg,rgba(3,48,71,.98),rgba(0,119,182,.90),rgba(18,181,203,.82));
  box-shadow:0 28px 70px rgba(0,92,135,.22); }
.hero:after { content:""; position:absolute; width:320px; height:320px; right:-100px; top:-130px;
  border-radius:50%; background:rgba(255,255,255,.09); }
.hero:before { content:"🛡️"; position:absolute; right:7%; bottom:8%; font-size:92px; opacity:.14; }
.hero h1 { position:relative; z-index:2; font-family:'Plus Jakarta Sans',sans-serif;
  font-size:clamp(34px,5vw,56px); margin:10px 0 0; font-weight:800; letter-spacing:-.05em; }
.hero p { position:relative; z-index:2; max-width:900px; font-size:16px; line-height:1.65; color:rgba(255,255,255,.93); }
.pill { display:inline-block; position:relative; z-index:3; padding:7px 12px; margin:3px 4px 5px 0; border-radius:999px;
  background:rgba(255,255,255,.12); border:1px solid rgba(255,255,255,.22); font-size:11px; font-weight:800; letter-spacing:.5px; }

.section-title { margin:27px 0 13px; color:@@SECTION@@; font-family:'Plus Jakarta Sans',sans-serif; font-size:24px; font-weight:800; }

.metric { position:relative; overflow:hidden; padding:22px; border-radius:24px; color:white; min-height:132px;
  display:flex; flex-direction:column; justify-content:space-between; border:1px solid rgba(255,255,255,.25);
  background:linear-gradient(135deg,#177da3,#42bfd1); box-shadow:0 18px 35px rgba(4,73,103,.15); transition:transform .25s ease; }
.metric:hover { transform:translateY(-5px); }
.metric h4 { margin:0; font-size:14px; opacity:.94; font-weight:700; }
.metric h2 { margin:14px 0 0; font-size:clamp(22px,2.1vw,34px); font-weight:800; letter-spacing:-.03em; }
.metric-1 { background:linear-gradient(135deg,#17865e,#4cc08e); }
.metric-2 { background:linear-gradient(135deg,#6847a5,#8e6bd1); }
.metric-3 { background:linear-gradient(135deg,#bd6c17,#efa947); }
.metric-4 { background:linear-gradient(135deg,#ad3945,#df626c); }

.stButton>button, .stDownloadButton>button, .stFormSubmitButton>button { border:0; border-radius:15px; min-height:45px;
  font-weight:700; color:white; background:linear-gradient(135deg,#075985,#12b5cb); box-shadow:0 9px 22px rgba(7,89,133,.20);
  transition:all .2s ease; }
.stButton>button:hover, .stDownloadButton>button:hover, .stFormSubmitButton>button:hover { transform:translateY(-2px); filter:brightness(1.06); color:white; }

section[data-testid="stSidebar"] { min-width:305px; background:
  radial-gradient(circle at 15% 15%,rgba(0,212,255,.12),transparent 28%),
  linear-gradient(180deg,#021923 0%,#043b55 50%,#021923 100%); }
section[data-testid="stSidebar"]>div { padding:1.1rem .9rem 1.5rem; }
section[data-testid="stSidebar"] * { color:#ecfeff; }
.brand { text-align:center; padding:10px 0 22px; }
.brand-icon { font-size:48px; filter:drop-shadow(0 0 15px rgba(0,212,255,.5)); }
.brand-name { color:white; font-size:26px; font-weight:850; }
.brand-tag { color:#7ddcf0; font-size:9px; letter-spacing:2px; font-weight:800; margin-top:4px; }
.nav-title { color:white; font-size:13px; font-weight:800; letter-spacing:2px; margin:18px 8px 12px; }
section[data-testid="stSidebar"] .stButton { margin-bottom:9px; }
section[data-testid="stSidebar"] .stButton>button { width:100%; min-height:54px; padding:0 16px; text-align:left;
  justify-content:flex-start; border-radius:16px; border:1px solid rgba(180,240,255,.18); color:#e9fbff!important;
  background:linear-gradient(135deg,rgba(255,255,255,.13),rgba(255,255,255,.045)); box-shadow:0 10px 25px rgba(0,0,0,.18); font-size:14px; }
section[data-testid="stSidebar"] .stButton>button:hover { background:rgba(50,205,235,.25); border-color:rgba(150,235,255,.48); }
section[data-testid="stSidebar"] .stButton>button[kind="primary"],
section[data-testid="stSidebar"] button[data-testid="stBaseButton-primary"] {
  background:linear-gradient(135deg,rgba(35,194,224,.45),rgba(70,110,220,.28))!important;
  border-color:rgba(165,240,255,.75)!important; transform:translateX(3px); }

.status-strip { display:flex; justify-content:space-between; gap:16px; margin:8px 0 20px; padding:15px 20px; border-radius:17px;
  color:@@MUTED@@; background:@@CARD@@; border:1px solid @@BORDER@@; box-shadow:0 10px 28px rgba(5,72,105,.07);
  backdrop-filter:blur(15px); font-size:13px; }
.glass { padding:18px 20px; border-radius:19px; background:@@CARD@@; border:1px solid @@BORDER@@;
  box-shadow:0 12px 30px rgba(5,72,105,.07); margin-bottom:12px; }
.glass h3 { margin-top:0; }
.flag { padding:11px 16px; border-left:5px solid #d64550; margin-bottom:8px; font-size:14px; }
.flag-ok { border-left-color:#17865e; }
.small-muted { color:@@MUTED@@; font-size:12px; }
.badge { display:inline-block; padding:3px 11px; border-radius:999px; font-size:12px; font-weight:800; color:white; }
.badge-high { background:#d64550; } .badge-mod { background:#d98a1f; } .badge-low { background:#17865e; }

@media(max-width:700px) { .block-container{padding:1rem} .hero{padding:26px 22px;border-radius:22px}
  .status-strip{flex-direction:column} section[data-testid="stSidebar"]{min-width:275px} }
@media(prefers-reduced-motion:reduce) { .metric, .stButton>button { transition:none!important } }
</style>
"""


def inject_css(dark: bool) -> None:
    if dark:
        theme = {
            "BG": "linear-gradient(135deg,#06151e,#0a2533 55%,#031017)",
            "TEXT": "#e9fbff", "SECTION": "#d8f7ff", "CARD": "rgba(255,255,255,.075)",
            "BORDER": "rgba(255,255,255,.13)", "MUTED": "#bdebf5",
        }
    else:
        theme = {
            "BG": ("radial-gradient(circle at 10% 10%,rgba(95,224,239,.28),transparent 28%),"
                   "radial-gradient(circle at 90% 15%,rgba(0,119,182,.18),transparent 27%),"
                   "linear-gradient(135deg,#eafcff,#f8fdff 45%,#eef9ff)"),
            "TEXT": "#102a43", "SECTION": "#073b59", "CARD": "rgba(255,255,255,.68)",
            "BORDER": "rgba(255,255,255,.85)", "MUTED": "#416b82",
        }
    css = CSS
    for key, value in theme.items():
        css = css.replace(f"@@{key}@@", value)

    if dark:
        # Streamlit's own widgets keep a light theme, so recolour text inside the main area only.
        scopes = ['[data-testid="stMain"]', '[data-testid="stAppViewContainer"] .main']
        targets = ["p", "li", "label", "h1", "h2", "h3", "h4", "summary", '[data-testid="stCaptionContainer"]']
        selector = ",".join(f"{sc} {t}" for sc in scopes for t in targets)
        css = css.replace(
            "</style>",
            f"{selector} {{ color:#e9fbff; }}\n"
            '.stApp .hero, .stApp .hero *, .stApp .metric, .stApp .metric *, .stApp .badge { color:#fff; }\n'
            '.stApp [data-testid="stAlert"] p, .stApp [data-testid="stAlert"] li, .stApp [data-testid="stAlert"] strong { color:#0f2b3d; }\n'
            "</style>",
        )
    st.markdown(css, unsafe_allow_html=True)


def hero(title: str, subtitle: str) -> None:
    st.markdown(
        f"""
    <div class="hero">
      <span class="pill">🛡️ DIGITAL PAYMENT PROTECTION</span>
      <h1>{html.escape(title)}</h1>
      <p>{html.escape(subtitle)}</p>
      <span class="pill">• Scam Awareness</span>
      <span class="pill">• Interactive Learning</span>
      <span class="pill">• Safer UPI Habits</span>
    </div>""",
        unsafe_allow_html=True,
    )


def section(title: str) -> None:
    st.markdown(f'<div class="section-title">{html.escape(title)}</div>', unsafe_allow_html=True)


def glass(inner_html: str, extra_class: str = "") -> None:
    st.markdown(f'<div class="glass {extra_class}">{inner_html}</div>', unsafe_allow_html=True)


def metric_cards(items: list[tuple[str, str]]) -> None:
    cols = st.columns(len(items), gap="medium")
    for i, (col, (label, value)) in enumerate(zip(cols, items)):
        with col:
            st.markdown(
                f'<div class="metric metric-{i % 5}"><h4>{html.escape(str(label))}</h4>'
                f"<h2>{html.escape(str(value))}</h2></div>",
                unsafe_allow_html=True,
            )


def risk_badge(level: str) -> str:
    cls = {"High": "badge-high", "Moderate": "badge-mod", "Medium": "badge-mod"}.get(level, "badge-low")
    return f'<span class="badge {cls}">{html.escape(level)}</span>'


def chart_layout(fig: go.Figure, height: int = 330) -> go.Figure:
    dark = st.session_state.get("dark_mode", False)
    fig.update_layout(
        height=height,
        margin=dict(l=10, r=10, t=50, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#e9fbff" if dark else "#102a43"),
    )
    return fig


# ----------------------------------------------------------------
# PRIVACY: REDACT SECRETS BEFORE ANALYSIS / LOGGING
# ----------------------------------------------------------------
CRED_AFTER_RE = re.compile(r"(?i)\b(otp|pin|cvv|cvc|password|passcode)\b([^\w\n]{0,3}(?:is\s+|was\s+)?)(\d{3,8})\b")
CRED_BEFORE_RE = re.compile(r"(?i)\b\d{4,8}\b(?=\s+(?:is\s+)?(?:my\s+|the\s+|your\s+)?(?:otp|upi pin|pin|cvv|cvc)\b)")
LONG_NUMBER_RE = re.compile(r"(?<![\w.])(?:\d[ -]?){13,19}(?!\d)")
PAN_RE = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")


def redact_sensitive(text: str) -> tuple[str, list[str]]:
    """Mask PIN/OTP/CVV values, 13-19 digit card/account numbers and PAN. Returns (text, kinds_found)."""
    found: set[str] = set()

    def cred_after(m: re.Match) -> str:
        found.add("a PIN/OTP/CVV/password value")
        return f"{m.group(1)}{m.group(2)}[REDACTED]"

    def cred_before(_: re.Match) -> str:
        found.add("a PIN/OTP/CVV/password value")
        return "[REDACTED]"

    def long_number(m: re.Match) -> str:
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19:
            found.add("a card/account number")
            return "[REDACTED NUMBER]"
        return m.group(0)

    def pan(_: re.Match) -> str:
        found.add("a PAN number")
        return "[REDACTED PAN]"

    out = CRED_AFTER_RE.sub(cred_after, text)
    out = CRED_BEFORE_RE.sub(cred_before, out)
    out = LONG_NUMBER_RE.sub(long_number, out)
    out = PAN_RE.sub(pan, out)
    return out, sorted(found)


def normalise(text: str) -> str:
    text = text.lower().replace("₹", " rs ").replace("’", "'").replace("‘", "'")
    return re.sub(r"\s+", " ", text).strip()


# Remove genuine warnings ("Do not share this OTP with anyone") so they are not mistaken for requests.
WARNING_RE = re.compile(
    r"\b(?:do not|don'?t|dont|never|should not|must not|not to)\s+(?:\w+\s+){0,4}?"
    r"(?:share|send|tell|give|disclose|reveal|provide|enter|forward)\b[^.!?\n]{0,60}?"
    r"\b(?:otp|pin|cvv|password|passcode|card|credentials|details)\b[^.!?\n]*",
    re.I,
)


def strip_warnings(norm_text: str) -> str:
    return WARNING_RE.sub(" ", norm_text)


# ----------------------------------------------------------------
# LINK + UPI ID INSPECTION (pure string checks; nothing is fetched)
# ----------------------------------------------------------------
URL_RE = re.compile(
    r"(?i)\b(?:https?://|www\.)[^\s<>\"']+"
    r"|\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|cutt\.ly|rb\.gy|is\.gd|shorturl\.at|wa\.me|t\.me)/[^\s<>\"']+"
)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "rb.gy", "is.gd", "shorturl.at", "wa.me", "t.me", "ow.ly", "buff.ly"}
RISKY_TLDS = {"xyz", "top", "click", "link", "online", "site", "tk", "ml", "ga", "cf", "gq", "cc", "icu", "buzz", "rest", "work", "shop", "vip", "live"}
TRUSTED_SUFFIXES = (".bank.in", ".gov.in", ".nic.in")
BRAND_DOMAINS = {
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "sbicard.com"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "axis": ["axisbank.com"],
    "kotak": ["kotak.com"],
    "pnb": ["pnbindia.in"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "npci": ["npci.org.in"],
    "bhim": ["bhimupi.org.in", "npci.org.in"],
    "googlepay": ["pay.google.com", "google.com"],
}
LONG_BRANDS = {"hdfc", "icici", "kotak", "paytm", "phonepe", "npci", "bhim", "googlepay"}


def extract_urls(text: str) -> list[str]:
    urls = []
    for m in URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;:!?)]}")
        if url not in urls:
            urls.append(url)
    return urls[:5]


def inspect_link(url: str) -> dict:
    """Heuristic red flags for a URL. Returns {'url', 'host', 'findings': [(text, points)], 'points'}."""
    raw = url.strip()
    parsed = urlparse(raw if "://" in raw else "//" + raw, scheme="https")
    host = (parsed.hostname or "").lower().strip(".")
    findings: list[tuple[str, int]] = []
    if not host:
        return {"url": raw, "host": "", "findings": [("Could not read a website address from this link.", 0)], "points": 0}

    if parsed.scheme == "http":
        findings.append(("Uses plain http instead of https, so it is not encrypted.", 10))
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        findings.append(("Uses a raw IP address instead of a normal website name.", 30))
    if host in SHORTENERS or any(host.endswith("." + s) for s in SHORTENERS):
        findings.append(("Uses a link shortener, which hides the real destination.", 25))
    if "xn--" in host:
        findings.append(("Contains 'xn--' (punycode), often used for look-alike characters.", 30))
    if "@" in raw.split("?")[0].split("//")[-1].split("/")[0]:
        findings.append(("Contains '@' before the host, a trick used to disguise the real destination.", 25))
    tld = host.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        findings.append((f"Ends in '.{tld}', a domain type frequently used in scams.", 15))
    labels = host.split(".")
    if host.count("-") >= 2 or len(labels) >= 5:
        findings.append(("Very long or hyphen-heavy address, a common look-alike pattern.", 10))

    trusted = host.endswith(TRUSTED_SUFFIXES)
    parts = [p for p in re.split(r"[^a-z0-9]+", host) if p]
    for brand, domains in BRAND_DOMAINS.items():
        mentioned = brand in host if brand in LONG_BRANDS else brand in parts
        official = trusted or any(host == d or host.endswith("." + d) for d in domains)
        if mentioned and not official:
            findings.append((f"Mentions '{brand}' but is not one of the official domains this tool knows ({', '.join(domains)}). "
                             "Verify through the official app instead.", 30))
            break

    return {"url": raw, "host": host, "findings": findings, "points": min(60, sum(p for _, p in findings))}


KNOWN_HANDLES = {
    "oksbi", "okhdfcbank", "okicici", "okaxis", "ybl", "ibl", "axl", "paytm", "ptyes", "pthdfc", "ptsbi", "apl",
    "upi", "sbi", "hdfcbank", "icici", "axisbank", "kotak", "yesbank", "airtel", "postbank", "jio", "freecharge",
    "fbl", "barodampay", "unionbank", "pnb", "cnrb", "idfcfirst", "indus", "rbl", "federal", "aubank", "slc",
}
SUSPICIOUS_ID_WORDS = ("refund", "support", "care", "cashback", "kyc", "helpdesk", "prize", "reward", "lottery", "bonus", "claim")


def inspect_upi_id(upi_id: str) -> dict:
    s = upi_id.strip()
    result = {"valid": False, "notes": [], "warnings": []}
    if not re.fullmatch(r"[A-Za-z0-9.\-_]{2,256}@[A-Za-z][A-Za-z0-9]{1,63}", s):
        result["warnings"].append("This is not a valid UPI ID format (expected name@bank).")
        return result
    name, handle = s.lower().split("@")
    result["valid"] = True
    if handle in KNOWN_HANDLES:
        result["notes"].append(f"'@{handle}' is a commonly seen UPI handle.")
    else:
        result["warnings"].append(f"'@{handle}' is not in this tool's short list of common handles. That does not mean it is fake; "
                                  "check the payee name your app shows.")
    if any(w in name for w in SUSPICIOUS_ID_WORDS):
        result["warnings"].append("The ID contains words like refund/support/care/prize. Real organisations do not collect money "
                                  "through personal-looking IDs with such names; scammers do.")
    if re.fullmatch(r"\d{10}", name):
        result["notes"].append("This ID is a mobile number. Confirm the person's name before paying.")
    result["notes"].append("A valid-looking ID does not prove who owns it. Always read the payee name shown by your UPI app.")
    return result


# ----------------------------------------------------------------
# MESSAGE ANALYSIS: red-flag rules + scam-pattern matching
# ----------------------------------------------------------------
_F = re.I | re.S
FLAG_RULES = [
    ("Asks you to share or read out a PIN, OTP, CVV or password",
     re.compile(r"\b(?:share|send|tell|give|read|provide|forward|batao|bata do|bhejo)\b.{0,40}\b(?:pin|otp|cvv|password|passcode)\b"
                r"|\b(?:pin|otp|cvv|password|passcode)\b.{0,25}\b(?:share|send|tell|give|forward|batao|bhejo)\b", _F), 45),
    ("Says you must enter your PIN to receive money, a refund or a prize",
     re.compile(r"\b(?:enter|put|type|input|use)\b.{0,30}\bpin\b.{0,60}\b(?:receive|credit|refund|cashback|prize|reward|claim)\b"
                r"|\b(?:receive|refund|cashback|prize|reward|claim)\b.{0,60}\b(?:enter|put|type|input)\b.{0,30}\bpin\b", _F), 40),
    ("Asks you to scan a QR code to receive or claim money",
     re.compile(r"\bscan\b.{0,50}\b(?:qr|code)\b.{0,60}\b(?:receive|get|claim|refund|cashback|reward)\b"
                r"|\b(?:qr|code)\b.{0,40}\bto (?:receive|get|claim)\b", _F), 35),
    ("Asks you to install a remote-access app or share your screen",
     re.compile(r"\b(?:anydesk|teamviewer|quicksupport|rustdesk|alpemix|screen[- ]?shar\w*|remote (?:access|control)|screen control"
                r"|share your screen|[\w-]+\.apk|(?:download|install) (?:this |the |our )?(?:apk|app))\b", _F), 35),
    ("Pushes you to approve a collect/payment request",
     re.compile(r"\bcollect request\b|\b(?:approve|accept|authori[sz]e)\b.{0,15}\brequest\b", _F), 25),
    ("Demands an advance fee, deposit or processing charge",
     re.compile(r"\b(?:processing fee|registration fee|advance (?:payment|amount)|token amount|security deposit|refund fee|"
                r"clearance fee|customs fee|deposit to unlock|pay (?:rs\.? ?)?\d[\d,]* (?:first|to (?:receive|claim|release|get)))\b", _F), 25),
    ("Creates urgency or threatens to block, suspend or disconnect",
     re.compile(r"\b(?:urgent(?:ly)?|immediately|right now|asap|within \d+ ?(?:minutes?|mins?|hours?|hrs?)|today only|last chance|"
                r"final notice|expires? (?:today|soon|tonight|in \d+)|(?:will|to) be (?:blocked|suspended|disconnected|deactivated)|"
                r"account (?:will be )?(?:blocked|suspended|closed)|(?:avoid|prevent)\b.{0,20}\b(?:block\w*|suspen\w*|disconnect\w*)|"
                r"disconnect(?:ed|ion)? (?:tonight|today)|jaldi|turant)\b", _F), 15),
    ("Claims to be police, customs, CBI or another authority",
     re.compile(r"\b(?:police|cbi|customs|narcotics|ncb|arrest(?:ed)?|digital arrest|legal action|court|warrant|income tax|"
                r"cyber ?cell|enforcement directorate|money laundering)\b", _F), 20),
    ("Offers a prize, lottery, guaranteed returns or easy earnings",
     re.compile(r"\b(?:lottery|lucky draw|you(?:'ve| have)? won|winner|prize|reward points|free gift|jackpot|guaranteed (?:profit|returns?)|"
                r"double your money|work from home|part[- ]time job|earn (?:rs\.? ?)?\d[\d,]*)\b", _F), 15),
    ("Uses a KYC / account-verification pretext",
     re.compile(r"\bkyc\b.{0,40}\b(?:expire[sd]?|update|pending|verify|verification|block(?:ed)?|suspend\w*)\b"
                r"|\b(?:update|verify|complete)\b.{0,15}\bkyc\b", _F), 25),
    ("Pretends to be bank, UPI or customer support",
     re.compile(r"\b(?:customer (?:care|support|service)|bank (?:official|executive|manager|employee|support)|upi support|"
                r"kyc (?:team|department)|helpdesk|support (?:agent|executive|team)|nodal officer|i am from (?:the )?(?:bank|upi|npci|rbi))\b", _F), 15),
    ("Claims to be a relative or a new number asking for money",
     re.compile(r"\b(?:new number|changed my number|this is my new|i am your (?:relative|son|daughter|friend|brother|sister|uncle))\b", _F), 20),
    ("Says money was sent 'by mistake' and asks for it back",
     re.compile(r"\b(?:sent (?:it |money )?(?:to you )?by mistake|(?:wrong|mistaken)(?:ly)? (?:transfer|transaction|sent|payment)|"
                r"mistakenly (?:sent|transferred|paid)|(?:please |pls )?(?:return|send back|refund) (?:it|the money|my money|the amount)|send it back)\b", _F), 20),
    ("Threatens utility, SIM or FASTag disconnection",
     re.compile(r"\b(?:electricity|power|gas|water|sim|mobile number|fastag)\b.{0,50}\b(?:disconnect\w*|block\w*|deactivat\w*|suspend\w*)\b", _F), 20),
    ("Promises money for simple online tasks",
     re.compile(r"\b(?:complete|finish) (?:\w+ )?tasks?\b.{0,40}\b(?:earn|commission|income)\b|\bearn\b.{0,30}\b(?:daily|per day|per hour|every day)\b", _F), 20),
    ("Pressures you to keep it secret or stay on the call",
     re.compile(r"\b(?:do not|don'?t|dont) (?:tell|inform) (?:anyone|anybody|your family)\b|keep (?:this )?(?:a )?(?:secret|confidential)|"
                r"stay on (?:the )?(?:call|line|video)|(?:do not|don'?t|dont) (?:disconnect|hang up|cut)", _F), 20),
    ("Tells you to click a link",
     re.compile(r"\b(?:click|tap|open|visit|follow)\b.{0,20}\b(?:link|url|below|here)\b", _F), 10),
]


@st.cache_resource(show_spinner=False)
def build_scam_search():
    corpus = [normalise(s["name"] + " " + s["example"] + " " + " ".join(s["signals"]) + " " + s["explanation"]) for s in SCAMS]
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words="english")
    return vectorizer, vectorizer.fit_transform(corpus)


@st.cache_resource(show_spinner=False)
def build_faq_search():
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words="english")
    return vectorizer, vectorizer.fit_transform([normalise(q) for q, _ in FAQ])


def match_scams(norm: str, scan: str, limit: int = 3, min_sim: float = 0.12):
    """Direct phrase hits first, then TF-IDF similarity. Returns (ranked, has_direct)."""
    vectorizer, matrix = build_scam_search()
    sims = cosine_similarity(vectorizer.transform([norm]), matrix).flatten()
    direct = []
    for idx, scam in enumerate(SCAMS):
        hits = [t for t in scam["signals"] if t in scan]
        if hits:
            direct.append((idx, min(1.0, 0.45 + 0.12 * len(hits)), hits))
    ranked = sorted(direct, key=lambda x: x[1], reverse=True)
    used = {r[0] for r in ranked}
    for idx in np.argsort(sims)[::-1]:
        idx = int(idx)
        if len(ranked) >= limit:
            break
        if idx not in used and sims[idx] >= min_sim:
            ranked.append((idx, float(sims[idx]), []))
            used.add(idx)
    return ranked[:limit], bool(direct)


def risk_level(score: int) -> str:
    if score >= 50:
        return "High"
    if score >= 25:
        return "Moderate"
    if score >= 10:
        return "Low"
    return "Minimal"


def analyse_message(message: str) -> dict:
    clean = message.strip()
    if not clean:
        return {"empty": True}
    safe_text, redacted = redact_sensitive(clean)
    norm = normalise(safe_text)
    scan = strip_warnings(norm)

    flags = [(label, weight) for label, rx, weight in FLAG_RULES if rx.search(scan)]
    links = [inspect_link(u) for u in extract_urls(safe_text)]
    matches, has_direct = match_scams(norm, scan)

    score = sum(w for _, w in flags)
    if links:
        score += min(30, max(link["points"] for link in links))
    if has_direct:
        score += 10
    score = int(min(100, score))
    level = risk_level(score)

    if level == "High":
        summary = "Several strong scam warning signs were found. Treat this as suspicious: do not pay, click or share anything."
    elif level == "Moderate":
        summary = "Some warning signs were found. Pause and verify through an official channel before taking any action."
    elif level == "Low":
        summary = "A few minor warning signs were found. Verify the sender and the payment details independently."
    else:
        summary = "No known scam pattern was detected. That does not prove the message is safe; verify the sender independently."
    return {"empty": False, "score": score, "level": level, "flags": flags, "links": links, "matches": matches,
            "redacted": redacted, "summary": summary, "word_count": len(clean.split())}


def risk_gauge(score: int) -> go.Figure:
    color = "#17865e" if score < 25 else "#d98a1f" if score < 50 else "#d64550"
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=score, number={"suffix": "/100"},
        title={"text": "Warning-sign score"},
        gauge={"axis": {"range": [0, 100]}, "bar": {"color": color},
               "steps": [{"range": [0, 25], "color": "rgba(23,134,94,.20)"},
                         {"range": [25, 50], "color": "rgba(217,138,31,.20)"},
                         {"range": [50, 100], "color": "rgba(214,69,80,.20)"}]},
    ))
    return chart_layout(fig, 260)


# ----------------------------------------------------------------
# SAFETY ASSISTANT (offline retrieval)
# ----------------------------------------------------------------
INCIDENT_RULES = [
    (re.compile(r"\b(?:i|we)\s+(?:have\s+|just\s+|already\s+)?(?:shared|told|gave|sent|entered|typed)\b.{0,30}\b(?:pin|otp|cvv|password)\b", re.I),
     "You shared a secret code, so contact your bank right away to secure your UPI/card access."),
    (re.compile(r"\b(?:i|we)\s+(?:have\s+|just\s+|already\s+)?installed\b|\b(?:anydesk|teamviewer|apk)\b", re.I),
     "Uninstall the app, turn off mobile data/Wi-Fi, and tell your bank before using any payment app again."),
    (re.compile(r"\b(?:i|we)\s+(?:have\s+|just\s+|already\s+)?(?:clicked|opened)\b", re.I),
     "If you entered any details on that page, reset those credentials through the official app and tell your bank."),
    (re.compile(r"\b(?:i|we)\s+(?:have\s+|just\s+|already\s+)?(?:scanned|approved|paid)\b", re.I),
     "Check your transaction history now and tell your bank and 1930 if money left your account."),
    (re.compile(r"\b(?:got|been|was|were)\s+(?:scammed|cheated|defrauded|hacked)\b", re.I), ""),
    (re.compile(r"\bmoney\b.{0,30}\b(?:debited|deducted|stolen|withdrawn)\b.{0,40}\b(?:without|fraud|scam|unknown|wrong)\b", re.I), ""),
    (re.compile(r"\b(?:unauthori[sz]ed|unknown)\s+(?:transaction|debit|payment)s?\b", re.I), ""),
]


def incident_response(extra: str) -> str:
    lead = f"**{extra}**\n\n" if extra else ""
    return (lead + "If money may have been lost, act immediately:\n\n"
            f"1. Call **{HELPLINE}** as soon as possible.\n"
            f"2. Report at **{PORTAL}** and note the reference number.\n"
            "3. Contact your bank and UPI app using official channels.\n"
            "4. Save the transaction ID/UTR, messages, phone numbers and screenshots.\n"
            "5. Never pay anyone who promises guaranteed recovery.\n\n"
            "Do not share your UPI PIN, OTP, CVV or password here.")


def answer_question(question: str) -> str:
    safe_q, redacted = redact_sensitive(question.strip())
    q = normalise(safe_q)
    note = ("\n\n⚠️ Your message appeared to contain a PIN/OTP or card number, so I hid it. "
            "Never type these into any chat or app other than your bank's own payment screen.") if redacted else ""

    if re.fullmatch(r"(?:hi|hello|hey|namaste|good (?:morning|afternoon|evening))\W*", q):
        return WELCOME
    if re.fullmatch(r"(?:thanks|thank you|ok|okay|thx)\W*", q):
        return "You're welcome. Stay alert and never share your PIN or OTP."

    for rx, extra in INCIDENT_RULES:
        if rx.search(q):
            return incident_response(extra) + note

    faq_vec, faq_matrix = build_faq_search()
    faq_sims = cosine_similarity(faq_vec.transform([q]), faq_matrix).flatten()
    faq_idx = int(np.argmax(faq_sims))
    faq_score = float(faq_sims[faq_idx])
    ranked, has_direct = match_scams(q, strip_warnings(q), limit=1, min_sim=0.3)

    def scam_answer(idx: int) -> str:
        scam = SCAMS[idx]
        return (f"**Possible topic: {scam['name']}**\n\n{scam['explanation']}\n\n**Safer action:** {scam['action']}\n\n"
                "This is an awareness suggestion, not a verified fraud verdict.")

    if faq_score >= 0.7 or (faq_score >= 0.45 and not has_direct):
        return FAQ[faq_idx][1] + note
    if has_direct:
        return scam_answer(ranked[0][0]) + note
    if faq_score >= 0.2:
        return FAQ[faq_idx][1] + note
    if ranked:
        return scam_answer(ranked[0][0]) + note
    return ("I can help with UPI basics, QR-code safety, collect requests, fake screenshots, phishing, customer-care scams, "
            "pending payments and reporting fraud. Try one of the quick questions below.\n\n"
            f"For suspected financial fraud, call **{HELPLINE}**, report at **{PORTAL}**, and contact your bank through official channels." + note)


def ask_assistant(question: str) -> None:
    safe_q, _ = redact_sensitive(question)
    st.session_state.chat_history.append({"role": "user", "content": safe_q})
    st.session_state.chat_history.append({"role": "assistant", "content": answer_question(question)})
    log_activity("Assistant question", safe_q[:120])


def clear_chat() -> None:
    st.session_state.chat_history = [{"role": "assistant", "content": "Chat cleared. Ask me a UPI safety question. Never share your PIN or OTP."}]


# ----------------------------------------------------------------
# PDF REPORT
# ----------------------------------------------------------------
def _pdf_text(value: str) -> str:
    value = value.replace("₹", "Rs. ")
    value = html.escape(value, quote=False)
    return value.encode("cp1252", "replace").decode("cp1252")


@st.cache_data(show_spinner=False)
def build_pdf_report() -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=38, leftMargin=38, topMargin=40, bottomMargin=44,
                            title="UPI Safety Coach - Awareness Report", author=APP_NAME)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("UPITitle", parent=styles["Title"], textColor=colors.HexColor("#075985"), fontSize=23, leading=28)
    cell = ParagraphStyle("cell", parent=styles["BodyText"], fontSize=8, leading=10)
    cell_head = ParagraphStyle("cellhead", parent=cell, fontName="Helvetica-Bold", textColor=colors.HexColor("#073B59"))

    story = [
        Paragraph("UPI Safety Coach", title_style),
        Paragraph("Digital Payment Awareness Report", styles["Heading2"]),
        Paragraph(f"Generated on {date.today():%d %B %Y}", styles["Italic"]),
        Spacer(1, 12),
        Paragraph("Purpose: help people recognise common UPI scam patterns, follow safer payment habits and understand "
                  "official reporting steps.", styles["BodyText"]),
        Spacer(1, 12),
        Paragraph("Golden Safety Rules", styles["Heading2"]),
    ]
    for rule in GOLDEN_RULES:
        story += [Paragraph("• " + _pdf_text(rule), styles["BodyText"]), Spacer(1, 4)]

    story += [Spacer(1, 10), Paragraph("Scam Awareness Library", styles["Heading2"])]
    rows = [[Paragraph(h, cell_head) for h in ("Scam pattern", "Category", "Risk", "Safer action")]]
    for s in SCAMS:
        rows.append([Paragraph(_pdf_text(s["name"]), cell), Paragraph(_pdf_text(s["category"]), cell),
                     Paragraph(_pdf_text(s["risk"]), cell), Paragraph(_pdf_text(s["action"]), cell)])
    table = Table(rows, colWidths=[120, 72, 42, 285], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D9F1F7")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#AABBC5")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2FAFC")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    story += [table, Spacer(1, 15), Paragraph("If you suspect financial cyber fraud in India", styles["Heading2"])]
    for step in INCIDENT_STEPS:
        story += [Paragraph("• " + _pdf_text(step.replace("**", "")), styles["BodyText"]), Spacer(1, 3)]
    story += [
        Spacer(1, 12),
        Paragraph("Important limitation: this report and the software provide general education. They do not verify live messages, "
                  "connect to banks, block accounts, reverse payments or guarantee recovery. Official processes may change; "
                  "follow current official instructions.", styles["Italic"]),
    ]

    def footer(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#5b7a8c"))
        canvas.drawString(38, 24, "UPI Safety Coach - educational use only. Never share your PIN or OTP.")
        canvas.drawRightString(A4[0] - 38, 24, f"Page {doc_.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


def build_incident_summary(fields: dict) -> str:
    lines = [f"UPI FRAUD INCIDENT SUMMARY  (prepared {datetime.now():%d %b %Y, %H:%M})", "=" * 60]
    for label, value in fields.items():
        lines.append(f"{label}: {value.strip() or 'Not provided'}")
    lines += ["", "Next steps", "-" * 60,
              f"1. Call {HELPLINE} and report at {PORTAL}; note the acknowledgement number.",
              "2. Contact your bank and UPI app through their official app/website.",
              "3. Keep screenshots, chats, call logs and SMS. Do not delete anything.",
              "", "This summary never needs your UPI PIN, OTP, CVV or passwords. Do not add them."]
    return "\n".join(lines)


# =================================================================
# PAGES
# =================================================================
def page_overview() -> None:
    hero(APP_NAME, "A smart digital-payment awareness platform to learn safe UPI habits, recognise common scam patterns "
                   "and understand what to do when something goes wrong.")
    st.markdown(
        f"""<div class="status-strip">
      <div>◉ <b>Safety dashboard ready</b> · {len(SCAMS)} scam patterns in the awareness library</div>
      <div>🛡️ <b>Privacy-first</b> · Nothing you type is saved to disk · never asks for your PIN or OTP</div>
    </div>""",
        unsafe_allow_html=True,
    )

    result = st.session_state.quiz_result
    quiz_text = f"{result['score']}/{len(QUIZ)}" if result else "Not taken"
    metric_cards([
        ("Scam Types Covered", str(len(SCAMS))),
        ("Safety FAQs", str(len(FAQ))),
        ("Quiz Questions", str(len(QUIZ))),
        ("Your Activities", str(len(st.session_state.activity))),
        ("Latest Quiz Score", quiz_text),
    ])

    section("🚀 Get Started")
    c1, c2, c3 = st.columns(3)
    cards = [
        (c1, "🔎 Check a Message", "Paste a suspicious SMS, WhatsApp text, link or UPI ID to see matching warning signs.", "Open Scam Checker", "🔎 Scam Checker"),
        (c2, "🧠 Test Your Knowledge", "Practise safe decisions with an interactive UPI safety quiz.", "Start Safety Quiz", "🧠 Safety Quiz"),
        (c3, "🆘 Need Urgent Help?", "Find the immediate steps for suspected financial cyber fraud in India.", "Open Emergency Help", "🆘 Emergency Help"),
    ]
    for col, title, body, label, target in cards:
        with col:
            glass(f"<h3>{html.escape(title)}</h3><p>{html.escape(body)}</p>")
            st.button(label, key=f"ov_{target}", on_click=goto, args=(target,), **STRETCH)

    section("📅 Today's Scam Spotlight")
    spot = SCAMS[date.today().toordinal() % len(SCAMS)]
    glass(f"<b>{html.escape(spot['name'])}</b> &nbsp; {risk_badge(spot['risk'])}<br><br>"
          f"<i>“{html.escape(spot['example'])}”</i><br><br>"
          f"<b>Why it works:</b> {html.escape(spot['explanation'])}<br>"
          f"<b>What to do:</b> {html.escape(spot['action'])}")

    section("📈 UPI Safety Snapshot")
    left, right = st.columns([3, 2])
    cats = pd.Series([s["category"] for s in SCAMS]).value_counts().reset_index()
    cats.columns = ["Scam category", "Patterns"]
    with left:
        fig = px.bar(cats.sort_values("Patterns"), x="Patterns", y="Scam category", orientation="h",
                     title="Awareness library by category", color_discrete_sequence=["#12b5cb"])
        fig.update_layout(showlegend=False)
        st.plotly_chart(chart_layout(fig, 360), **STRETCH)
    with right:
        risk = pd.Series([s["risk"] for s in SCAMS]).value_counts().reset_index()
        risk.columns = ["Risk indicator", "Patterns"]
        fig2 = px.pie(risk, names="Risk indicator", values="Patterns", hole=0.55, title="Risk indicators",
                      color="Risk indicator", color_discrete_map={"High": "#d64550", "Medium": "#d98a1f", "Low": "#17865e"})
        st.plotly_chart(chart_layout(fig2, 360), **STRETCH)

    section("⭐ Five Golden Rules")
    for i, rule in enumerate(GOLDEN_RULES, 1):
        glass(f"<b>{i:02d}</b> &nbsp; {html.escape(rule)}")
    st.info("Educational tool only. It does not connect to banks, inspect real transactions, block accounts or recover money.")


def render_analysis(res: dict) -> None:
    left, right = st.columns([2, 3])
    with left:
        st.plotly_chart(risk_gauge(res["score"]), **STRETCH)
    with right:
        glass(f"<b>Assessment: {risk_badge(res['level'])}</b><br><br>{html.escape(res['summary'])}")
        if res["redacted"]:
            st.warning("Your text appeared to contain " + " and ".join(res["redacted"]) +
                       ". It was hidden before analysis. Never share these with anyone.")

    if res["flags"]:
        section("🚩 Warning signs found")
        for label, _ in res["flags"]:
            glass(f"⚑ {html.escape(label)}", "flag")
    else:
        st.info("No specific warning signs matched. Scammers adapt, so still verify independently.")

    if res["links"]:
        section("🔗 Links inspected (not opened)")
        for link in res["links"]:
            st.code(link["url"], language=None)
            if link["findings"]:
                for text, _ in link["findings"]:
                    glass(f"⚑ {html.escape(text)}", "flag")
            else:
                glass("No structural red flags found. A clean-looking link can still be harmful; prefer opening your bank's own app.", "flag flag-ok")

    if res["matches"]:
        section("🧩 Closest known scam patterns")
        for idx, score, hits in res["matches"]:
            scam = SCAMS[idx]
            with st.expander(f"{'🚨' if scam['risk'] == 'High' else '⚠️'} {scam['name']} · match {score:.0%}", expanded=(idx == res['matches'][0][0])):
                st.write(scam["explanation"])
                st.success("Safer action: " + scam["action"])
                if hits:
                    st.caption("Matched phrases: " + ", ".join(hits))

    st.caption("The score counts known warning signs. A low score does not mean a message is safe; a high score is an awareness flag, not proof of fraud.")


def load_sample(i: int) -> None:
    st.session_state.checker_input = SAMPLE_MESSAGES[i]


def clear_checker() -> None:
    st.session_state.checker_input = ""


def page_scam_checker() -> None:
    hero("Scam Checker", "Check suspicious messages, links or UPI IDs against warning-sign rules and a curated scam-awareness library.")
    st.warning("Do not paste your UPI PIN, OTP, CVV, password or full card number. Obvious secrets are hidden automatically, but remove personal details anyway.")
    tab_msg, tab_link, tab_id = st.tabs(["💬 Message", "🔗 Link", "🆔 UPI ID"])

    with tab_msg:
        st.markdown("**Try a sample**")
        cols = st.columns(len(SAMPLE_MESSAGES))
        for i, col in enumerate(cols):
            with col:
                st.button(f"Load sample {i + 1}", key=f"sample_{i}", on_click=load_sample, args=(i,), **STRETCH)
        st.text_area("Paste the suspicious message or describe what happened", key="checker_input", height=170,
                     placeholder="Example: Your account will be blocked today. Click this link and share your OTP...")
        c1, c2, c3 = st.columns([1, 1, 3])
        analyse = c1.button("🔍 Analyse", key="analyse_btn", **STRETCH)
        c2.button("Clear", key="clear_btn", on_click=clear_checker, **STRETCH)
        c3.caption("Uses transparent keyword rules, link checks and TF-IDF similarity. It is not a definitive fraud detector.")
        if analyse:
            text = st.session_state.checker_input
            if not text.strip():
                st.error("Please enter a message first.")
            else:
                res = analyse_message(text)
                log_activity("Scam check", f"{res['level']} risk ({res['score']}/100), {res['word_count']} words")
                render_analysis(res)

    with tab_link:
        url = st.text_input("Paste a link to inspect", key="link_input", placeholder="http://sbi-kyc-update.xyz/login")
        st.caption("The link is analysed as text only. It is never opened or contacted.")
        if st.button("Inspect link", key="inspect_link_btn"):
            if not url.strip():
                st.error("Please paste a link first.")
            else:
                result = inspect_link(url)
                log_activity("Link check", result["host"] or "unreadable link")
                level = risk_level(result["points"])
                glass(f"<b>Host:</b> {html.escape(result['host'] or 'unknown')} &nbsp; {risk_badge(level if level != 'Minimal' else 'Low')}")
                if result["findings"]:
                    for text, _ in result["findings"]:
                        glass(f"⚑ {html.escape(text)}", "flag")
                else:
                    glass("No structural red flags found. Still prefer opening your bank or payment app directly.", "flag flag-ok")

    with tab_id:
        upi_id = st.text_input("Enter a UPI ID to check", key="upi_id_input", placeholder="name@bank")
        if st.button("Check UPI ID", key="check_id_btn"):
            if not upi_id.strip():
                st.error("Please enter a UPI ID first.")
            else:
                res = inspect_upi_id(upi_id)
                log_activity("UPI ID check", "format valid" if res["valid"] else "format invalid")
                for w in res["warnings"]:
                    glass(f"⚑ {html.escape(w)}", "flag")
                for n in res["notes"]:
                    glass(f"ℹ️ {html.escape(n)}", "flag flag-ok")


def page_learn() -> None:
    hero("Learn UPI", "Understand the basics of Unified Payments Interface and the simple habits that help protect your money.")
    tab_basics, tab_myths, tab_habits = st.tabs(["📘 Basics", "❓ Myths vs facts", "✅ Safe-payment habits"])
    with tab_basics:
        for title, body in LESSONS:
            with st.expander(title):
                st.write(body)
    with tab_myths:
        st.dataframe(pd.DataFrame(MYTHS, columns=["Myth", "Fact"]), hide_index=True, **STRETCH)
    with tab_habits:
        c1, c2, c3 = st.columns(3)
        habits = {
            "Before you pay": ["Check the payee name and UPI ID", "Confirm the amount", "Be wary of pressure or 'too good' offers"],
            "While you pay": ["Enter your PIN only to send money", "Never share screen or install unknown apps", "Use official app stores only"],
            "After you pay": ["Check the confirmation in your own app", "Keep the transaction ID", "Report problems quickly through official channels"],
        }
        for col, (title, items) in zip((c1, c2, c3), habits.items()):
            with col:
                glass(f"<h3>{html.escape(title)}</h3>" + "".join(f"<p>• {html.escape(i)}</p>" for i in items))
    section("🛡️ Golden Rules")
    extra = GOLDEN_RULES + [
        "Do not install remote-access apps at a stranger's request.",
        "Keep your phone locked and payment apps updated.",
        "Check transactions in your own app and bank statement.",
    ]
    st.dataframe(pd.DataFrame({"Rule": extra}), hide_index=True, **STRETCH)
    st.info("Remember: a UPI PIN authorises a payment. It is never required to receive money.")


def page_library() -> None:
    hero("Scam Library", "Explore common UPI-related fraud patterns, warning signs and safer responses.")
    c1, c2, c3 = st.columns([2, 2, 3])
    categories = sorted({s["category"] for s in SCAMS})
    chosen = c1.multiselect("Category", categories, placeholder="All categories")
    risks = c2.multiselect("Risk indicator", ["High", "Medium"], placeholder="All risk levels")
    query = c3.text_input("Search", placeholder="e.g. QR, refund, OTP").strip().lower()

    visible = []
    for s in SCAMS:
        if chosen and s["category"] not in chosen:
            continue
        if risks and s["risk"] not in risks:
            continue
        haystack = " ".join([s["name"], s["category"], s["explanation"], s["example"], " ".join(s["signals"])]).lower()
        if query and query not in haystack:
            continue
        visible.append(s)

    metric_cards([("Patterns shown", str(len(visible))),
                  ("High-risk patterns", str(sum(s["risk"] == "High" for s in visible))),
                  ("Categories", str(len({s["category"] for s in visible})))])
    if not visible:
        st.info("No scam patterns match these filters.")
    for scam in visible:
        with st.expander(f"{'🚨' if scam['risk'] == 'High' else '⚠️'} {scam['name']} · {scam['risk']} indicator"):
            st.write("**How it works:** " + scam["explanation"])
            st.write("**Example:** " + scam["example"])
            st.success("**What to do:** " + scam["action"])
            st.caption("Warning phrases: " + ", ".join(scam["signals"]))


def shuffled_options(i: int, rnd: int) -> list[str]:
    options = list(QUIZ[i]["options"])
    random.Random(rnd * 1000 + i).shuffle(options)
    return options


def retake_quiz() -> None:
    st.session_state.quiz_round += 1
    st.session_state.quiz_result = None


def page_quiz() -> None:
    hero("Safety Quiz", "Practise your digital-payment safety knowledge. Choose the safest action in each situation.")
    rnd = st.session_state.quiz_round
    result = st.session_state.quiz_result
    if result is None:
        st.caption("Your answers stay in this session. Answer every question, then submit to see your score and explanations.")
        with st.form(f"quiz_form_{rnd}"):
            answers = {}
            for i, item in enumerate(QUIZ):
                st.markdown(f"**Q{i + 1}. {item['q']}**")
                answers[i] = st.radio("Choose one:", shuffled_options(i, rnd), key=f"quiz_{rnd}_{i}", index=None, label_visibility="collapsed")
            submitted = st.form_submit_button("Submit My Answers", **STRETCH)
        if submitted:
            missing = [i + 1 for i, a in answers.items() if a is None]
            if missing:
                st.warning("Please answer every question. Missing: " + ", ".join(f"Q{m}" for m in missing))
            else:
                score = sum(answers[i] == QUIZ[i]["options"][QUIZ[i]["answer"]] for i in range(len(QUIZ)))
                st.session_state.quiz_result = {"answers": answers, "score": score}
                best = st.session_state.quiz_best
                st.session_state.quiz_best = score if best is None else max(best, score)
                log_activity("Safety quiz", f"Scored {score}/{len(QUIZ)}")
                st.rerun()
        return

    score = result["score"]
    pct = score / len(QUIZ)
    verdict = "Excellent" if pct >= 0.8 else "Good" if pct >= 0.6 else "Keep practising"
    metric_cards([("Your Score", f"{score}/{len(QUIZ)}"), ("Percentage", f"{pct:.0%}"), ("Best This Session", f"{st.session_state.quiz_best}/{len(QUIZ)}"), ("Result", verdict)])
    st.progress(pct)

    weak = []
    for i, item in enumerate(QUIZ):
        correct = item["options"][item["answer"]]
        if result["answers"][i] == correct:
            st.success(f"Q{i + 1}: Correct. {item['why']}")
        else:
            weak.append(item["topic"])
            st.error(f"Q{i + 1}: You chose “{result['answers'][i]}”. Correct answer: {correct}. {item['why']}")
    if weak:
        topics = ", ".join(sorted(set(weak)))
        st.info(f"Worth revisiting in the Scam Library: {topics}.")
        st.button("Open Scam Library", key="quiz_to_lib", on_click=goto, args=("🚨 Scam Library",))
    st.button("🔁 Retake Quiz", key="retake", on_click=retake_quiz)


def page_emergency() -> None:
    hero("Emergency Help", "If you suspect financial cyber fraud, stop the interaction and report it quickly through official channels.")
    st.error("🚨 If money may have been lost, act immediately. Fast reporting may help authorities and banks attempt to trace or stop the movement of funds, but recovery is not guaranteed.")
    metric_cards([("Cyber Fraud Helpline", HELPLINE), ("Official Reporting Portal", "cybercrime.gov.in"), ("Priority", "Act Quickly")])

    st.markdown("### Immediate action checklist")
    done = 0
    for i, step in enumerate(INCIDENT_STEPS):
        done += bool(st.checkbox(step, key=f"emergency_step_{i}"))
    st.progress(done / len(INCIDENT_STEPS), text=f"{done} of {len(INCIDENT_STEPS)} steps done")

    st.markdown("### Common situations")
    situations = {
        "Money debited but payment is pending or failed": "Do not repeat the payment immediately. Check the status and bank statement, note the transaction ID, and raise a complaint through the official app/bank if it does not resolve.",
        "Payment sent to the wrong person": "Contact your bank and UPI app immediately with the transaction details and ask about their dispute process. Do not assume the payment can be cancelled or recovered. If the bank does not resolve it, you can escalate to the RBI Ombudsman at cms.rbi.org.in.",
        "I shared my UPI PIN or OTP": "Contact your bank immediately through official channels, secure your UPI access, review recent transactions and report any unauthorised debit.",
        "I clicked a suspicious link": "Do not enter any details. If you already did, reset those credentials through the official app and tell your bank. Clear the message and do not forward it.",
        "I installed a remote-access app": "Uninstall it, switch off mobile data/Wi-Fi, and contact your bank before opening any banking or payment app again.",
        "Someone sent me money 'by mistake'": "Do not send money to a new number. Inform your bank about the unexpected credit and let the bank handle any reversal.",
    }
    for title, body in situations.items():
        with st.expander(title):
            st.write(body)

    section("📝 Incident summary builder")
    st.caption("Fill in what you know. This text stays in your browser session and is not saved. Do NOT enter your PIN, OTP, CVV or passwords.")
    with st.form("incident_form"):
        a, b = st.columns(2)
        when = a.text_input("Date and time of incident")
        amount = b.text_input("Amount involved (₹)")
        app_bank = a.text_input("UPI app and bank used")
        txn = b.text_input("Transaction ID / UTR")
        fraudster = st.text_input("Fraudster's UPI ID, phone number or link")
        what = st.text_area("What happened?", height=120)
        taken = st.text_area("Actions already taken (called 1930, informed bank, etc.)", height=80)
        build = st.form_submit_button("Build summary", **STRETCH)
    if build:
        raw = {"Date/time": when, "Amount": amount, "UPI app / bank": app_bank, "Transaction ID / UTR": txn,
               "Fraudster's details": fraudster, "What happened": what, "Actions taken": taken}
        redacted_any = set()
        cleaned = {}
        for k, v in raw.items():
            cleaned[k], found = redact_sensitive(v)
            redacted_any.update(found)
        if redacted_any:
            st.warning("Removed " + " and ".join(sorted(redacted_any)) + " from your text. Never include these in reports.")
        st.session_state.incident_summary = build_incident_summary(cleaned)
        log_activity("Incident summary", "Built incident summary")
    if st.session_state.incident_summary:
        st.code(st.session_state.incident_summary, language=None)
        st.download_button("⬇️ Download summary (.txt)", st.session_state.incident_summary.encode("utf-8"),
                           "upi_incident_summary.txt", "text/plain", **STRETCH)
    st.warning("This software cannot call 1930 for you, block an account, reverse a transaction or recover funds. Use the official channels yourself.")


def page_assistant() -> None:
    hero("Safety Assistant", "Ask simple questions about UPI, suspicious payment requests, scams and safe next steps.")
    st.info("This is an offline knowledge assistant based on the included awareness content. It is not connected to a bank or live support service. Never share PINs, OTPs or passwords.")
    for item in st.session_state.chat_history:
        with st.chat_message(item["role"]):
            st.markdown(item["content"])

    section("Quick questions")
    cols = st.columns(2)
    for i, q in enumerate(QUICK_QUESTIONS):
        with cols[i % 2]:
            st.button(q, key=f"quick_{i}", on_click=ask_assistant, args=(q,), **STRETCH)
    st.button("🧹 Clear chat", key="clear_chat", on_click=clear_chat)

    prompt = st.chat_input("Ask about UPI safety...")
    if prompt:
        ask_assistant(prompt)
        st.rerun()


def clear_session_data() -> None:
    st.session_state.activity = []
    st.session_state.quiz_result = None
    st.session_state.quiz_best = None
    st.session_state.quiz_round += 1
    st.session_state.incident_summary = ""
    st.session_state.checker_input = ""
    clear_chat()


def page_reports() -> None:
    hero("Reports & Settings", "Review your learning activity and export an awareness report for personal or classroom use.")
    result = st.session_state.quiz_result
    metric_cards([
        ("Scam Library", str(len(SCAMS))),
        ("FAQ Entries", str(len(FAQ))),
        ("Activities This Session", str(len(st.session_state.activity))),
        ("Quiz Completed", "Yes" if result else "No"),
    ])

    section("📥 Export scam awareness library")
    export = pd.DataFrame([{
        "scam_name": s["name"], "category": s["category"], "risk_indicator": s["risk"],
        "explanation": s["explanation"], "safe_action": s["action"], "example": s["example"],
    } for s in SCAMS])
    st.download_button("Download Scam Library CSV", export.to_csv(index=False).encode("utf-8"),
                       "upi_scam_awareness_library.csv", "text/csv", **STRETCH)

    section("📋 Session activity")
    if st.session_state.activity:
        df = pd.DataFrame(st.session_state.activity)
        st.dataframe(df, hide_index=True, **STRETCH)
        st.download_button("Download Activity CSV", df.to_csv(index=False).encode("utf-8"),
                           "upi_safety_activity.csv", "text/csv", **STRETCH)
    else:
        st.info("No activity recorded in this session yet. Use the Scam Checker, Quiz or Assistant to create entries.")
    st.button("🗑️ Clear all session data", key="clear_all", on_click=clear_session_data)

    section("📄 Download PDF awareness report")
    if REPORTLAB_AVAILABLE:
        st.download_button("📄 Download UPI Safety Coach PDF", build_pdf_report(),
                           "UPI_Safety_Coach_Awareness_Report.pdf", "application/pdf", **STRETCH)
    else:
        st.warning("ReportLab is not installed. Run: python -m pip install reportlab")

    section("🔐 Privacy & limitations")
    st.markdown("""
- Checks compare text with a small built-in library and rule set. They are not a definitive fraud detector.
- Obvious PINs, OTPs, card numbers and PAN values are masked before analysis and logging.
- Links are inspected as text only; nothing is opened or sent anywhere.
- Activity lives only in this browser session and is never written to disk.
- No real UPI transaction is initiated or accessed, and no bank is contacted.
- Official processes change; always follow current instructions from your bank, NPCI and cybercrime.gov.in.
""")


PAGES = {
    "🏠 Overview": page_overview,
    "🔎 Scam Checker": page_scam_checker,
    "📚 Learn UPI": page_learn,
    "🚨 Scam Library": page_library,
    "🧠 Safety Quiz": page_quiz,
    "🆘 Emergency Help": page_emergency,
    "💬 Safety Assistant": page_assistant,
    "📊 Reports & Settings": page_reports,
}


# =================================================================
# SIDEBAR + MAIN
# =================================================================
def render_sidebar() -> None:
    with st.sidebar:
        st.markdown(
            """
        <div class="brand">
          <div class="brand-icon">🛡️</div>
          <div class="brand-name">UPI Safety Coach</div>
          <div class="brand-tag">SMART DIGITAL PAYMENT SAFETY</div>
        </div>
        <div class="nav-title">MAIN DASHBOARD</div>""",
            unsafe_allow_html=True,
        )
        for i, name in enumerate(NAV_ITEMS):
            st.button(name, key=f"upi_nav_{i}", on_click=goto, args=(name,),
                      type="primary" if st.session_state.nav == name else "secondary", **STRETCH)
        st.divider()
        st.toggle("🌙 Dark mode", key="dark_mode")
        st.markdown(
            f"""
        <div class="glass" style="color:#d8f7ff;background:rgba(255,255,255,.07)">
          <b>🟢 AWARENESS ENGINE ONLINE</b><br><br>
          🔎 Scam patterns: {len(SCAMS)}<br>
          📚 Learning topics: {len(FAQ)}<br>
          🧠 Quiz questions: {len(QUIZ)}<br>
          🛡️ Privacy: No PIN/OTP collection
        </div>
        <div style="text-align:center;color:#7ab7c7;font-size:10px;padding:14px">
          UPI Safety Coach v{APP_VERSION}<br>Awareness • Prevention • Response
        </div>""",
            unsafe_allow_html=True,
        )


def main() -> None:
    init_state()
    inject_css(st.session_state.dark_mode)
    render_sidebar()
    PAGES.get(st.session_state.nav, page_overview)()
    st.markdown(
        """
<br><br>
<div style="text-align:center;opacity:.68;padding:20px;font-size:12px">
  🛡️ <b>UPI Safety Coach</b> — Digital Payment Awareness Platform<br>
  Scam Awareness • Safe UPI Habits • Learning • Responsible Reporting<br>
  <span style="font-size:10px">Educational use only · Never share your PIN or OTP</span>
</div>""",
        unsafe_allow_html=True,
    )


main()

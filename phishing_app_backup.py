import tkinter as tk
from tkinter import messagebox
import re
from urllib.parse import urlparse
import requests

# ================== API KEY ==================
API_KEY = "6dc5a8ae8d3e4bdae7779939aa5cc82c6ed76ea554ee9c8fc375385eac2c564b"

# ================== LOCAL PHISHING CHECK ==================
def is_phishing(url):
    suspicious_keywords = [
        "login", "verify", "update", "secure", "account",
        "password", "bank", "free", "claim", "win", "urgent"
    ]

    suspicious_extensions = [
        ".xyz", ".top", ".kim", ".loan", ".click", ".country"
    ]

    parsed = urlparse(url)

    if not parsed.scheme:
        return "❌ Invalid URL (Missing http/https)"

    domain = parsed.netloc.lower()

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        return "⚠️ Phishing suspected (Raw IP address used)"

    for word in suspicious_keywords:
        if word in url.lower():
            return f"⚠️ Suspicious keyword detected: {word}"

    for ext in suspicious_extensions:
        if domain.endswith(ext):
            return f"⚠️ Suspicious domain extension: {ext}"

    if domain.count('-') >= 2:
        return "⚠️ Suspicious domain (too many hyphens)"

    if len(domain) > 30:
        return "⚠️ Suspicious domain (too long)"

    return "✅ No phishing signs found (Local Scan)"

# ================== API BASED CHECK (FIXED) ==================
def api_check_url(url):
    headers = {
        "x-apikey": API_KEY
    }

    data = {
        "url": url
    }

    try:
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data=data,
            timeout=10
        )

        if response.status_code in [200, 202]:
            return "✅ URL submitted to VirusTotal (Real-time scan started)"
        elif response.status_code == 401:
            return "❌ Invalid API Key"
        elif response.status_code == 429:
            return "❌ API limit exceeded (Too many requests)"
        else:
            return f"❌ API Error (Code: {response.status_code})"

    except requests.exceptions.RequestException:
        return "❌ Internet / API connection error"

# ================== BUTTON FUNCTION ==================
def check_url():
    url = entry.get()

    if url.strip() == "":
        messagebox.showerror("Error", "Please enter a URL")
        return

    local_result = is_phishing(url)
    api_result = api_check_url(url)

    final_result = (
        "🔍 LOCAL SCAN RESULT:\n"
        f"{local_result}\n\n"
        "🌐 REAL-TIME API RESULT:\n"
        f"{api_result}"
    )

    messagebox.showinfo("Scan Result", final_result)

# ================== GUI DESIGN ==================
root = tk.Tk()
root.title("Phishing URL Detector")
root.geometry("500x320")
root.config(bg="#1e1e2e")

title = tk.Label(
    root,
    text="🔐 Phishing URL Detector",
    font=("Segoe UI", 18, "bold"),
    bg="#1e1e2e",
    fg="#ffffff"
)
title.pack(pady=15)

frame = tk.Frame(root, bg="#2a2a40", padx=20, pady=20)
frame.pack(pady=10)

label = tk.Label(
    frame,
    text="Enter URL:",
    font=("Segoe UI", 12),
    bg="#2a2a40",
    fg="#ffffff"
)
label.pack(anchor="w")

entry = tk.Entry(
    frame,
    width=45,
    font=("Segoe UI", 12),
    relief="flat",
    bg="#3b3b58",
    fg="white",
    insertbackground="white"
)
entry.pack(pady=8)

btn = tk.Button(
    frame,
    text="Check URL",
    font=("Segoe UI", 12, "bold"),
    bg="#4a4aff",
    fg="white",
    activebackground="#3737d6",
    relief="flat",
    command=check_url,
    padx=10,
    pady=5
)
btn.pack(pady=10)

root.mainloop()

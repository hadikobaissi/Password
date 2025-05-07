
import tkinter as tk
from tkinter import messagebox
import re
import hashlib
import requests
import math

def check_pwned(password):
    sha1pwd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1pwd[:5], sha1pwd[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    res = requests.get(url)

    if res.status_code != 200:
        return -1  # API error

    hashes = (line.split(":") for line in res.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return int(count)
    return 0

def estimate_time_to_crack(password):
    pool = 0
    if re.search(r'[a-z]', password): pool += 26
    if re.search(r'[A-Z]', password): pool += 26
    if re.search(r'[0-9]', password): pool += 10
    if re.search(r'[^A-Za-z0-9]', password): pool += 32  # approx special chars

    combinations = pool ** len(password)
    guesses_per_second = 1_000_000_000  # 1 billion guesses/sec
    seconds = combinations / guesses_per_second

    years = seconds / (60 * 60 * 24 * 365)
    if years > 1000:
        return "1000+ years (very strong)"
    elif years > 1:
        return f"{years:.1f} years"
    elif seconds > 60:
        return f"{seconds / 60:.1f} minutes"
    else:
        return f"{seconds:.1f} seconds"

def check_strength(password):
    score = 0
    feedback = []

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Too short.")

    if re.search(r"[a-z]", password): score += 1
    else: feedback.append("Add lowercase.")

    if re.search(r"[A-Z]", password): score += 1
    else: feedback.append("Add uppercase.")

    if re.search(r"[0-9]", password): score += 1
    else: feedback.append("Add numbers.")

    if re.search(r"[^A-Za-z0-9]", password): score += 1
    else: feedback.append("Add special characters.")

    return score, feedback

def analyze_password():
    pwd = entry.get()
    score, fb = check_strength(pwd)
    pwned_count = check_pwned(pwd)
    crack_time = estimate_time_to_crack(pwd)

    strength_levels = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong"]
    result = f" Password Strength: {strength_levels[score]}\n"

    if fb:
        result += "🛠️ Suggestions:\n" + "\n".join(f"- {s}" for s in fb)

    result += f"\n⏱️ Estimated Time to Crack: {crack_time}"

    if pwned_count == -1:
        result += "\n⚠ Could not check HaveIBeenPwned."
    elif pwned_count > 0:
        result += f"\n❌ Found in {pwned_count} data breaches!"
    else:
        result += "\n✅ Not found in known breaches."

    messagebox.showinfo("Password Analysis", result)

def toggle_visibility():
    if entry.cget('show') == '':
        entry.config(show='*')
        toggle_btn.config(text="Show")
    else:
        entry.config(show='')
        toggle_btn.config(text="Hide")

# GUI setup
window = tk.Tk()
window.title("Password Strength Checker")
window.geometry("420x220")

label = tk.Label(window, text="Enter a password to check:", font=("Arial", 12))
label.pack(pady=10)

entry = tk.Entry(window, show="*", width=30, font=("Arial", 12))
entry.pack()

toggle_btn = tk.Button(window, text="Show", command=toggle_visibility)
toggle_btn.pack(pady=5)

btn = tk.Button(window, text="Check Password", command=analyze_password)
btn.pack(pady=10)

window.mainloop()

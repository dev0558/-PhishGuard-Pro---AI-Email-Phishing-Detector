# === IMPORTS ===
import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext, ttk
import joblib
import numpy as np
import re
import os
from datetime import datetime

# === LOAD MODEL AND VECTORIZER ===
try:
    model = joblib.load(r"phishing_model(1).pkl")
    vectorizer = joblib.load(r"vectorizer(1).pkl")
except Exception as e:
    raise FileNotFoundError("Ensure both 'phishing_model(1).pkl' and 'vectorizer(1).pkl' are in the same directory.") from e

# === PREMIUM COLOR SCHEME ===
COLORS = {
    'primary_bg': '#0a0a0f',           # Deep space black
    'secondary_bg': '#1a1a2e',         # Rich navy
    'card_bg': '#16213e',              # Card background
    'elevated_bg': '#0f3460',          # Elevated elements
    'accent_primary': '#667eea',       # Beautiful blue gradient start
    'accent_secondary': '#764ba2',     # Purple gradient end
    'success': '#00d4aa',              # Modern teal success
    'danger': '#ff6b6b',               # Warm red
    'warning': '#ffd93d',              # Bright yellow
    'text_primary': '#ffffff',         # Pure white
    'text_secondary': '#e2e8f0',       # Light gray
    'text_muted': '#94a3b8',           # Muted gray
    'border_subtle': '#2d3748',        # Subtle borders
    'border_accent': '#4a5568',        # Accent borders
    'hover_bg': '#2a2d3a',            # Hover states
    'input_bg': '#1e2029',            # Input backgrounds
    'shadow': '#000000',              # Shadows
}

# === FONTS ===
FONTS = {
    'heading_xl': ('SF Pro Display', 32, 'bold'),
    'heading_lg': ('SF Pro Display', 24, 'bold'),
    'heading_md': ('SF Pro Display', 18, 'bold'),
    'heading_sm': ('SF Pro Display', 16, 'bold'),
    'body_lg': ('SF Pro Text', 16),
    'body_md': ('SF Pro Text', 14),
    'body_sm': ('SF Pro Text', 12),
    'mono': ('SF Mono', 13),
    'button': ('SF Pro Display', 14, 'bold'),
}

# === ANALYSIS HISTORY CLASS ===
class AnalysisHistory:
    def __init__(self):
        self.history = []
    
    def add_entry(self, email_preview, result, confidence):
        timestamp = datetime.now().strftime("%H:%M:%S")
        entry = {
            'time': timestamp,
            'preview': email_preview[:80] + "..." if len(email_preview) > 80 else email_preview,
            'result': result,
            'confidence': confidence
        }
        self.history.insert(0, entry)
        if len(self.history) > 8:
            self.history.pop()

# === PHISHING INDICATORS ANALYSIS ===
def analyze_email_content(email_text):
    """Analyze email content for common phishing indicators."""
    indicators = {
        'suspicious_urls': [],
        'urgent_phrases': [],
        'suspicious_domains': [],
        'personal_info_requests': [],
        'grammar_issues': 0,
        'suspicious_senders': []
    }
    
    # Check for suspicious URLs
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, email_text.lower())
    
    suspicious_domains = ['bit.ly', 'tinyurl', 't.co', 'short.link', 'ow.ly', 'goo.gl']
    for url in urls:
        for domain in suspicious_domains:
            if domain in url:
                indicators['suspicious_urls'].append(url)
    
    # Check for urgent/threatening phrases
    urgent_phrases = [
        'urgent', 'immediate action', 'act now', 'limited time', 'expire today',
        'suspended', 'verify immediately', 'click here now', 'confirm identity',
        'update payment', 'account will be closed', 'security alert', 'winner',
        'congratulations', 'claim now', 'free money', 'inheritance'
    ]
    
    for phrase in urgent_phrases:
        if phrase in email_text.lower():
            indicators['urgent_phrases'].append(phrase)
    
    # Check for personal information requests
    personal_requests = [
        'social security', 'ssn', 'credit card', 'password', 'pin number',
        'bank account', 'routing number', 'personal information', 'verify account',
        'login credentials', 'full name', 'date of birth'
    ]
    
    for request in personal_requests:
        if request in email_text.lower():
            indicators['personal_info_requests'].append(request)
    
    # Check for suspicious sender patterns
    suspicious_patterns = ['noreply@', 'no-reply@', 'admin@', 'support@']
    for pattern in suspicious_patterns:
        if pattern in email_text.lower():
            indicators['suspicious_senders'].append(pattern)
    
    # Grammar and formatting issues
    grammar_issues = len(re.findall(r'[a-z][A-Z]', email_text))
    grammar_issues += len(re.findall(r'\s{3,}', email_text))
    grammar_issues += len(re.findall(r'!!+', email_text))
    indicators['grammar_issues'] = grammar_issues
    
    return indicators

def generate_explanation(label, confidence, email_text):
    """Generate detailed explanation for the prediction."""
    indicators = analyze_email_content(email_text)
    
    if label == "Phishing":
        reasons = []
        
        if indicators['suspicious_urls']:
            reasons.append(f"🔗 Suspicious shortened URLs detected")
        
        if indicators['urgent_phrases']:
            reasons.append(f"⚡ Urgent/threatening language patterns")
        
        if indicators['personal_info_requests']:
            reasons.append(f"🔐 Requests for sensitive information")
        
        if indicators['grammar_issues'] > 3:
            reasons.append("📝 Multiple grammar/formatting irregularities")
        
        if indicators['suspicious_senders']:
            reasons.append("📧 Suspicious sender patterns identified")
        
        if not reasons:
            reasons.append("🤖 AI model detected phishing patterns")
        
        explanation = "🚨 SECURITY ALERT - PHISHING DETECTED:\n\n" + "\n".join(f"• {reason}" for reason in reasons)
        
    else:
        reasons = []
        
        if not indicators['suspicious_urls']:
            reasons.append("✅ No suspicious URLs found")
        
        if not indicators['urgent_phrases']:
            reasons.append("✅ Professional communication tone")
        
        if not indicators['personal_info_requests']:
            reasons.append("✅ No sensitive information requests")
        
        if indicators['grammar_issues'] <= 2:
            reasons.append("✅ Proper grammar and formatting")
        
        if not reasons:
            reasons.append("✅ All security checks passed")
        
        explanation = "🛡️ SECURITY VERIFIED - EMAIL IS LEGITIMATE:\n\n" + "\n".join(f"• {reason}" for reason in reasons)
    
    return explanation

# === PREDICTION FUNCTION ===
def predict_email(email_text):
    """Predict if an email is phishing or legitimate with confidence score and explanation."""
    email_vector = vectorizer.transform([email_text])
    prediction = model.predict(email_vector)
    probabilities = model.predict_proba(email_vector)
    confidence = np.max(probabilities) * 100
    label = "Phishing" if prediction[0] == 1 else "Legitimate"
    explanation = generate_explanation(label, confidence, email_text)
    return label, confidence, explanation

# === PREMIUM GRADIENT BUTTON CLASS ===
class GradientButton(tk.Button):
    def __init__(self, parent, **kwargs):
        self.bg_color = kwargs.pop('bg_color', COLORS['accent_primary'])
        self.hover_color = kwargs.pop('hover_color', COLORS['accent_secondary'])
        self.text_color = kwargs.pop('text_color', COLORS['text_primary'])
        
        super().__init__(parent, **kwargs)
        
        self.configure(
            relief=tk.FLAT,
            borderwidth=0,
            bg=self.bg_color,
            fg=self.text_color,
            activebackground=self.hover_color,
            activeforeground=self.text_color,
            cursor='hand2',
            font=FONTS['button'],
            pady=15,
            padx=30
        )
        
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
    
    def _on_enter(self, event):
        self.configure(bg=self.hover_color)
    
    def _on_leave(self, event):
        self.configure(bg=self.bg_color)

# === PREMIUM CARD FRAME ===
class PremiumCard(tk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, 
                        bg=COLORS['card_bg'], 
                        relief=tk.FLAT,
                        **kwargs)
        
        # Add subtle border effect
        self.configure(highlightbackground=COLORS['border_accent'], 
                      highlightthickness=1)

# === GUI ACTIONS ===
def on_check():
    email_text = email_entry.get("1.0", tk.END).strip()
    if not email_text:
        messagebox.showwarning("Input Required", "Please enter email content to analyze.")
        return
    
    # Show loading state
    analyze_btn.configure(text="🔄 ANALYZING...", state=tk.DISABLED)
    root.update()
    
    try:
        label, confidence, explanation = predict_email(email_text)
        
        # Add to history
        history.add_entry(email_text, label, confidence)
        update_history_display()
        
        # Update result display with animation-like effect
        if label == "Phishing":
            result_icon.configure(text="⚠️", fg=COLORS['danger'])
            result_label.configure(text="PHISHING DETECTED", fg=COLORS['danger'])
            confidence_label.configure(text=f"Confidence: {confidence:.1f}%")
            result_card.configure(highlightbackground=COLORS['danger'])
        else:
            result_icon.configure(text="🛡️", fg=COLORS['success'])
            result_label.configure(text="EMAIL IS SAFE", fg=COLORS['success'])
            confidence_label.configure(text=f"Confidence: {confidence:.1f}%")
            result_card.configure(highlightbackground=COLORS['success'])
        
        # Update explanation
        explanation_text.configure(state=tk.NORMAL)
        explanation_text.delete("1.0", tk.END)
        explanation_text.insert("1.0", explanation)
        explanation_text.configure(state=tk.DISABLED)
        
        # Update status
        status_label.configure(text=f"✓ Analysis Complete - {label} Detected", 
                              fg=COLORS['success'])
        
    except Exception as e:
        messagebox.showerror("Analysis Error", f"An error occurred: {str(e)}")
    finally:
        analyze_btn.configure(text="🔍 ANALYZE EMAIL", state=tk.NORMAL)

def on_clear():
    email_entry.delete("1.0", tk.END)
    result_icon.configure(text="", fg=COLORS['text_primary'])
    result_label.configure(text="", fg=COLORS['text_primary'])
    confidence_label.configure(text="")
    explanation_text.configure(state=tk.NORMAL)
    explanation_text.delete("1.0", tk.END)
    explanation_text.configure(state=tk.DISABLED)
    file_label.configure(text="No file selected")
    status_label.configure(text="Ready for Analysis", fg=COLORS['text_secondary'])
    result_card.configure(highlightbackground=COLORS['border_accent'])
    update_char_count()

def on_load_file():
    file_path = filedialog.askopenfilename(
        title="Select Email File",
        filetypes=[
            ("Text files", "*.txt"),
            ("Email files", "*.eml"),
            ("All files", "*.*")
        ]
    )
    
    if file_path:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                content = file.read()
                email_entry.delete("1.0", tk.END)
                email_entry.insert("1.0", content)
                file_label.configure(text=f"📎 {os.path.basename(file_path)}")
                status_label.configure(text=f"📁 File Loaded: {os.path.basename(file_path)}", 
                                      fg=COLORS['success'])
                update_char_count()
        except Exception as e:
            messagebox.showerror("File Error", f"Could not read file: {str(e)}")

def load_sample_phishing():
    sample = """URGENT: Your PayPal account has been compromised!

Dear Customer,

Your PayPal account will be suspended in 24 hours due to suspicious activity. 
Click here IMMEDIATELY to verify your identity: http://bit.ly/paypal-verify-now

Please provide:
- Full Name
- Credit Card Number  
- Social Security Number
- Password

Failure to act now will result in permanent account closure!

Best regards,
PayPal Security Team
(This is not from PayPal)"""
    
    email_entry.delete("1.0", tk.END)
    email_entry.insert("1.0", sample)
    status_label.configure(text="📧 Sample Phishing Email Loaded", fg=COLORS['warning'])
    update_char_count()

def load_sample_legitimate():
    sample = """Hi there,

Thank you for your recent purchase from Amazon. Your order #123-4567890-1234567 has been shipped and is on its way to you.

Order Details:
- iPhone 15 Pro Max - $1,199.00
- Shipping: FREE
- Estimated Delivery: Tomorrow by 10 PM

You can track your package at: amazon.com/your-orders

If you have any questions, please contact customer service through your Amazon account.

Best regards,
Amazon Customer Service"""
    
    email_entry.delete("1.0", tk.END)
    email_entry.insert("1.0", sample)
    status_label.configure(text="📧 Sample Legitimate Email Loaded", fg=COLORS['success'])
    update_char_count()

def update_history_display():
    history_listbox.delete(0, tk.END)
    
    for i, entry in enumerate(history.history):
        status_icon = "🚨" if entry['result'] == 'Phishing' else "✅"
        display_text = f"{status_icon} [{entry['time']}] {entry['result']} ({entry['confidence']:.0f}%)"
        history_listbox.insert(tk.END, display_text)
        
        # Color coding with better contrast
        if entry['result'] == 'Phishing':
            history_listbox.itemconfig(i, {'fg': '#ff8a80'})  # Lighter red for better visibility
        else:
            history_listbox.itemconfig(i, {'fg': '#69f0ae'})  # Lighter green for better visibility

def update_char_count(*args):
    content = email_entry.get("1.0", tk.END)
    char_count = len(content) - 1
    char_label.configure(text=f"Characters: {char_count:,}")

# === INITIALIZE ===
history = AnalysisHistory()

# === MAIN WINDOW SETUP ===
root = tk.Tk()
root.title("PhishGuard Pro - AI Email Security")
root.geometry("1600x1000")
root.configure(bg=COLORS['primary_bg'])
root.resizable(True, True)

# === HEADER SECTION ===
header = tk.Frame(root, bg=COLORS['primary_bg'], height=100)
header.pack(fill='x', padx=0, pady=0)
header.pack_propagate(False)

# Logo and Title
title_frame = tk.Frame(header, bg=COLORS['primary_bg'])
title_frame.pack(expand=True, fill='both')

logo_label = tk.Label(title_frame, text="🛡️", font=('SF Pro Display', 40), 
                     fg=COLORS['accent_primary'], bg=COLORS['primary_bg'])
logo_label.pack(side='left', padx=(40, 20), pady=20)

title_container = tk.Frame(title_frame, bg=COLORS['primary_bg'])
title_container.pack(side='left', fill='y', pady=20)

main_title = tk.Label(title_container, text="PhishGuard Pro", 
                     font=FONTS['heading_xl'], 
                     fg=COLORS['text_primary'], bg=COLORS['primary_bg'])
main_title.pack(anchor='w')

subtitle = tk.Label(title_container, text="AI-Powered Email Security Analysis", 
                   font=FONTS['body_lg'], 
                   fg=COLORS['text_secondary'], bg=COLORS['primary_bg'])
subtitle.pack(anchor='w')

# === MAIN CONTENT CONTAINER ===
main_container = tk.Frame(root, bg=COLORS['primary_bg'])
main_container.pack(fill='both', expand=True, padx=30, pady=(0, 30))

# === LEFT PANEL - EMAIL INPUT ===
left_panel = PremiumCard(main_container)
left_panel.pack(side='left', fill='both', expand=True, padx=(0, 15))

# Left panel header
left_header = tk.Frame(left_panel, bg=COLORS['card_bg'], height=80)
left_header.pack(fill='x', padx=0, pady=0)
left_header.pack_propagate(False)

left_title_frame = tk.Frame(left_header, bg=COLORS['card_bg'])
left_title_frame.pack(fill='both', expand=True, padx=30, pady=20)

left_icon = tk.Label(left_title_frame, text="📧", font=('SF Pro Display', 24),
                    fg=COLORS['accent_primary'], bg=COLORS['card_bg'])
left_icon.pack(side='left')

left_title = tk.Label(left_title_frame, text="Email Content Analysis", 
                     font=FONTS['heading_md'],
                     fg=COLORS['text_primary'], bg=COLORS['card_bg'])
left_title.pack(side='left', padx=(15, 0))

# File operations
file_frame = tk.Frame(left_panel, bg=COLORS['card_bg'])
file_frame.pack(fill='x', padx=30, pady=(20, 0))

load_file_btn = GradientButton(file_frame, text="📁 LOAD FILE", 
                              command=on_load_file,
                              bg_color=COLORS['accent_primary'])
load_file_btn.pack(side='left', padx=(0, 15))

sample_phish_btn = GradientButton(file_frame, text="⚠️ SAMPLE PHISHING", 
                                 command=load_sample_phishing,
                                 bg_color=COLORS['danger'])
sample_phish_btn.pack(side='left', padx=(0, 15))

sample_safe_btn = GradientButton(file_frame, text="✅ SAMPLE SAFE", 
                                command=load_sample_legitimate,
                                bg_color=COLORS['success'])
sample_safe_btn.pack(side='left')

file_label = tk.Label(file_frame, text="No file selected", 
                     font=FONTS['body_md'], fg=COLORS['text_muted'], 
                     bg=COLORS['card_bg'])
file_label.pack(side='right', pady=10)

# Email input section
input_frame = tk.Frame(left_panel, bg=COLORS['card_bg'])
input_frame.pack(fill='both', expand=True, padx=30, pady=20)

input_label = tk.Label(input_frame, text="Email Content", 
                      font=FONTS['heading_sm'], 
                      fg=COLORS['text_primary'], bg=COLORS['card_bg'])
input_label.pack(anchor='w', pady=(0, 15))

# Text area with premium styling
email_entry = scrolledtext.ScrolledText(
    input_frame, height=20, font=FONTS['mono'],
    wrap=tk.WORD, relief=tk.FLAT, borderwidth=0,
    bg=COLORS['input_bg'], fg=COLORS['text_primary'],
    selectbackground=COLORS['accent_primary'], 
    selectforeground=COLORS['text_primary'],
    insertbackground=COLORS['text_primary'],
    highlightthickness=2,
    highlightcolor=COLORS['accent_primary'],
    highlightbackground=COLORS['border_subtle']
)
email_entry.pack(fill='both', expand=True, pady=(0, 20))

# Character count and action buttons
bottom_frame = tk.Frame(left_panel, bg=COLORS['card_bg'])
bottom_frame.pack(fill='x', padx=30, pady=(0, 30))

char_label = tk.Label(bottom_frame, text="Characters: 0", 
                     font=FONTS['body_sm'], fg=COLORS['text_muted'], 
                     bg=COLORS['card_bg'])
char_label.pack(side='right')

action_frame = tk.Frame(bottom_frame, bg=COLORS['card_bg'])
action_frame.pack(side='left')

analyze_btn = GradientButton(action_frame, text="🔍 ANALYZE EMAIL", 
                            command=on_check,
                            bg_color=COLORS['danger'],
                            hover_color='#ff5252')
analyze_btn.pack(side='left', padx=(0, 20))

clear_btn = GradientButton(action_frame, text="🗑️ CLEAR", 
                          command=on_clear,
                          bg_color=COLORS['elevated_bg'],
                          hover_color=COLORS['hover_bg'])
clear_btn.pack(side='left')

# === RIGHT PANEL - RESULTS ===
right_panel = PremiumCard(main_container)
right_panel.pack(side='right', fill='both', expand=True, padx=(15, 0))

# Right panel header
right_header = tk.Frame(right_panel, bg=COLORS['card_bg'], height=80)
right_header.pack(fill='x')
right_header.pack_propagate(False)

right_title_frame = tk.Frame(right_header, bg=COLORS['card_bg'])
right_title_frame.pack(fill='both', expand=True, padx=30, pady=20)

right_icon = tk.Label(right_title_frame, text="📊", font=('SF Pro Display', 24),
                     fg=COLORS['accent_secondary'], bg=COLORS['card_bg'])
right_icon.pack(side='left')

right_title = tk.Label(right_title_frame, text="Analysis Results", 
                      font=FONTS['heading_md'],
                      fg=COLORS['text_primary'], bg=COLORS['card_bg'])
right_title.pack(side='left', padx=(15, 0))

# Results display card
result_card = PremiumCard(right_panel)
result_card.pack(fill='x', padx=30, pady=(20, 0))

result_content = tk.Frame(result_card, bg=COLORS['card_bg'])
result_content.pack(fill='both', padx=40, pady=40)

result_icon = tk.Label(result_content, text="🔍", font=('SF Pro Display', 60),
                      fg=COLORS['text_muted'], bg=COLORS['card_bg'])
result_icon.pack(pady=(0, 20))

result_label = tk.Label(result_content, text="Ready to Analyze", 
                       font=FONTS['heading_lg'],
                       fg=COLORS['text_muted'], bg=COLORS['card_bg'])
result_label.pack(pady=(0, 10))

confidence_label = tk.Label(result_content, text="", 
                           font=FONTS['body_lg'],
                           fg=COLORS['text_secondary'], bg=COLORS['card_bg'])
confidence_label.pack()

# Analysis details section
details_frame = tk.Frame(right_panel, bg=COLORS['card_bg'])
details_frame.pack(fill='both', expand=True, padx=30, pady=20)

details_label = tk.Label(details_frame, text="📋 Analysis Details", 
                        font=FONTS['heading_sm'], 
                        fg=COLORS['text_primary'], bg=COLORS['card_bg'])
details_label.pack(anchor='w', pady=(0, 15))

explanation_text = scrolledtext.ScrolledText(
    details_frame, height=8, font=FONTS['body_md'], 
    wrap=tk.WORD, state=tk.DISABLED, relief=tk.FLAT,
    bg=COLORS['input_bg'], fg=COLORS['text_primary'],
    borderwidth=0, highlightthickness=1,
    highlightcolor=COLORS['border_accent'],
    highlightbackground=COLORS['border_subtle']
)
explanation_text.pack(fill='both', expand=True, pady=(0, 20))

# History section
history_label = tk.Label(details_frame, text="📈 Recent Analysis", 
                        font=FONTS['heading_sm'], 
                        fg=COLORS['text_primary'], bg=COLORS['card_bg'])
history_label.pack(anchor='w', pady=(20, 15))

history_listbox = tk.Listbox(
    details_frame, height=6, font=FONTS['body_sm'],
    bg=COLORS['card_bg'], fg=COLORS['text_primary'],
    selectbackground=COLORS['accent_primary'],
    selectforeground=COLORS['text_primary'],
    borderwidth=1, highlightthickness=1,
    highlightcolor=COLORS['accent_primary'],
    highlightbackground=COLORS['border_accent'],
    relief=tk.FLAT
)
history_listbox.pack(fill='both', expand=True)

# === STATUS BAR ===
status_bar = tk.Frame(root, bg=COLORS['secondary_bg'], height=50)
status_bar.pack(fill='x', side='bottom')
status_bar.pack_propagate(False)

status_content = tk.Frame(status_bar, bg=COLORS['secondary_bg'])
status_content.pack(fill='both', expand=True, padx=40, pady=15)

status_label = tk.Label(status_content, text="Ready for Analysis", 
                       font=FONTS['body_md'], fg=COLORS['text_secondary'], 
                       bg=COLORS['secondary_bg'])
status_label.pack(side='left')

instructions_label = tk.Label(status_content, 
                             text="💡 Pro Tip: Try the sample emails to see PhishGuard in action", 
                             font=FONTS['body_sm'], fg=COLORS['text_muted'],
                             bg=COLORS['secondary_bg'])
instructions_label.pack(side='right')

# === BIND EVENTS ===
email_entry.bind('<KeyRelease>', update_char_count)
email_entry.bind('<Button-1>', update_char_count)

# === INITIALIZE DISPLAY ===
update_char_count()

# === START APPLICATION ===
if __name__ == "__main__":
    root.mainloop()

import requests
import urllib.parse
import re
import sys

# List of known URL shortener services (you can expand this list)
SHORTENER_DOMAINS = [
    'bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'ow.ly', 'buff.ly', 'is.gd',
    't.ly', 'cutt.ly', 'rebrand.ly', 'bl.ink', 'rb.gy', 'shorte.st', 'shorturl.at'
]

# Function to display the introductory page
def display_intro():
    print("=" * 60)
    print(" " * 10 + "Shortguard: URL Shortener Exploit Detection")
    print(" " * 20 + "Created by: Aniket")
    print("=" * 60)
    print("\nWelcome to Shortguard! This tool helps you detect potentially malicious URLs hidden behind short links.\n")

# Check if the URL belongs to a known URL shortener
def is_shortened_url(url):
    parsed_url = urllib.parse.urlparse(url)
    domain = parsed_url.netloc.lower()
    return any(domain.endswith(shortener) for shortener in SHORTENER_DOMAINS)

# Unshortening URL 
def unshorten_url(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        return response.url
    except requests.RequestException as e:
        print(f"[ERROR] Could not resolve shortened URL: {e}")
        return None


import base64

# To check if the URL is blacklisted using VirusTotal Public API (replace 'YOUR_API_KEY' with your actual API key)
import base64
import requests

def check_blacklist(url):
    try:
        api_key = "383113349314c71f69393e1009f77c5743117033d1eff9cbc9f532ee9022af33"
        headers = {
            "x-apikey": api_key
        }

        # VirusTotal requires the URL to be base64-encoded
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        # API endpoint for URL analysis
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        print(f"[DEBUG] Sending request to VirusTotal for URL: {url}")
        response = requests.get(vt_url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            analysis_stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            print(f"[DEBUG] VirusTotal response: {analysis_stats}")
            return analysis_stats
        else:
            print(f"[ERROR] VirusTotal API returned status code: {response.status_code}")
            print(f"[DEBUG] Response content: {response.text}")
            return None

    except Exception as e:
        print(f"[ERROR] VirusTotal lookup failed: {e}")
        return None


# Detect phishing by checking for common phishing patterns in the URL
def detect_phishing(url):
    phishing_indicators = [
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address in URL
        r'@',                                   # "@" symbol in URL
        r'https?://[^/]*[^\w\-\.]$',            # Special characters in domain
        r'login|signin|secure|account|update|verify|password|bank|paypal|phonepe|paytm|bharatpe|googlepay'
    ]
    for pattern in phishing_indicators:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    return False

# Main function to check URL
def check_url(url):
    print(f"[INFO] Checking URL: {url}")
    
    # Initialize original_url with the input URL by default
    original_url = url

    # Step 1: Check if it's a shortened URL
    if is_shortened_url(url):
        print("[INFO] Shortened URL detected.")
        original_url = unshorten_url(url)
        if original_url:
            print(f"[INFO] Resolved to: {original_url}")
        else:
            print("[ERROR] Could not resolve shortened URL.")
            return

    # Step 2: Check for blacklist
    blacklist_result = check_blacklist(original_url)
    if blacklist_result:
        if blacklist_result.get('malicious', 0) > 0:
            print("[WARNING] URL detected as malicious based on blacklist.")
        else:
            print("[INFO] URL appears safe according to blacklist check.")
    else:
        print("[INFO] No blacklist data available for this URL.")

    # Step 3: Phishing detection
    if detect_phishing(original_url):
        print("[WARNING] Potential phishing URL detected!")
    else:
        print("[INFO] No phishing indicators found.")

    print("[INFO] URL analysis completed.\n")


# Entry point of the script
if __name__ == "__main__":
    # Display the intro page
    display_intro()

    # Prompt user for input URL
    url_to_check = input("Please paste the URL you want to analyze: ").strip()

    # Check if the user entered a URL
    if url_to_check:
        check_url(url_to_check)
    else:
        print("[ERROR] No URL provided. Please try again.")

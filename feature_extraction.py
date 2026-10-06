import socket
from urllib.parse import urlparse
import re
import math


FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "num_dots",
    "num_hyphens",
    "num_special_chars",
    "has_at_symbol",
    "is_https",
    "num_digits",
    "suspicious_words_count",
    "num_subdomains",
    "has_ip_address",
    "is_shortened",
    "has_double_slash_redirect",
    "has_domain_hyphen",
    "url_entropy"
]

SUSPICIOUS_WORDS = [
    "login", "verify", "account", "secure", "update", "password",
    "bank", "confirm", "free", "winner", "signin", "auth",
    "suspended", "billing", "unfreeze", "support", "bonus",
    "claim", "wallet", "kyc", "unlock", "payment", "urgent"
]

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly"
]

VERIFIED_LEGITIMATE_DOMAINS = {
    "google", "youtube", "facebook", "instagram", "twitter", "x", "wikipedia",
    "amazon", "microsoft", "apple", "netflix", "reddit", "linkedin", "github",
    "stackoverflow", "wordpress", "pinterest", "spotify", "yahoo", "ebay",
    "walmart", "cnn", "bbc", "nytimes", "imdb", "medium", "twitch", "adobe",
    "salesforce", "shopify", "dropbox", "slack", "zoom", "canva", "openai",
    "chase", "bankofamerica", "wellsfargo", "paypal", "binance", "coinbase",
    "hashnode", "pypi", "ikea", "playstation", "xbox", "trello", "affirm",
    "square", "schwab", "santander", "cloudflare", "mozilla", "w3schools",
    "sciencedirect", "caltech", "nvidia", "ibm", "target", "bestbuy",
    "leetcode", "hackerrank", "codeforces", "geeksforgeeks", "kaggle",
    "coursera", "udemy", "edx", "freecodecamp", "gitlab", "bitbucket",
    "docker", "kubernetes", "npmjs", "python", "vercel", "netlify",
    "figma", "notion", "linear", "discord", "telegram", "sublime",
    "oracle", "intel", "amd", "cisco", "atlassian", "jira", "confluence"
}

DICTIONARY_ROOTS = {
    "tech", "cloud", "data", "cyber", "code", "dev", "app", "net", "web", "hub",
    "lab", "link", "smart", "host", "mail", "media", "digital", "secure", "pay",
    "shop", "market", "trade", "travel", "game", "news", "daily", "global", "world",
    "life", "health", "fast", "easy", "open", "free", "box", "node", "craft", "flow",
    "space", "base", "line", "point", "work", "zone", "post", "cast", "feed", "wire",
    "wave", "byte", "stack", "sync", "track", "view", "spot", "core", "pulse", "spark",
    "snap", "star", "edge", "prime", "peak", "shift", "shield", "guard", "lock", "key",
    "book", "face", "drop", "sound", "air", "play", "station", "hash", "well", "fargo",
    "fire", "fox", "soft", "micro", "tube", "gram", "insta", "tik", "tok", "red", "dit",
    "blog", "site", "page", "desk", "room", "land", "port", "city", "town", "bank", "card",
    "leet", "hack", "rank", "force", "geek", "learn", "study", "camp", "quest", "solve"
}


def normalize_url(url: str) -> str:
    """Normalize any input URL format (e.g. bare domain, custom port, query) safely."""
    url_str = str(url).strip()
    if not url_str:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url_str):
        url_str = "http://" + url_str
    return url_str


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy to measure character randomness."""
    if not text:
        return 0.0
    probabilities = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    entropy = -sum(p * math.log2(p) for p in probabilities if p > 0)
    return round(entropy, 4)


def is_pronounced_word(domain_label: str) -> bool:
    """Checks if a domain label has natural vowel/consonant distribution rather than DGA consonant spam."""
    label = domain_label.lower().strip()
    if len(label) <= 3:
        return True
    vowels = set("aeiouy")
    vowel_count = sum(1 for c in label if c in vowels)
    vowel_ratio = vowel_count / len(label)
    if vowel_ratio < 0.15:
        return False
    # Check for 5+ consecutive consonants (unpronounceable botnet DGA cluster)
    if re.search(r"[^aeiouy0-9\-]{5,}", label):
        return False
    return True


def check_domain_dns(hostname: str) -> bool:
    """Fast DNS resolution check (1.5s timeout) to verify domain existence in global DNS."""
    try:
        socket.setdefaulttimeout(1.5)
        socket.getaddrinfo(hostname, None)
        return True
    except Exception:
        return False


def extract_features(url: str):
    """
    Extract 15 numerical features from a URL string for ML models.
    Supports any URL format (full URL, bare domain, IP address, etc.).
    """
    raw_url = str(url).strip()
    normalized = normalize_url(raw_url)
    
    parsed_url = urlparse(normalized)
    hostname = (parsed_url.hostname or "").lower()
    path = parsed_url.path or ""

    features = []

    # 1. Total URL Length
    features.append(len(raw_url))

    # 2. Domain Length
    features.append(len(hostname))

    # 3. Number of dots in URL
    features.append(raw_url.count("."))

    # 4. Number of hyphens in URL
    features.append(raw_url.count("-"))

    # 5. Number of special characters (@, ?, =, %, &)
    features.append(len(re.findall(r"[@?=&%]", raw_url)))

    # 6. Has '@' symbol (often used to obscure real host)
    features.append(1 if "@" in raw_url else 0)

    # 7. HTTPS check
    features.append(1 if raw_url.lower().startswith("https://") else 0)

    # 8. Number of numeric digits
    features.append(sum(c.isdigit() for c in raw_url))

    # 9. Suspicious keywords count
    suspicious_count = sum(1 for word in SUSPICIOUS_WORDS if word in raw_url.lower())
    features.append(suspicious_count)

    # 10. Number of subdomains
    if hostname:
        dots_in_host = hostname.count(".")
        features.append(max(0, dots_in_host - 1))
    else:
        features.append(0)

    # 11. Has IP address in hostname
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    has_ip = 1 if re.match(ip_pattern, hostname) else 0
    features.append(has_ip)

    # 12. Shortened URL indicator
    is_shortened = 1 if any(short in hostname for short in SHORTENER_DOMAINS) else 0
    features.append(is_shortened)

    # 13. Double slash redirection (// in path)
    has_double_slash = 1 if "//" in path else 0
    features.append(has_double_slash)

    # 14. Domain contains hyphens (prefix/suffix attacks)
    features.append(1 if "-" in hostname else 0)

    # 15. URL Shannon Entropy
    features.append(calculate_entropy(raw_url))

    return features


KNOWN_BRANDS = {
    "worldhealth": "World Health Organization (WHO)",
    "google": "Google",
    "microsoft": "Microsoft",
    "apple": "Apple",
    "amazon": "Amazon",
    "facebook": "Facebook / Meta",
    "instagram": "Instagram",
    "twitter": "Twitter / X",
    "netflix": "Netflix",
    "paypal": "PayPal",
    "binance": "Binance",
    "coinbase": "Coinbase",
    "chase": "Chase Bank",
    "wellsfargo": "Wells Fargo",
    "bankofamerica": "Bank of America",
    "citibank": "Citibank",
    "capitalone": "Capital One",
    "barclays": "Barclays Bank",
    "santander": "Santander",
    "revolut": "Revolut",
    "whatsapp": "WhatsApp",
    "telegram": "Telegram",
    "discord": "Discord",
    "spotify": "Spotify",
    "github": "GitHub",
    "linkedin": "LinkedIn",
    "dropbox": "Dropbox",
    "yahoo": "Yahoo",
    "adobe": "Adobe",
    "walmart": "Walmart",
    "ebay": "eBay",
    "target": "Target",
    "shopify": "Shopify",
    "fedex": "FedEx",
    "dhl": "DHL Express",
    "usps": "USPS",
    "tiktok": "TikTok",
    "zoom": "Zoom",
    "healthline": "Healthline",
    "metamask": "MetaMask",
    "blockchain": "Blockchain.com",
    "steam": "Steam",
    "playstation": "PlayStation",
    "youtube": "YouTube"
}

HOMOGLYPH_MAP = {
    "0": "o", "1": "l", "3": "e", "5": "s", "8": "b", "@": "a", "$": "s", "vv": "w"
}

KEYBOARD_ADJACENT = {
    "q": "wa", "w": "qesad", "e": "wrsdf", "r": "etdfg", "t": "ryfgh",
    "y": "tughj", "u": "yijhk", "i": "uojkl", "o": "ipkl", "p": "ol",
    "a": "qwsz", "s": "weadzx", "d": "ersfxc", "f": "rtdgcv", "g": "tyfhvb",
    "h": "yugjbn", "j": "uikhmn", "k": "iojlm", "l": "opk",
    "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn",
    "n": "bhjm", "m": "njk"
}

HIGH_RISK_CREDENTIAL_TERMS = [
    "logininfo", "login", "signin", "logon", "auth", "authenticate", "verification",
    "verify", "password", "passcode", "credential", "accountinfo", "account",
    "myaccount", "useraccount", "unfreeze", "suspended", "security-alert",
    "securityupdate", "recover", "recovery", "unlock", "unblock", "billing",
    "invoice", "kyc", "wallet", "claim", "bonus", "winner", "prize", "cpanel",
    "webmail", "securelogin", "banking", "supportdesk"
]

HIGH_ABUSE_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "work", "click", "link",
    "live", "stream", "bid", "loan", "date", "racing", "win", "men", "icu",
    "buzz", "monster", "fit", "surf", "site", "club", "online"
}


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def check_typosquatting(url: str):
    """
    Checks if domain name is a typosquatting / look-alike impersonation of known brands.
    Detects single/double character edits, keyboard adjacent misspellings, and homoglyphs.
    """
    raw_url = normalize_url(str(url).strip())
    parsed_url = urlparse(raw_url)
    hostname = (parsed_url.hostname or "").lower()
    
    if not hostname:
        return {"is_typosquat": False, "target_brand": None, "details": "None", "risk": "Safe"}

    # Extract primary domain token (excluding TLD and subdomains if applicable)
    parts = hostname.split(".")
    if len(parts) >= 2:
        domain_label = parts[-2]
    else:
        domain_label = hostname

    # Homoglyph normalization
    normalized_label = domain_label
    for k, v in HOMOGLYPH_MAP.items():
        normalized_label = normalized_label.replace(k, v)

    for brand, display_name in KNOWN_BRANDS.items():
        if domain_label == brand:
            return {
                "is_typosquat": False,
                "target_brand": display_name,
                "details": f"Legitimate brand match ({display_name})",
                "risk": "Safe"
            }

        # Check direct homoglyph replacement (e.g. g00gle, paypa1, micros0ft)
        if normalized_label == brand:
            return {
                "is_typosquat": True,
                "target_brand": display_name,
                "brand_keyword": brand,
                "distance": 1,
                "typo_type": "Visual Homoglyph Spoofing",
                "details": f"[!] Typosquatting impersonating '{display_name}' (Visual Homoglyph Spoofing)",
                "risk": "High"
            }

        dist_raw = levenshtein_distance(domain_label, brand)
        dist_norm = levenshtein_distance(normalized_label, brand)
        dist = min(dist_raw, dist_norm)

        # Flag if distance is 1 (or 2 for longer brand names >= 7 chars)
        if (dist == 1) or (dist == 2 and len(brand) >= 7):
            is_keyboard_typo = False
            if len(domain_label) == len(brand):
                diffs = [(domain_label[i], brand[i]) for i in range(len(brand)) if domain_label[i] != brand[i]]
                if len(diffs) == 1:
                    c1, c2 = diffs[0]
                    if c1 in KEYBOARD_ADJACENT.get(c2, "") or c2 in KEYBOARD_ADJACENT.get(c1, ""):
                        is_keyboard_typo = True

            typo_type = "Keyboard Neighbor Typo" if is_keyboard_typo else "Character Substitution/Typo"
            return {
                "is_typosquat": True,
                "target_brand": display_name,
                "brand_keyword": brand,
                "distance": dist,
                "typo_type": typo_type,
                "details": f"[!] Typosquatting impersonating '{display_name}' ({typo_type}, edit distance {dist})",
                "risk": "High"
            }

    return {
        "is_typosquat": False,
        "target_brand": None,
        "details": "No brand look-alike detected",
        "risk": "Safe"
    }


def evaluate_security_threat(url: str):
    """
    Comprehensive multi-vector threat intelligence and heuristic engine.
    Analyzes typosquatting, credential harvesting terms, deceptive subdomains,
    high-abuse TLDs, gibberish/DGA strings, and DNS reachability.
    """
    raw_url = normalize_url(str(url).strip())
    parsed_url = urlparse(raw_url)
    hostname = (parsed_url.hostname or "").lower()
    path = (parsed_url.path or "").lower()

    threat_reasons = []
    threat_score = 0
    is_critical_phishing = False

    # 1. Typosquatting Analysis
    typo_info = check_typosquatting(raw_url)
    if typo_info["is_typosquat"]:
        threat_reasons.append(f"Brand Impersonation / Typosquatting targeting '{typo_info['target_brand']}' ({typo_info['typo_type']})")
        threat_score += 80
        is_critical_phishing = True

    parts = hostname.split(".")
    tld = parts[-1] if len(parts) > 1 else ""
    domain_label = parts[-2] if len(parts) >= 2 else hostname
    subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""

    # Verified Whitelisted Brand / Legitimate Domain Check
    is_verified_legit = (domain_label in VERIFIED_LEGITIMATE_DOMAINS) and (tld in ["com", "org", "net", "edu", "gov", "io", "ai", "co", "uk", "in", "de"])

    if is_verified_legit:
        return {
            "is_threat": False,
            "is_critical": False,
            "threat_score": 0,
            "threat_reasons": [],
            "typosquat_info": typo_info,
            "is_verified_legit": True
        }

    # 2. Repetitive Character, Gibberish & DGA Domain Detection
    if re.match(r"^(.)\1{2,}$", domain_label):
        threat_reasons.append(f"Repetitive Single-Character Disposable Domain: '{domain_label}'")
        threat_score += 65
        is_critical_phishing = True
    elif len(domain_label) >= 4 and len(set(domain_label)) <= 2 and not domain_label.isdigit():
        threat_reasons.append(f"Abnormally Low Character Diversity / Gibberish Pattern: '{domain_label}'")
        threat_score += 50
        is_critical_phishing = True
    elif not is_pronounced_word(domain_label):
        threat_reasons.append(f"Unpronounceable DGA Consonant Cluster: '{domain_label}'")
        threat_score += 55
        is_critical_phishing = True

    # 3. Live DNS Existence Check (Non-existent / unregistered phantom domain)
    if hostname and not check_domain_dns(hostname):
        threat_reasons.append(f"Non-Existent / Dead Host (No active global DNS A/AAAA records found for '{hostname}')")
        threat_score += 65
        is_critical_phishing = True

    # 4. Credential Harvesting in Domain Name or Subdomain
    matched_domain_terms = []
    for term in HIGH_RISK_CREDENTIAL_TERMS:
        if term in domain_label:
            matched_domain_terms.append(term)
        elif subdomain and term in subdomain:
            matched_domain_terms.append(f"subdomain:{term}")

    if matched_domain_terms:
        threat_reasons.append(f"Credential Harvesting Pattern in Host: '{', '.join(matched_domain_terms)}'")
        threat_score += 55
        is_critical_phishing = True

    # 5. Deceptive / Dummy Subdomain Detection (e.g. ggg, xxx, aaa, temp)
    if subdomain and subdomain != "www":
        sub_tokens = subdomain.split(".")
        for sub in sub_tokens:
            if re.match(r"^(.)\1+$", sub) or sub in ["ggg", "xxx", "aaa", "zzz", "temp", "srv", "node"]:
                threat_reasons.append(f"Suspicious Dummy/Repetitive Subdomain detected: '{sub}'")
                threat_score += 40
                is_critical_phishing = True
            elif len(sub) == 1:
                threat_reasons.append(f"Suspicious Single-Letter Subdomain: '{sub}'")
                threat_score += 25

        # Brand spoofing inside subdomains (e.g. paypal.com.evil.com)
        for brand in KNOWN_BRANDS.keys():
            if brand in subdomain:
                threat_reasons.append(f"Brand name masquerading in subdomain: '{brand}'")
                threat_score += 60
                is_critical_phishing = True

    # 6. High Abuse / Phishing TLDs
    if tld in HIGH_ABUSE_TLDS:
        threat_reasons.append(f"High-Abuse Phishing TLD detected: '.{tld}'")
        threat_score += 35

    # 7. IP Address host detection
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname):
        threat_reasons.append("Raw IP Address used as host (bypassing DNS reputation)")
        threat_score += 50
        is_critical_phishing = True

    # 8. Unencrypted HTTP on sensitive credential terms
    if raw_url.startswith("http://") and (matched_domain_terms or any(w in path for w in ["login", "verify", "account", "bank"])):
        threat_reasons.append("Unencrypted HTTP protocol on credential/authentication endpoint")
        threat_score += 25

    # 9. @ symbol or double slash redirect
    if "@" in raw_url:
        threat_reasons.append("URL contains '@' symbol (host obfuscation trick)")
        threat_score += 40
    if "//" in path:
        threat_reasons.append("Path contains double slash redirection ('//')")
        threat_score += 35

    is_threat = is_critical_phishing or (threat_score >= 35)
    normalized_score = min(100, max(threat_score, 99 if is_critical_phishing else threat_score))

    return {
        "is_threat": is_threat,
        "is_critical": is_critical_phishing,
        "threat_score": normalized_score,
        "threat_reasons": threat_reasons,
        "typosquat_info": typo_info,
        "is_verified_legit": is_verified_legit
    }


def get_feature_details(url: str):
    """
    Returns structured, human-readable breakdown of extracted features
    with individual risk indicators, including threat intelligence analysis.
    """
    raw_url = str(url).strip()
    f = extract_features(raw_url)
    threat_intel = evaluate_security_threat(raw_url)
    typo_info = threat_intel["typosquat_info"]
    
    threat_summary = "Safe (Verified Legitimate Domain)" if threat_intel.get("is_verified_legit") else ("Safe (No threat indicators)" if not threat_intel["is_threat"] else f"🚨 Threat Detected ({len(threat_intel['threat_reasons'])} indicators)")
    
    details = {
        "Threat Intelligence & Heuristics": {
            "value": threat_summary,
            "risk": "High" if threat_intel["is_threat"] else "Safe"
        },
        "Typosquatting & Brand Spoofing": {
            "value": typo_info["details"],
            "risk": typo_info["risk"]
        },
        "URL Length": {"value": f[0], "risk": "High" if f[0] > 75 else ("Medium" if f[0] > 50 else "Normal")},
        "Domain Length": {"value": f[1], "risk": "High" if f[1] > 30 else "Normal"},
        "Dot Count": {"value": f[2], "risk": "High" if f[2] > 3 else "Normal"},
        "Hyphen Count": {"value": f[3], "risk": "High" if f[3] > 2 else "Normal"},
        "Special Characters (@?=&%)": {"value": f[4], "risk": "High" if f[4] > 3 else "Normal"},
        "@ Symbol Detected": {"value": "Yes" if f[5] == 1 else "No", "risk": "High" if f[5] == 1 else "Safe"},
        "SSL/HTTPS Protocol": {"value": "HTTPS Secure" if f[6] == 1 else "HTTP Unencrypted", "risk": "Safe" if f[6] == 1 else "High"},
        "Numeric Digits Count": {"value": f[7], "risk": "High" if f[7] > 5 else "Normal"},
        "Suspicious Phishing Keywords": {"value": f"{f[8]} detected", "risk": "High" if f[8] > 0 else "Safe"},
        "Subdomain Count": {"value": f[9], "risk": "High" if f[9] > 2 else "Normal"},
        "IP Address Used As Host": {"value": "Yes (Suspicious)" if f[10] == 1 else "No (Domain Name)", "risk": "High" if f[10] == 1 else "Safe"},
        "URL Shortener Service": {"value": "Yes (Shortened)" if f[11] == 1 else "No", "risk": "Medium" if f[11] == 1 else "Safe"},
        "Path Redirection (//)": {"value": "Detected" if f[12] == 1 else "None", "risk": "High" if f[12] == 1 else "Safe"},
        "Domain Hyphen Separator": {"value": "Detected" if f[13] == 1 else "None", "risk": "Medium" if f[13] == 1 else "Safe"},
        "URL Entropy (Randomness)": {"value": f"{f[14]} bits", "risk": "High" if f[14] > 4.5 else "Normal"}
    }
    return details


if __name__ == "__main__":
    test_url = input("Enter URL to test: ")
    print("\nFeature Vector:", extract_features(test_url))
    print("\nThreat Intel:", evaluate_security_threat(test_url))
    print("\nDetailed Analysis:")
    for k, v in get_feature_details(test_url).items():
        print(f" - {k}: {v['value']} [{v['risk']}]")
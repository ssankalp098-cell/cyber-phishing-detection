import csv
import random

def build_massive_dataset():
    # 1. Base Legitimate Root Domains & Patterns
    legit_domains = [
        # Search & Portals
        "google.com", "bing.com", "duckduckgo.com", "yahoo.com", "baidu.com", "yandex.com", "ecosia.org", "ask.com", "aol.com", "search.brave.com",
        
        # Tech & SaaS Giants
        "microsoft.com", "apple.com", "amazon.com", "meta.com", "github.com", "gitlab.com", "bitbucket.org", "aws.amazon.com", "azure.microsoft.com",
        "cloud.google.com", "digitalocean.com", "linode.com", "cloudflare.com", "vercel.com", "netlify.com", "heroku.com", "oracle.com", "ibm.com",
        "intel.com", "amd.com", "nvidia.com", "cisco.com", "salesforce.com", "adobe.com", "openai.com", "huggingface.co", "kaggle.com",
        "stackoverflow.com", "stackexchange.com", "python.org", "nodejs.org", "react.dev", "angular.io", "vuejs.org", "getbootstrap.com",
        "tailwindcss.com", "developer.mozilla.org", "w3schools.com", "medium.com", "dev.to", "hashnode.com", "substack.com", "wordpress.org",
        "atlassian.com", "jira.com", "notion.so", "figma.com", "canva.com", "slack.com", "zoom.us", "dropbox.com", "box.com", "trello.com",
        "asana.com", "monday.com", "gitlab.io", "github.io", "sourceforge.net", "npm.js", "pypi.org", "docker.com", "kubernetes.io",

        # Banking & Fintech
        "chase.com", "bankofamerica.com", "wellsfargo.com", "citigroup.com", "hsbc.com", "barclays.co.uk", "standardchartered.com",
        "capitalone.com", "americanexpress.com", "discover.com", "visa.com", "mastercard.com", "paypal.com", "stripe.com", "square.com",
        "wise.com", "revolut.com", "robinhood.com", "fidelity.com", "vanguard.com", "schwab.com", "tdbank.com", "usbank.com", "pnc.com",
        "bmo.com", "santander.com", "db.com", "ubs.com", "goldmansachs.com", "morganstanley.com", "coinbase.com", "binance.com", "kraken.com",
        "gemini.com", "metamask.io", "ally.com", "chime.com", "sofi.com", "klarna.com", "affirm.com",

        # E-Commerce & Retail
        "ebay.com", "walmart.com", "target.com", "aliexpress.com", "alibaba.com", "etsy.com", "bestbuy.com", "homedepot.com", "lowes.com",
        "costco.com", "ikea.com", "asos.com", "zalando.com", "rakuten.com", "shopify.com", "wayfair.com", "sephora.com", "nike.com",
        "adidas.com", "zara.com", "hm.com", "gap.com", "macys.com", "nordstrom.com", "newegg.com", "chewy.com", "overstock.com",

        # Social & Entertainment
        "youtube.com", "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com", "reddit.com", "tiktok.com", "pinterest.com",
        "snapchat.com", "tumblr.com", "quora.com", "discord.com", "telegram.org", "whatsapp.com", "twitch.tv", "mastodon.social",
        "bsky.app", "threads.net", "netflix.com", "spotify.com", "hulu.com", "disneyplus.com", "max.com", "primevideo.com", "steampowered.com",
        "epicgames.com", "playstation.com", "xbox.com", "nintendo.com", "roblox.com",

        # News & Encyclopedias
        "wikipedia.org", "britannica.com", "bbc.com", "cnn.com", "nytimes.com", "reuters.com", "bloomberg.com", "theguardian.com",
        "forbes.com", "wsj.com", "washingtonpost.com", "cnbc.com", "techcrunch.com", "wired.com", "theverge.com", "arstechnica.com",
        "nature.com", "sciencedirect.com", "nih.gov",

        # Education & Gov
        "harvard.edu", "mit.edu", "stanford.edu", "ox.ac.uk", "cam.ac.uk", "berkeley.edu", "columbia.edu", "princeton.edu", "yale.edu",
        "caltech.edu", "cornell.edu", "ucla.edu", "coursera.org", "edx.org", "udemy.com", "khanacademy.org", "usa.gov", "gov.uk",
        "europa.eu", "who.int", "un.org", "cdc.gov", "nasa.gov", "irs.gov", "dhl.com", "fedex.com", "usps.com", "ups.com", "booking.com", "airbnb.com"
    ]

    legitimate_paths = [
        "",
        "/about",
        "/contact-us",
        "/help/faq",
        "/docs/api/v2/endpoints",
        "/products/category/item?id=84732&ref=banner",
        "/search?q=machine+learning+security+whitepaper&hl=en",
        "/blog/2026/05/security-updates-and-release-notes",
        "/user/profile/settings/notifications",
        "/articles/cybersecurity-best-practices.html",
        "/download/stable/release-linux-x86_64.tar.gz",
        "/support/kb/index.php?article_id=9832",
        "/en-us/windows/security-center/protection-guide",
        "/courses/computer-science/intro-to-algorithms"
    ]

    legitimate_urls = []
    for d in legit_domains:
        # Standard https
        legitimate_urls.append(f"https://www.{d}")
        legitimate_urls.append(f"https://{d}")
        # Bare domain
        legitimate_urls.append(f"{d}")
        # Standard http
        legitimate_urls.append(f"http://www.{d}")
        # With path
        path = random.choice(legitimate_paths)
        if path:
            legitimate_urls.append(f"https://www.{d}{path}")
            legitimate_urls.append(f"https://{d}{path}")
            legitimate_urls.append(f"http://{d}{path}")

    # 2. Phishing URLs Generation
    phish_brands = [
        "paypal", "chase", "wellsfargo", "bankofamerica", "citibank", "hsbc", "barclays", "capitalone", "revolut", "wise", "appleid",
        "microsoft", "office365", "google-drive", "google-docs", "netflix", "amazon-prime", "metamask", "binance", "coinbase", "ledger",
        "trustwallet", "dhl-tracking", "fedex-parcel", "usps-redelivery", "facebook-security", "instagram-badge", "whatsapp-web",
        "discord-nitro", "steam-gift", "tax-refund-gov", "covid-relief-fund", "walmart-giftcard"
    ]

    phish_suspicious_tlds = [
        ".xyz", ".top", ".club", ".online", ".site", ".info", ".cc", ".tk", ".ml", ".ga", ".cf", ".gq", ".biz", ".work", ".live", ".link"
    ]

    phish_keywords = [
        "login", "verify-account", "security-update", "confirm-identity", "password-reset", "unfreeze-account", "claim-bonus", "auth-session",
        "billing-update", "urgent-notice", "restore-access", "wallet-connect", "kyc-verification", "free-winner-prize", "account-suspended"
    ]

    phishing_urls = []

    # Permutations of phishing domains (using both http, https, and bare domains)
    for brand in phish_brands:
        for _ in range(5):
            tld = random.choice(phish_suspicious_tlds)
            kw = random.choice(phish_keywords)
            proto = random.choice(["http://", "https://", ""])
            
            # Pattern A: brand-kw.tld/path
            url_a = f"{proto}{brand}-{kw}{tld}/login.php?ref=security_alert"
            phishing_urls.append(url_a)
            
            # Pattern B: subdomain spoofing (e.g. www.paypal.com.suspicious.xyz/auth)
            proto_b = random.choice(["http://", "https://"])
            url_b = f"{proto_b}www.{brand}.com.{kw}{tld}/auth"
            phishing_urls.append(url_b)

            # Pattern C: double hyphen prefix/suffix (e.g. secure-login-brand-verify.site)
            url_c = f"{proto}secure-{brand}-login-verify{tld}/index.html?token=9284732"
            phishing_urls.append(url_c)

    # IP-based Phishing Hosts
    ip_samples = [
        "192.168.1.100", "10.0.0.1", "172.16.254.1", "198.51.100.42", "203.0.113.195",
        "185.220.101.5", "194.26.29.112", "91.240.118.16", "45.142.214.88", "103.145.13.20",
        "149.202.160.1", "51.15.22.8", "162.243.10.15", "89.248.167.3", "185.190.140.5"
    ]
    for ip in ip_samples:
        for brand in ["paypal", "chase", "netflix", "microsoft", "bank"]:
            proto = random.choice(["http://", "https://", ""])
            phishing_urls.append(f"{proto}{ip}/{brand}/login.php?verify=1")

    # Shortener Services Phishing
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "bit.do", "buff.ly", "adf.ly"]
    for s in shorteners:
        for target in ["chase-verify", "paypal-auth", "free-bitcoin-claim", "apple-id-locked", "amazon-bonus-winner"]:
            proto = random.choice(["http://", "https://"])
            phishing_urls.append(f"{proto}{s}/{target}-2026")

    # Remove duplicates
    legitimate_urls = list(set(legitimate_urls))
    phishing_urls = list(set(phishing_urls))

    rows = []
    for u in legitimate_urls:
        rows.append({"url": u.strip(), "label": 0})
    for u in phishing_urls:
        rows.append({"url": u.strip(), "label": 1})

    random.seed(42)
    random.shuffle(rows)

    with open("dataset/phishing_dataset.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "label"])
        writer.writeheader()
        writer.writerows(rows)

    with open("dataset/phising_dataset.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "label"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Successfully generated MASSIVE balanced dataset with {len(rows)} samples!")
    print(f"    - Legitimate URLs : {len(legitimate_urls)}")
    print(f"    - Phishing URLs   : {len(phishing_urls)}")

if __name__ == "__main__":
    build_massive_dataset()

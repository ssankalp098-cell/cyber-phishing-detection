from urllib.parse import urlparse
import re


def extract_features(url):
    features = []

    # 1. URL Length
    features.append(len(url))

    # 2. Number of dots
    features.append(url.count("."))

    # 3. Number of hyphens
    features.append(url.count("-"))

    # 4. Number of special characters
    features.append(len(re.findall(r"[@?=&%]", url)))

    # 5. HTTPS check
    features.append(1 if url.startswith("https") else 0)

    # 6. Number of digits
    features.append(sum(c.isdigit() for c in url))

    # 7. Suspicious words
    suspicious_words = [
        "login",
        "verify",
        "account",
        "secure",
        "update",
        "password",
        "bank",
        "confirm",
        "free",
        "winner"
    ]

    features.append(
        1 if any(word in url.lower() for word in suspicious_words) else 0
    )

    # 8. Number of subdomains
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or ""
    features.append(max(0, hostname.count(".") - 1))

    return features


def get_feature_details(url):
    features = extract_features(url)

    return {
        "URL Length": features[0],
        "Number of Dots": features[1],
        "Number of Hyphens": features[2],
        "Special Characters": features[3],
        "HTTPS": "Yes" if features[4] == 1 else "No",
        "Number of Digits": features[5],
        "Suspicious Words": "Yes" if features[6] == 1 else "No",
        "Number of Subdomains": features[7]
    }


if __name__ == "__main__":

    url = input("URL: ")

    print("\nExtracted Features:")
    print(extract_features(url))

    print("\nFeature Details:")

    details = get_feature_details(url)

    for name, value in details.items():
        print(f"{name}: {value}")
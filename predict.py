import joblib
from feature_extraction import extract_features


# 1. Load trained model
model = joblib.load("phishing_model.pkl")

print("Phishing Detection Model Loaded Successfully!")


# 2. Take URL from user
url = input("\nEnter URL: ")


# 3. Extract features
features = extract_features(url)


# 4. Predict
prediction = model.predict([features])[0]


# 5. Display result
print("\n" + "=" * 40)

if prediction == 1:
    print("⚠️ PHISHING URL DETECTED!")
else:
    print("✅ LEGITIMATE URL")

print("=" * 40)
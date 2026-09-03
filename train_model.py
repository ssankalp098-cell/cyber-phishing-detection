import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

from feature_extraction import extract_features


# 1. Load dataset
data = pd.read_csv("dataset/phising_dataset.csv")

print("Dataset loaded successfully!")
print("Total URLs:", len(data))


# 2. Extract features from URLs
X = []
y = []

for _, row in data.iterrows():
    url = row["url"]
    label = row["label"]

    features = extract_features(url)

    X.append(features)
    y.append(label)


# 3. Convert to DataFrame
X = pd.DataFrame(X)
y = pd.Series(y)


# 4. Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)


# 5. Create ML model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)


# 6. Train model
model.fit(X_train, y_train)

print("\nModel training completed!")


# 7. Test model
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("\nModel Accuracy:", accuracy)
print("\nClassification Report:")
print(classification_report(y_test, y_pred))


# 8. Save trained model
joblib.dump(model, "phishing_model.pkl")

print("\nModel saved successfully!")
print("File created: phishing_model.pkl")
from flask import Flask, render_template, request
import joblib

from feature_extraction import extract_features, get_feature_details

app = Flask(__name__)

# Load trained ML model
model = joblib.load("phishing_model.pkl")


@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    result_class = ""
    url = ""
    confidence = None
    feature_details = None

    if request.method == "POST":

        # Get URL
        url = request.form["url"].strip()

        # Extract features
        features = extract_features(url)

        # Prediction
        prediction = model.predict([features])[0]

        # Prediction confidence
        probabilities = model.predict_proba([features])[0]
        confidence = round(max(probabilities) * 100, 2)

        # Feature analysis
        feature_details = get_feature_details(url)

        # Result
        if prediction == 1:
            result = "⚠️ PHISHING URL DETECTED!"
            result_class = "danger"
        else:
            result = "✅ LEGITIMATE URL"
            result_class = "safe"

    return render_template(
        "index.html",
        result=result,
        result_class=result_class,
        url=url,
        confidence=confidence,
        feature_details=feature_details
    )


if __name__ == "__main__":
    app.run(debug=True)
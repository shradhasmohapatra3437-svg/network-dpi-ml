from flask import Flask, request, jsonify
import pandas as pd
import joblib

app = Flask(__name__)

print("Loading ML model...")

# Load trained model + feature columns
model = joblib.load("ids_model.pkl")
columns = joblib.load("columns.pkl")

# =========================
# PREDICTION FUNCTION
# =========================
def predict_intrusion(sample):
    df = pd.DataFrame([sample])

    # Convert categorical → numeric
    df = pd.get_dummies(df)

    # Align with training columns (CRITICAL)
    df = df.reindex(columns=columns, fill_value=0)

    pred = model.predict(df)[0]

    return "ATTACK" if pred == 1 else "NORMAL"

# =========================
# TEST ROUTE
# =========================
@app.route('/')
def home():
    return "IDS API Running 🚀"

# =========================
# PREDICTION ROUTE
# =========================
@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    result = predict_intrusion(data)
    return jsonify({"result": result})

# =========================
# START SERVER
# =========================
if __name__ == "__main__":
    print("Starting IDS API...")
    app.run(host="127.0.0.1", port=5000, debug=True)
    
    
    

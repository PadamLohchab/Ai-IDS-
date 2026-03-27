
import streamlit as st
import pandas as pd
import joblib

st.set_page_config(page_title="AI IDS Dashboard", layout="wide")

st.title("🚨 AI-Powered Intrusion Detection System")

model_path = "../models/model.joblib"

@st.cache_resource
def load_model():
    return joblib.load(model_path)

model = load_model()
st.title("AI-based Intrusion Detection System")

# Upload CSV file
uploaded_file = st.file_uploader("Upload a CSV file for prediction", type=["csv"])

if uploaded_file is not None:
    # Read uploaded CSV
    df = pd.read_csv(uploaded_file)
    st.write("### Uploaded Data Preview", df.head())

    # Drop label column if present
    # Ensure the same features used during training
required_features = ["bytes_in", "bytes_out", "duration", "packets"]

# Check if all required features exist in uploaded data
missing = [f for f in required_features if f not in df.columns]
if missing:
    st.error(f"Uploaded file is missing required features: {missing}")
else:
    X = df[required_features]


    # Load trained model
    model = load_model()

    # Predict
    predictions = model.predict(X)

    # Show predictions
    df["Prediction"] = predictions
    st.write("### Predictions", df)

    # Show counts
    st.write("### Prediction Summary")
    st.bar_chart(df["Prediction"].value_counts())

st.sidebar.header("Input Network Features")
duration = st.sidebar.number_input("Duration", min_value=0.0, max_value=100.0, value=1.0)
bytes_in = st.sidebar.number_input("Bytes In", min_value=0, max_value=10000, value=500)
bytes_out = st.sidebar.number_input("Bytes Out", min_value=0, max_value=10000, value=600)
packets = st.sidebar.number_input("Packets", min_value=1, max_value=200, value=10)
protocol = st.sidebar.selectbox("Protocol", [0, 1])

if st.sidebar.button("Detect"):
    df = pd.DataFrame([{
        "duration": duration,
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "packets": packets,
        "protocol": protocol
    }])
    pred = model.predict(df)[0]
    label = "⚠️ Attack" if pred == 1 else "✅ Benign"
    st.metric("Prediction", label)

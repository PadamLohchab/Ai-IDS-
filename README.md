# 🚀 AI-IDS Dashboard

## 📌 Overview

AI-IDS Dashboard is a Machine Learning-based Intrusion Detection System that monitors network traffic and detects suspicious activities in real time.

It combines **network analysis, active scanning, and ML-based classification** into a single interactive dashboard.

---

## 🔧 Features

* 📡 Real-time network traffic monitoring (Scapy)
* 🔍 Active port scanning (multi-threaded)
* 📊 CSV-based offline analysis
* ⚠️ Attack detection with probability score
* 🧠 ML-based classification (Random Forest)
* 📈 Traffic analytics & visualization
* 📜 Alert history tracking

---

## 🛠 Tech Stack

* Python
* Streamlit
* Scikit-learn
* Pandas, NumPy
* Scapy (packet sniffing)
* Socket Programming

---

## 📂 Project Structure

```
AI-IDS-Dashboard/
│── app.py
│── train.py
│── model.joblib
│── sample_data.csv
│── requirements.txt
│── README.md
```

---

## ▶️ Run the Project

### 1. Install dependencies

pip install -r requirements.txt

### 2. Run dashboard

streamlit run app.py

---

## 🧠 Train the Model

python train.py --data train.csv --out model.joblib

Dataset must contain a **label column**:

* 0 → Normal
* 1 → Attack

---

## 📊 How It Works

1. Capture network traffic or upload dataset
2. Extract features (bytes, packets, protocol)
3. Convert protocol to numeric format
4. Apply ML model
5. Generate alerts with probability score

---

## 📷 Screenshots
## 📷 Screenshots

### 🔹 Dashboard Interface
<img width="1718" height="998" alt="Screenshot_2026-03-27_12_59_13" src="https://github.com/user-attachments/assets/12712dd3-8bcb-4563-9489-fd4c71fecd63" />



### 🔹 Attack Detection Alert
<img width="1718" height="998" alt="Screenshot_2026-03-27_12_56_33" src="https://github.com/user-attachments/assets/101c1ec6-d624-4527-b2c2-ccfdb5ab6781" />



### 🔹 Active Scan Results
<img width="1718" height="998" alt="Screenshot_2026-03-27_12_56_08" src="https://github.com/user-attachments/assets/e47ec585-67c0-41c5-ba61-e296e44e6141" />




---

## 🎯 Future Improvements

* 🔐 Email/SMS alert integration
* 🌐 Deployment (Streamlit Cloud)
* 🤖 Deep learning-based IDS
* 🔗 Integration with SIEM tools

---

## 👨‍💻 Author

Padam Lohchab
Cybersecurity & Networking Enthusiast

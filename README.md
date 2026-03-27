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


### 🔹 Dashboard Interface

<img width="1718" height="998" alt="Dashboard" src="https://github.com/user-attachments/assets/b5955bc5-2944-4b2e-97c8-ca706b22a42c" />



### 🔹 Attack Detection Alert
<img width="1718" height="998" alt="alert" src="https://github.com/user-attachments/assets/33d8699a-0360-4d9b-97c2-d6130b68c99e" />




### 🔹 Active Scan Results
<img width="1718" height="998" alt="scan" src="https://github.com/user-attachments/assets/431a49d1-8e28-4d19-97bb-9e368b9ccbd9" />






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

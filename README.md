# 🛡️ DDoS Detector: Intelligent Multi-Class DDoS Attack Classification

> An AI-powered intrusion detection system designed to detect and classify various DDoS attack types (e.g., SYN flood, UDP-Lag, DrDoS) using machine learning and anomaly detection techniques. Supports both training and prediction pipelines, including a fully installable Linux-compatible CLI tool.

---

## 📦 Features

- ✅ Multi-class classification of DDoS attacks (SYN, UDP, DrDoS, NetBIOS, etc.)
- ✅ Isolation Forest-based anomaly detection integration
- ✅ Detailed per-class explanations and severity levels
- ✅ CLI-ready with Linux install support
- ✅ Auto-generates attack/benign sample files
- ✅ Supports custom CSV inputs for predictions
- ✅ Model artifacts (scaler, encoder, etc.) are stored for consistent use


## 🧠 Attack Types Detected

| Attack Type | Description |
|-------------|-------------|
| **SYN**     | Exploits the TCP handshake by sending multiple SYN packets and never completing the handshake, leading to half-open connections. |
| **UDP**     | Sends large volumes of UDP packets to random ports to exhaust system resources and network bandwidth. |
| **DrDoS**   | Distributed reflection attacks using services like DNS, NTP to amplify traffic toward the victim. |
| **TFTP**    | Uses insecure file transfer requests to reflect and amplify traffic. |
| **NetBIOS** | Exploits the NetBIOS protocol (port 137) to reflect and flood traffic from spoofed sources. |
| **BENIGN**  | Normal, legitimate network traffic with no evidence of DDoS behavior. |


## 🗂️ Folder Structure
ddos_detector/
├── model/ # Trained models and confusion matrix
│ ├── model.pkl
│ ├── scaler.pkl
│ ├── isolation_forest.pkl
│ ├── feature_names.pkl
│ ├── class_labels.pkl
│ └── confusion_matrix.png
├── samples/ # Auto-generated random benign and attack sample CSVs
│ ├── BENIGN.csv
│ ├── ATTACK.csv
│ └── ATTACKNOLABEL.csv
├── train_multiclass_grouped.py # Training script
├── predictor.py # Prediction script with CLI support
├── cli.py # CLI entry point for Linux users
├── requirements.txt # Dependencies
├── setup.py # Package setup
└── README.md

---

## 🔧 Installation

### 🔁 Requirements

- Python 3.8+
- pip
- Git (for cloning repo)
- Linux / Windows / macOS

### ✅ Clone This Repository
git clone https://github.com/DarkHorse06-dev/ddos_detector.git
cd ddos_detector

🛠️ Install Dependencies
pip install -r requirements.txt

🚀 Usage
🔍 Train a New Model
python model/train_multiclass_grouped.py
Uses sampled subsets of CIC-DDoS2019 dataset

Balances classes (up to 10000 samples each)

Trains using XGBoost + Isolation Forest

Generates 3 sample CSVs: BENIGN.csv, ATTACK.csv, and ATTACKNOLABEL.csv

📊 Run Predictions
python predictor.py samples/ATTACK.csv
Outputs:

Class probabilities

Prediction confidence

Attack type and severity

Explanation for the attack

Saves result to prediction_report.txt

🖥️ CLI Tool (Linux Installation)
🧪 Install as a CLI package (Linux/macOS)

pip install .
Now you can use:
ddos-predict --file path/to/your/test.csv
CLI Help

ddos-predict --help
🧪 Sample Output
📥 Predicting file: samples/ATTACK.csv
🔎 Usable rows after cleaning: 120

📄 Prediction Report
Status       : ATTACK
Confidence   : 94.20%
Attack Type  : SYN
Severity     : High
Explanation  : SYN floods exploit the TCP handshake by sending numerous SYN requests without completing the handshake. These half-open connections deplete server memory, making the service unavailable...

📊 Class Probabilities:
- BENIGN    : 1.12%
- SYN       : 94.20%
- UDP       : 2.00%
- DrDoS     : 1.50%
- NetBIOS   : 0.91%

📁 Sample Data Expectations
CSV format (e.g., exported from CIC-DDoS2019 or equivalent)

Numeric columns only (IP, Timestamp, and other metadata are auto-removed)

Features must match training time features

Optional: model will automatically flag issues like missing anomaly_score or SimillarHTTP

🧠 Model Architecture
XGBoost for robust multi-class classification

Isolation Forest adds anomaly score as an additional feature

Standard Scaler for normalization

Weighted sampling to handle imbalanced classes

🛡️ Security & Ethical Use
This tool is meant for research and defensive security purposes only. It must not be used to simulate or perform attacks in unauthorized environments. Always follow ethical hacking and cybersecurity policies of your institution.

🧩 TODOs / Future Work
 REST API deployment (Flask/FastAPI)

 Docker containerization

 Live packet sniffing support

 Model versioning support

📜 License
This project is licensed under the MIT License. See LICENSE for details.

👨‍💻 Author
DarkHorse06-dev

GitHub: @DarkHorse06-dev

Email: gbenlemuiz@gmail.com

Project: https://github.com/DarkHorse06-dev/ddos_detector


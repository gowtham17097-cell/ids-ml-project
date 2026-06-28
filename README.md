<div align="center">

# 🛡️ Intrusion Detection System with Machine Learning

**Real-time network threat detection powered by Random Forest**

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Scikit-learn](https://img.shields.io/badge/Scikit--learn-1.3+-orange?style=flat-square&logo=scikit-learn)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-red?style=flat-square&logo=streamlit)
![Scapy](https://img.shields.io/badge/Scapy-2.5+-green?style=flat-square)
![Accuracy](https://img.shields.io/badge/Accuracy-99.9%25-brightgreen?style=flat-square)

</div>

---

## 📌 Overview

A complete, end-to-end Intrusion Detection System that captures live network packets, extracts flow-based features in real-time, classifies traffic using a trained Random Forest model, and displays results on a dark-themed SOC dashboard — all built from scratch.

Trained on the **NSL-KDD** dataset (125,973 samples, 41 features), achieving **99.9% accuracy** in binary classification (normal vs. attack).

---

## ✨ Features

| Feature | Details |
|---|---|
| 🤖 **ML Model** | Random Forest — 100 estimators, 122 features after one-hot encoding |
| 📡 **Live Capture** | Scapy sniffing across all 9 network interfaces simultaneously |
| 🔄 **Flow Tracking** | Groups packets into connections, tracks 2-sec and 100-conn rolling windows |
| 🧮 **Feature Engine** | 28 of 41 NSL-KDD features computed live (Basic + Traffic groups) |
| ⚡ **Attack Types** | Detects portsweep, probe, r2l, DoS patterns |
| 🖥️ **SOC Dashboard** | Live alert feed, ACK system, threat meter, top IPs, uptime counter |
| 🎯 **Accuracy** | 99.9% on NSL-KDD test set — 22 wrong out of 25,195 samples |

---

## 📊 Model Comparison

| Model | Accuracy | Precision | Recall | F1 Score | Train Time |
|---|---|---|---|---|---|
| ✅ **Random Forest** | **99.91%** | **99.88%** | **99.96%** | **99.92%** | **2.24s** |
| Decision Tree | 99.81% | 99.86% | 99.78% | 99.82% | 1.54s |
| K-Nearest Neighbors | 99.66% | 99.76% | 99.60% | 99.68% | 0.14s |
| Logistic Regression | 95.39% | 95.74% | 95.63% | 95.68% | 30.91s |

> **Winner: Random Forest** — best across all metrics, fast inference, interpretable via feature importance.

---

## 🗂️ Project Structure

```
ids-ml-project/
│
├── data/
│   ├── datasets/              # NSL-KDD CSV files (not included — see Setup)
│   ├── processed/             # Cleaned, one-hot encoded features.csv
│   └── raw/                   # Optional: raw .pcap captures
│
├── notebooks/
│   ├── 01_data_exploration.ipynb
│   ├── 02_model_training.ipynb
│   └── 03_model_comparison.ipynb
│
├── src/
│   ├── capture/
│   │   └── packet_capture.py      # Scapy multi-interface live sniffer
│   ├── preprocessing/
│   │   ├── flow_tracker.py        # Core flow engine + rolling window features
│   │   ├── feature_mapper.py      # Flow dict → 122-column model input
│   │   └── service_lookup.py      # Port → NSL-KDD service name mapping
│   ├── models/
│   │   └── saved/                 # rf_model.pkl (generated after training)
│   ├── detection/
│   │   └── realtime_detector.py   # Loads model, runs predictions
│   └── alerts/
│       └── alert_manager.py       # Logs to logs/alerts.csv
│
├── dashboard/
│   └── app.py                     # Streamlit SOC dashboard (HTML/JS embedded)
│
├── logs/
│   └── alerts.csv                 # Generated at runtime
│
├── requirements.txt
├── .gitignore
└── README.md
```

---

## ⚙️ Setup

### 1. Clone and install

```bash
git clone https://github.com/YOUR_USERNAME/ids-ml-project.git
cd ids-ml-project
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

### 2. Download the dataset

Download **KDDTrain+.csv** and **KDDTest+.csv** from:
- Kaggle: https://www.kaggle.com/datasets/hassan06/nslkdd
- GitHub mirror: https://github.com/jmnwong/NSL-KDD-Dataset

Place both files in `data/datasets/`.

### 3. Train the model

Open and run all cells in order:

```
notebooks/01_data_exploration.ipynb   → explore + clean data
notebooks/02_model_training.ipynb     → train + save rf_model.pkl
notebooks/03_model_comparison.ipynb   → compare all models
```

### 4. Run live detection

> Requires **Administrator** terminal + **Npcap** installed (Windows)

```bash
python -m src.capture.packet_capture
```

### 5. Run the dashboard

In a separate terminal:

```bash
streamlit run dashboard/app.py
```

Open `http://localhost:8501`

---

## 🔬 How It Works

```
Live Packets → Flow Tracker → Feature Mapper → Random Forest → Alert Manager
   (Scapy)    (group by 5-tuple)  (122 columns)   (predict)     (log + display)
                    ↓
             Rolling Windows
          2-sec: count, error rates
          100-conn: dst_host_* rates
```

### Feature Groups

| Group | Features | Status |
|---|---|---|
| Basic (9) | duration, src_bytes, dst_bytes, flag, protocol, service... | ✅ Fully computed |
| Traffic (19) | count, serror_rate, same_srv_rate, dst_host_count... | ✅ Fully computed |
| Content (13) | logged_in, num_failed_logins, root_shell... | ⚠️ Approximated / defaulted |

> **Documented limitation:** Content features require deep payload inspection (FTP/Telnet session parsing). `logged_in` is approximated from TCP flag (SF = established connection).

---

## 🖥️ Dashboard Features

- **5 KPI cards** — total flows, threats, clean traffic, avg confidence, uptime
- **Threat meter** — live bar showing % of traffic flagged
- **Traffic timeline** — area chart, normal vs attack per minute
- **Connection rate** — packets/min spike detection
- **Top attacking IPs** — with local/external flag
- **Targeted services** — most probed ports
- **Attack classification** — portsweep / probe / r2l
- **Live alert feed** — timestamped, color-coded, with severity badges
- **ACK system** — mark alerts as reviewed, tracks false positive rate
- **Auto-refresh** — every 5 seconds

---

## 🛠️ Tech Stack

- **Python 3.10+**
- **Scikit-learn** — Random Forest, model evaluation
- **Scapy** — live packet capture and parsing
- **Pandas / NumPy** — data processing
- **Streamlit** — dashboard server
- **Chart.js** — live charts in dashboard
- **NSL-KDD** — benchmark dataset

---

## ⚠️ Important Notes

- Run packet capture as **Administrator** (required for raw socket access on Windows)
- Only test port scans against **your own machine** (`127.0.0.1` or your LAN IP)
- Never capture traffic on networks you don't own or have permission to monitor
- The model was trained on NSL-KDD (2009 lab data) — real-world accuracy will vary

---

## 👤 Author

**Gowtham** — 2nd year CS student  
Built as a portfolio project covering ML, networking, and cybersecurity.

---

<div align="center">
<sub>IDS-ML-PROJECT · NSL-KDD · Random Forest · 99.9% accuracy</sub>
</div>

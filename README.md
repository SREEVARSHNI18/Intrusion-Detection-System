# Intrusion Detection System (IDS)

This project develops an **Intrusion Detection System (IDS)** using the **KDD dataset** to classify network traffic as normal or malicious. It employs **Random Forest**, **Gradient Boosting**, **Decision Tree**, and **Naive Bayes** models, achieving high accuracy and performance. An interactive **Streamlit web app** allows real-time predictions based on user input.

---

## 📊 Model Performance

| Model              | Precision | Accuracy  | F1 Score  | Recall    |
|--------------------|-----------|-----------|-----------|-----------|
| **Naive Bayes**    | 0.991412  | 0.856766  | 0.884911  | 0.856766  |
| **Decision Tree**  | 0.999177  | 0.986438  | 0.981539  | 0.986438  |
| **Random Forest**  | 0.999177  | 0.999246  | 0.999188  | 0.999246  |
| **Gradient Boosting** | 0.999736 | 0.999733 | 0.999729 | 0.999736 |

---

## 🛠️ Features

- **Preprocessing**: Removed redundant columns, standardized data.
- **Models**: Offers Random Forest, Gradient Boosting, Decision Tree, Naive Bayes.
- **Streamlit UI**: Input data, select models, and get predictions in real-time.

---

## 🚀 How to Run

1. **Clone the repository**:
   ```bash
   git clone https://github.com/SREEVARSHNI18/Intrusion-Detection-System.git
2.**Install dependencies:**:
  ```bash
  pip install -r requirements.txt


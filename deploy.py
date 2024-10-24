import streamlit as st
import joblib
import numpy as np
from sklearn.preprocessing import LabelEncoder

# Load the trained models
random_forest_model = joblib.load(r'model\random_forest_model.pkl')
gradient_boosting_model = joblib.load(r'model\gradient_boosting_model.pkl')
decision_tree_model = joblib.load(r'model\decision_tree_model.pkl')
naive_bayes_model = joblib.load(r'model\naive_bayes_model.pkl')

# Set up the Streamlit app layout
st.title("Intrusion Detection System Prediction")
st.write("Select the model and input features to get predictions.")

# Dropdown for model selection
model_choice = st.selectbox("Select the Model", 
                             ["Random Forest", "Gradient Boosting", 
                              "Decision Tree", "Naive Bayes"])

# Input features based on KDD dataset
duration = st.number_input("Duration", value=0.0)
protocol_type = st.selectbox("Protocol Type", ["tcp", "udp", "icmp"])
flag = st.selectbox("Flag", ["SF", "S0", "REJ", "RSTO", "RSTOS0"])
src_bytes = st.number_input("Source Bytes", value=0.0)
dst_bytes = st.number_input("Destination Bytes", value=0.0)
land = st.number_input("Land (0 or 1)", value=0)
wrong_fragment = st.number_input("Wrong Fragment", value=0)
urgent = st.number_input("Urgent", value=0)
hot = st.number_input("Hot", value=0)
num_failed_logins = st.number_input("Number of Failed Logins", value=0)
logged_in = st.number_input("Logged In (0 or 1)", value=0)
num_compromised = st.number_input("Number Compromised", value=0)
root_shell = st.number_input("Root Shell (0 or 1)", value=0)
su_attempted = st.number_input("SU Attempted (0 or 1)", value=0)
num_file_creations = st.number_input("Number of File Creations", value=0)
num_shells = st.number_input("Number of Shells", value=0)
num_access_files = st.number_input("Number of Access Files", value=0)
num_outbound_cmds = st.number_input("Number of Outbound Commands", value=0)
is_host_login = st.number_input("Is Host Login (0 or 1)", value=0)
count = st.number_input("Count", value=0)
serror_rate = st.number_input("Service Error Rate", value=0.0)
rerror_rate = st.number_input("Remote Error Rate", value=0.0)
same_srv_rate = st.number_input("Same Service Rate", value=0.0)
diff_srv_rate = st.number_input("Different Service Rate", value=0.0)
srv_diff_host_rate = st.number_input("Service Different Host Rate", value=0.0)
dst_host_count = st.number_input("Destination Host Count", value=0)

dst_host_diff_srv_rate = st.number_input("Destination Host Different Service Rate", value=0.0)
dst_host_same_src_port_rate = st.number_input("Destination Host Same Source Port Rate", value=0.0)
dst_host_srv_diff_host_rate = st.number_input("Destination Host Service Different Host Rate", value=0.0)

# Mapping categorical variables to numerical values
protocol_mapping = {"tcp": 0, "udp": 1, "icmp": 2}
flag_mapping = {"SF": 0, "S0": 1, "REJ": 2, "RSTO": 3, "RSTOS0": 4}

# Convert categorical features to numeric values
protocol_type_encoded = protocol_mapping[protocol_type]
flag_encoded = flag_mapping[flag]

# Create a feature array with all required features (32 features)
features = np.array([[duration, 
                      protocol_type_encoded, 
                      flag_encoded, 
                      src_bytes, 
                      dst_bytes,
                      land, 
                      wrong_fragment, 
                      urgent, 
                      hot, 
                      num_failed_logins, 
                      logged_in, 
                      num_compromised, 
                      root_shell, 
                      su_attempted,
                      num_file_creations,
                      num_shells,
                      num_access_files,
                      num_outbound_cmds,
                      is_host_login,
                      count,
                      serror_rate,
                      rerror_rate,
                      same_srv_rate,
                      diff_srv_rate,
                      srv_diff_host_rate,
                      dst_host_count,
                      dst_host_diff_srv_rate,
                      dst_host_same_src_port_rate,
                      dst_host_srv_diff_host_rate]])

# Ensure the shape of features is correct (1 sample, 32 features)
features = features.reshape(1, -1)

# Mapping the prediction output to specific attack types from the KDD dataset
attack_types = {
    0: 'Normal',
    1: 'DoS - smurf',
    2: 'DoS - neptune',
    3: 'DoS - teardrop',
    4: 'DoS - pod',
    5: 'DoS - land',
    6: 'Probe - ipsweep',
    7: 'Probe - nmap',
    8: 'Probe - portsweep',
    9: 'Probe - satan',
    10: 'R2L - ftp_write',
    11: 'R2L - guess_passwd',
    12: 'R2L - imap',
    13: 'R2L - multihop',
    14: 'R2L - phf',
    15: 'R2L - spy',
    16: 'R2L - warezclient',
    17: 'R2L - warezmaster',
    18: 'U2R - buffer_overflow',
    19: 'U2R - loadmodule',
    20: 'U2R - perl',
    21: 'U2R - rootkit',
}
    # Continue adding mappings for other attacks based on your KDD dataset

# Make predictions based on the selected model
from scipy import stats

if st.button("Predict"):
    try:
        # Get predictions from all models
        random_forest_pred = random_forest_model.predict(features)
        gradient_boosting_pred = gradient_boosting_model.predict(features)
        decision_tree_pred = decision_tree_model.predict(features)
        naive_bayes_pred = naive_bayes_model.predict(features)

        # Combine predictions (XGBoost gets more influence by being repeated)
        combined_predictions = [
            random_forest_pred[0],
            gradient_boosting_pred[0],
            decision_tree_pred[0],
            naive_bayes_pred[0]
        ]

        # Use mode to get the final prediction
        final_prediction = stats.mode(combined_predictions)[0][0]

        # Display the final prediction result
        attack_prediction = attack_types.get(final_prediction, 'Unknown')
        st.write(f"Prediction: {final_prediction} - Attack Type: {attack_prediction}")
    
        
    except Exception as e:
        st.error(f"An error occurred: {str(e)}")

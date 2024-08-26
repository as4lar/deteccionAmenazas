import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from scapy.all import sniff, TCP
import joblib
# Cargar el modelo y el scaler
model = joblib.load('random_forest_model.pkl')
scaler = joblib.load('standard_scaler.pkl')

# Datos iniciales del flujo de paquetes
flow_data = {
    "Flow Duration": 0,
    "Tot Fwd Pkts": 0,
    "Tot Bwd Pkts": 0,
    "TotLen Fwd Pkts": 0,
    "TotLen Bwd Pkts": 0,
    "Fwd Pkt Len Max": 0,
    "Fwd Pkt Len Min": float('inf'),
    "Fwd Pkt Len Mean": 0,
    "Fwd Pkt Len Std": 0,
    "Bwd Pkt Len Max": 0,
    "Bwd Pkt Len Min": float('inf'),
    "Bwd Pkt Len Mean": 0,
    "Bwd Pkt Len Std": 0,
    "Flow Byts/s": 0,
    "Flow Pkts/s": 0,
    "Flow IAT Mean": 0,
    "Flow IAT Std": 0,
    "Flow IAT Max": 0,
    "Flow IAT Min": float('inf'),
    "Fwd IAT Tot": 0,
    "Fwd IAT Mean": 0,
    "Fwd IAT Std": 0,
    "Fwd IAT Max": 0,
    "Fwd IAT Min": float('inf'),
    "Bwd IAT Tot": 0,
    "Bwd IAT Mean": 0,
    "Bwd IAT Std": 0,
    "Bwd IAT Max": 0,
    "Bwd IAT Min": float('inf'),
    "Bwd PSH Flags": 0,
    "Fwd Header Len": 0,
    "Bwd Header Len": 0,
    "Fwd Pkts/s": 0,
    "Bwd Pkts/s": 0,
    "Pkt Len Min": float('inf'),
    "Pkt Len Max": 0,
    "Pkt Len Mean": 0,
    "Pkt Len Std": 0,
    "Pkt Len Var": 0,
    "FIN Flag Cnt": 0,
    "SYN Flag Cnt": 0,
    "RST Flag Cnt": 0,
    "ACK Flag Cnt": 0,
    "Down/Up Ratio": 0,
    "Pkt Size Avg": 0,
    "Fwd Seg Size Avg": 0,
    "Bwd Seg Size Avg": 0,
    "Init Bwd Win Byts": 0,
    "Fwd Act Data Pkts": 0,
    "Active Mean": 0,
    "Active Std": 0,
    "Active Max": 0,
    "Active Min": float('inf'),
    "Idle Mean": 0,
    "Idle Std": 0,
    "Idle Max": 0,
    "Idle Min": float('inf')
}


def extract_features(packet):
    # Actualiza Flow Duration
    flow_data['Flow Duration'] = packet.time

    # Verifica la correcta actualización de las características
    print("Before Extraction:", flow_data)

    # Número total de paquetes hacia adelante y hacia atrás
    if packet.haslayer(TCP):
        if packet[TCP].sport:
            flow_data['Tot Fwd Pkts'] += 1
            flow_data['TotLen Fwd Pkts'] += len(packet)
            fwd_pkt_len = len(packet)
            flow_data['Fwd Pkt Len Max'] = max(
                flow_data['Fwd Pkt Len Max'], fwd_pkt_len)
            flow_data['Fwd Pkt Len Min'] = min(
                flow_data['Fwd Pkt Len Min'], fwd_pkt_len) if fwd_pkt_len > 0 else flow_data['Fwd Pkt Len Min']
            flow_data['Fwd Pkt Len Mean'] = np.mean(
                [flow_data['Fwd Pkt Len Mean'], fwd_pkt_len])
            flow_data['Fwd Pkt Len Std'] = np.std(
                [flow_data['Fwd Pkt Len Std'], fwd_pkt_len])
        else:
            flow_data['Tot Bwd Pkts'] += 1
            flow_data['TotLen Bwd Pkts'] += len(packet)
            bwd_pkt_len = len(packet)
            flow_data['Bwd Pkt Len Max'] = max(
                flow_data['Bwd Pkt Len Max'], bwd_pkt_len)
            flow_data['Bwd Pkt Len Min'] = min(
                flow_data['Bwd Pkt Len Min'], bwd_pkt_len) if bwd_pkt_len > 0 else flow_data['Bwd Pkt Len Min']
            flow_data['Bwd Pkt Len Mean'] = np.mean(
                [flow_data['Bwd Pkt Len Mean'], bwd_pkt_len])
            flow_data['Bwd Pkt Len Std'] = np.std(
                [flow_data['Bwd Pkt Len Std'], bwd_pkt_len])

    # Reemplaza valores infinitos por 0
    features = list(flow_data.values())
    features = [0 if np.isnan(val) or np.isinf(
        val) else val for val in features]

    print("After Extraction:", features)
    features_df = pd.DataFrame([features], columns=scaler.feature_names_in_)
    features_normalized = scaler.transform(
        features_df)  # Normaliza las características

    return features_normalized


def packet_callback(packet):
    features = extract_features(packet)
    # Predicción usando el modelo entrenado
    prediction = model.predict(features)

    # Maneja la predicción (normal o ataque)
    print(f"Predicción: {prediction[0]}")


# Captura de paquetes en tiempo real
sniff(prn=packet_callback, count=100)

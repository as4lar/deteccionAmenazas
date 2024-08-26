import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score
from scapy.all import sniff, IP, TCP, UDP

# 1. Cargar los datasets
df_normal = pd.read_csv('CTU13_Normal_Traffic.csv')
df_ataque = pd.read_csv('CTU13_Attack_Traffic.csv')

# 2. Combinar los datasets
df = pd.concat([df_normal, df_ataque], ignore_index=True)

# 3. Separar las características (features) y la etiqueta (label)
X = df.drop(columns=['Label'])
y = df['Label']

# 4. Normalizar las características
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# 5. Dividir los datos en entrenamiento y prueba
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.3, random_state=42)

# 6. Entrenar el modelo RandomForest
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 7. Evaluar el modelo
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f'Accuracy del modelo: {accuracy:.2f}')

# 8. Preparar la captura de red en tiempo real
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
    flow_data['Tot Fwd Pkts'] += 1 if packet.haslayer(
        TCP) and packet[TCP].sport else 0
    flow_data['Tot Bwd Pkts'] += 1 if packet.haslayer(
        TCP) and packet[TCP].dport else 0

    # Longitud total de paquetes hacia adelante y hacia atrás
    flow_data['TotLen Fwd Pkts'] += len(packet) if packet.haslayer(
        TCP) and packet[TCP].sport else 0
    flow_data['TotLen Bwd Pkts'] += len(packet) if packet.haslayer(
        TCP) and packet[TCP].dport else 0

    # Longitud de paquetes
    fwd_pkt_len = len(packet) if packet.haslayer(
        TCP) and packet[TCP].sport else 0
    bwd_pkt_len = len(packet) if packet.haslayer(
        TCP) and packet[TCP].dport else 0

    flow_data['Fwd Pkt Len Max'] = max(
        flow_data['Fwd Pkt Len Max'], fwd_pkt_len)
    flow_data['Fwd Pkt Len Min'] = min(
        flow_data['Fwd Pkt Len Min'], fwd_pkt_len) if fwd_pkt_len > 0 else flow_data['Fwd Pkt Len Min']
    flow_data['Fwd Pkt Len Mean'] = np.mean(
        [flow_data['Fwd Pkt Len Mean'], fwd_pkt_len])
    flow_data['Fwd Pkt Len Std'] = np.std(
        [flow_data['Fwd Pkt Len Std'], fwd_pkt_len])

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
sniff(
    prn=packet_callback, count=100)

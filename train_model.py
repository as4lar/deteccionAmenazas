import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score
import joblib

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

# 8. Guardar el modelo y el scaler
joblib.dump(model, 'random_forest_model.pkl')
joblib.dump(scaler, 'standard_scaler.pkl')

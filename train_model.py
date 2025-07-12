import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib

# Load data
df = pd.read_csv("dataset.csv")

# Get all unique symptoms from all symptom columns
all_symptoms = set()
for col in df.columns:
    if col.startswith("Symptom_"):
        all_symptoms.update(df[col].dropna().unique())
all_symptoms = sorted(all_symptoms)

# Prepare training data
X = []
y = []

for _, row in df.iterrows():
    # Create binary feature vector (1=has symptom, 0=doesn't)
    features = [1 if symptom in row.values else 0 for symptom in all_symptoms]
    X.append(features)
    y.append(row["Disease"])

# Train model
model = RandomForestClassifier()
model.fit(X, y)

# Save model and symptom list
joblib.dump(model, "model.joblib")
joblib.dump(all_symptoms, "symptoms.joblib")

print("Model trained successfully!")
print(f"Found {len(all_symptoms)} symptoms")
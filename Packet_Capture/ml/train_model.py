import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

print("Loading dataset...")

# =========================
# LOAD DATASET
# =========================
train = pd.read_csv(r"C:\Users\HP\Downloads\archive (5)\UNSW-NB15_c\UNSW_NB15_training-set.csv")

# =========================
# CLEAN DATA
# =========================
drop_cols = [c for c in ['id', 'attack_cat'] if c in train.columns]

X = train.drop(drop_cols + ['label'], axis=1)
y = train['label']

# =========================
# SPLIT DATA
# =========================
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# =========================
# ENCODING
# =========================
X_train = pd.get_dummies(X_train)
X_test = pd.get_dummies(X_test)

X_test = X_test.reindex(columns=X_train.columns, fill_value=0)

# =========================
# TRAIN MODEL
# =========================
print("Training model...")

model = RandomForestClassifier(
    n_estimators=150,
    max_depth=18,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# =========================
# EVALUATION
# =========================
acc = model.score(X_test, y_test)
print("Accuracy:", acc)

# =========================
# SAVE MODEL + FEATURES
# =========================
print("Saving files...")

joblib.dump(model, "ids_model.pkl")
joblib.dump(X_train.columns.tolist(), "columns.pkl")

print("DONE  Model created successfully")

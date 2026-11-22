"""
preprocessing.py — NEXUS-IDS Data Preprocessing Pipeline

Handles categorical encoding, feature scaling, label mapping, train/test
serialization, and missing-value imputation for the NSL-KDD dataset.
"""

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
MODELS_DIR = PROJECT_ROOT / "models"

# 5-class label mapping
ATTACK_MAP = {
    'normal': 'normal',
    'neptune': 'dos', 'smurf': 'dos', 'back': 'dos', 'teardrop': 'dos',
    'pod': 'dos', 'land': 'dos', 'mailbomb': 'dos', 'apache2': 'dos',
    'processtable': 'dos', 'udpstorm': 'dos',
    'ipsweep': 'probe', 'portsweep': 'probe', 'nmap': 'probe', 'satan': 'probe',
    'mscan': 'probe', 'saint': 'probe',
    'ftp_write': 'r2l', 'guess_passwd': 'r2l', 'imap': 'r2l', 'spy': 'r2l',
    'phf': 'r2l', 'multihop': 'r2l', 'warezmaster': 'r2l', 'warezclient': 'r2l',
    'snmpguess': 'r2l', 'snmpgetattack': 'r2l', 'httptunnel': 'r2l',
    'sendmail': 'r2l', 'named': 'r2l', 'xlock': 'r2l', 'xsnoop': 'r2l',
    'worm': 'r2l',
    'buffer_overflow': 'u2r', 'loadmodule': 'u2r', 'perl': 'u2r',
    'rootkit': 'u2r', 'sqlattack': 'u2r', 'xterm': 'u2r', 'ps': 'u2r',
}

CLASS_TO_INT = {'normal': 0, 'dos': 1, 'probe': 2, 'r2l': 3, 'u2r': 4}
CATEGORICAL_COLS = ['protocol_type', 'service', 'flag']


def map_labels(df: pd.DataFrame) -> pd.DataFrame:
    """
    Maps raw NSL-KDD attack names to 5 classes and integer-encodes them.

    Args:
        df: Raw DataFrame with 'label' column.

    Returns:
        DataFrame with 'attack_class' (str) and 'target' (int) columns added.
    """
    df = df.copy()
    df['attack_class'] = df['label'].map(ATTACK_MAP).fillna('unknown')
    df['target'] = df['attack_class'].map(CLASS_TO_INT).fillna(3).astype(int)
    return df


def encode_categoricals(df: pd.DataFrame, fit: bool = True, encoders: dict = None) -> tuple:
    """
    Label-encodes categorical columns (protocol_type, service, flag).

    Args:
        df: DataFrame to encode.
        fit: If True, fit new encoders. If False, use provided encoders.
        encoders: Pre-fitted LabelEncoder dict (for test data).

    Returns:
        Tuple of (encoded DataFrame, encoder dict).
    """
    df = df.copy()
    if encoders is None:
        encoders = {}

    for col in CATEGORICAL_COLS:
        if col in df.columns:
            if fit:
                le = LabelEncoder()
                df[col] = le.fit_transform(df[col].astype(str))
                encoders[col] = le
            else:
                le = encoders[col]
                # Handle unseen labels gracefully
                known = set(le.classes_)
                df[col] = df[col].astype(str).apply(lambda x: x if x in known else le.classes_[0])
                df[col] = le.transform(df[col])

    return df, encoders


def scale_features(X: pd.DataFrame, fit: bool = True, scaler: StandardScaler = None) -> tuple:
    """
    Standardize feature matrix using StandardScaler.

    Args:
        X: Feature matrix.
        fit: If True, fit a new scaler.
        scaler: Pre-fitted scaler (for test data).

    Returns:
        Tuple of (scaled DataFrame, scaler).
    """
    if fit or scaler is None:
        scaler = StandardScaler()
        X_scaled = pd.DataFrame(scaler.fit_transform(X), columns=X.columns, index=X.index)
    else:
        X_scaled = pd.DataFrame(scaler.transform(X), columns=X.columns, index=X.index)

    return X_scaled, scaler


def preprocess_pipeline(df: pd.DataFrame, fit: bool = True,
                        encoders: dict = None, scaler: StandardScaler = None,
                        save: bool = False, tag: str = "train") -> dict:
    """
    Full preprocessing pipeline: map labels, handle missing values, encode,
    scale, and optionally save artifacts.

    Args:
        df: Raw NSL-KDD DataFrame.
        fit: If True, fit new encoders/scaler (training). False for test.
        encoders: Pre-fitted encoders (test mode).
        scaler: Pre-fitted scaler (test mode).
        save: If True, save processed data to disk.
        tag: 'train' or 'test'.

    Returns:
        Dict with keys: X, y, attack_classes, encoders, scaler, feature_names
    """
    print(f"[*] Preprocessing {tag} data ...")

    # 1. Map labels
    df = map_labels(df)

    # 2. Drop unnecessary columns
    drop_cols = ['label', 'difficulty', 'attack_class', 'target']
    feature_cols = [c for c in df.columns if c not in drop_cols]

    # 3. Handle missing values
    for col in feature_cols:
        if df[col].dtype in ['float64', 'int64']:
            df[col] = df[col].fillna(df[col].median())
        else:
            df[col] = df[col].fillna(df[col].mode().iloc[0] if len(df[col].mode()) > 0 else 'unknown')

    # 4. Encode categoricals
    df, encoders = encode_categoricals(df, fit=fit, encoders=encoders)

    # 5. Extract features and targets
    X = df[feature_cols].copy()
    y = df['target'].values
    attack_classes = df['attack_class'].values

    # 6. Scale features
    X_scaled, scaler = scale_features(X, fit=fit, scaler=scaler)

    print(f"[✓] Preprocessing complete — X: {X_scaled.shape}, y: {y.shape}")

    # 7. Save if requested
    if save:
        PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
        MODELS_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(X_scaled, PROCESSED_DIR / f"X_{tag}.pkl")
        joblib.dump(y, PROCESSED_DIR / f"y_{tag}.pkl")
        
        # Only save encoders/scaler if fit=True (training data)
        if fit:
            joblib.dump(encoders, MODELS_DIR / "encoders.pkl")
            joblib.dump(scaler, MODELS_DIR / "scaler.pkl")
            print("[✓] encoders.pkl saved")
            print("[✓] scaler.pkl saved")

        print(f"[✓] Saved processed {tag} data and artifacts.")

    return {
        "X": X_scaled,
        "y": y,
        "attack_classes": attack_classes,
        "encoders": encoders,
        "scaler": scaler,
        "feature_names": list(X_scaled.columns),
    }


if __name__ == "__main__":
    import argparse
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from data_loader import load_dataset

    parser = argparse.ArgumentParser(description="NEXUS-IDS Preprocessor")
    parser.add_argument("--save", action="store_true", help="Save processed files")
    args = parser.parse_args()

    # Process train
    train_df = load_dataset("train")
    train_result = preprocess_pipeline(train_df, fit=True, save=args.save, tag="train")

    # Process test with same encoders/scaler
    test_df = load_dataset("test")
    test_result = preprocess_pipeline(
        test_df, fit=False,
        encoders=train_result["encoders"],
        scaler=train_result["scaler"],
        save=args.save, tag="test"
    )

    print(f"\nTrain X: {train_result['X'].shape}, Test X: {test_result['X'].shape}")
    print(f"Feature names: {train_result['feature_names'][:5]} ...")

"""
data_loader.py — NEXUS-IDS Data Acquisition Module

Handles downloading, loading, and basic validation of the NSL-KDD dataset.
Supports both KDDTrain+.csv and KDDTest+.csv.
Falls back to generating a realistic synthetic dataset when downloads fail.
"""

import pandas as pd
import numpy as np
from pathlib import Path
import requests
import os
import sys

# Canonical NSL-KDD column names (41 features + label + difficulty)
NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty"
]

# 5-class label mapping
ATTACK_MAP = {
    'normal': 'normal',
    # DoS attacks
    'neptune': 'dos', 'smurf': 'dos', 'back': 'dos', 'teardrop': 'dos',
    'pod': 'dos', 'land': 'dos', 'mailbomb': 'dos', 'apache2': 'dos',
    'processtable': 'dos', 'udpstorm': 'dos',
    # Probe attacks
    'ipsweep': 'probe', 'portsweep': 'probe', 'nmap': 'probe', 'satan': 'probe',
    'mscan': 'probe', 'saint': 'probe',
    # R2L attacks
    'ftp_write': 'r2l', 'guess_passwd': 'r2l', 'imap': 'r2l', 'spy': 'r2l',
    'phf': 'r2l', 'multihop': 'r2l', 'warezmaster': 'r2l', 'warezclient': 'r2l',
    'snmpguess': 'r2l', 'snmpgetattack': 'r2l', 'httptunnel': 'r2l',
    'sendmail': 'r2l', 'named': 'r2l', 'xlock': 'r2l', 'xsnoop': 'r2l',
    'worm': 'r2l',
    # U2R attacks
    'buffer_overflow': 'u2r', 'loadmodule': 'u2r', 'perl': 'u2r',
    'rootkit': 'u2r', 'sqlattack': 'u2r', 'xterm': 'u2r', 'ps': 'u2r',
    'httptunnel': 'u2r',
}

CLASS_TO_INT = {'normal': 0, 'dos': 1, 'probe': 2, 'r2l': 3, 'u2r': 4}

# Remote URLs for NSL-KDD (multiple mirrors)
DOWNLOAD_URLS = {
    "KDDTrain+.csv": [
        "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.csv",
    ],
    "KDDTest+.csv": [
        "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.csv",
    ],
}

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = PROJECT_ROOT / "data" / "raw"


def download_file(filename: str) -> bool:
    """
    Attempts to download a dataset file from known mirrors.

    Args:
        filename: The target filename (e.g. 'KDDTrain+.csv')

    Returns:
        True if download succeeded, False otherwise.
    """
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    dest = RAW_DIR / filename

    if dest.exists():
        print(f"[✓] {filename} already exists at {dest}")
        return True

    urls = DOWNLOAD_URLS.get(filename, [])
    for url in urls:
        try:
            print(f"[*] Downloading {filename} from {url} ...")
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            dest.write_bytes(resp.content)
            print(f"[✓] Downloaded {filename} ({len(resp.content) / 1024:.0f} KB)")
            return True
        except Exception as e:
            print(f"[!] Mirror failed: {e}")
            continue

    print(f"[!] Could not download {filename}. Will generate synthetic data.")
    return False


def _generate_synthetic(num_samples: int = 25000) -> pd.DataFrame:
    """
    Generates a statistically realistic synthetic NSL-KDD dataset.
    Used as fallback when real dataset is unavailable.

    Args:
        num_samples: Number of records to generate.

    Returns:
        DataFrame with NSL-KDD schema.
    """
    np.random.seed(42)
    protocols = ['tcp', 'udp', 'icmp']
    services = [
        'http', 'smtp', 'ftp_data', 'private', 'domain_u', 'ftp',
        'eco_i', 'pop_3', 'telnet', 'finger', 'other', 'auth',
        'ssh', 'imap4', 'login', 'remote_job'
    ]
    flags = ['SF', 'S0', 'REJ', 'RSTR', 'SH', 'RSTO', 'S1', 'S2', 'S3', 'OTH']

    attack_types = list(ATTACK_MAP.keys())
    # Weighted distribution — normal ~53%, dos ~35%, probe ~8%, r2l ~3%, u2r ~1%
    weights_by_class = {'normal': 0.53, 'dos': 0.35, 'probe': 0.08, 'r2l': 0.03, 'u2r': 0.01}
    attack_weights = []
    for a in attack_types:
        cls = ATTACK_MAP[a]
        cls_attacks = [k for k, v in ATTACK_MAP.items() if v == cls]
        attack_weights.append(weights_by_class[cls] / len(cls_attacks))

    attack_weights = np.array(attack_weights)
    attack_weights /= attack_weights.sum()

    rows = []
    for _ in range(num_samples):
        label = np.random.choice(attack_types, p=attack_weights)
        cls = ATTACK_MAP[label]
        is_attack = cls != 'normal'

        row = {
            'duration': int(np.random.exponential(10)) if is_attack else 0,
            'protocol_type': np.random.choice(protocols, p=[0.7, 0.2, 0.1] if not is_attack else [0.4, 0.3, 0.3]),
            'service': np.random.choice(services),
            'flag': np.random.choice(flags, p=[0.6, 0.15, 0.05, 0.05, 0.03, 0.03, 0.03, 0.02, 0.02, 0.02] if not is_attack else [0.2, 0.35, 0.1, 0.1, 0.05, 0.05, 0.05, 0.03, 0.04, 0.03]),
            'src_bytes': int(np.random.lognormal(5, 2)) if not is_attack else int(np.random.lognormal(3, 2)),
            'dst_bytes': int(np.random.lognormal(6, 2)) if not is_attack else int(np.random.lognormal(1, 2)),
            'land': int(np.random.choice([0, 1], p=[0.99, 0.01])),
            'wrong_fragment': int(np.random.choice([0, 1, 3], p=[0.92, 0.05, 0.03])),
            'urgent': 0,
            'hot': int(np.random.poisson(0.3)) if is_attack else 0,
            'num_failed_logins': int(np.random.choice([0, 1, 2, 3], p=[0.93, 0.04, 0.02, 0.01])),
            'logged_in': 1 if not is_attack else int(np.random.choice([0, 1], p=[0.7, 0.3])),
            'num_compromised': int(np.random.choice([0, 1, 2])) if is_attack else 0,
            'root_shell': int(np.random.choice([0, 1], p=[0.98, 0.02])) if cls == 'u2r' else 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
            'count': int(np.random.randint(1, 500)),
            'srv_count': int(np.random.randint(1, 500)),
            'serror_rate': float(np.random.uniform(0.5, 1.0)) if cls == 'dos' else 0.0,
            'srv_serror_rate': float(np.random.uniform(0.5, 1.0)) if cls == 'dos' else 0.0,
            'rerror_rate': float(np.random.uniform(0, 0.3)),
            'srv_rerror_rate': 0.0,
            'same_srv_rate': float(np.random.uniform(0.6, 1.0)) if not is_attack else float(np.random.uniform(0, 0.5)),
            'diff_srv_rate': float(np.random.uniform(0, 0.1)) if not is_attack else float(np.random.uniform(0.1, 0.8)),
            'srv_diff_host_rate': float(np.random.uniform(0, 0.2)),
            'dst_host_count': int(np.random.randint(1, 255)),
            'dst_host_srv_count': int(np.random.randint(1, 255)),
            'dst_host_same_srv_rate': float(np.random.uniform(0.5, 1.0)) if not is_attack else float(np.random.uniform(0, 0.5)),
            'dst_host_diff_srv_rate': float(np.random.uniform(0, 0.1)) if not is_attack else float(np.random.uniform(0.1, 0.8)),
            'dst_host_same_src_port_rate': float(np.random.uniform(0, 0.3)),
            'dst_host_srv_diff_host_rate': float(np.random.uniform(0, 0.1)),
            'dst_host_serror_rate': float(np.random.uniform(0.5, 1.0)) if cls == 'dos' else 0.0,
            'dst_host_srv_serror_rate': float(np.random.uniform(0.5, 1.0)) if cls == 'dos' else 0.0,
            'dst_host_rerror_rate': float(np.random.uniform(0, 0.2)),
            'dst_host_srv_rerror_rate': float(np.random.uniform(0, 0.1)),
            'label': label,
            'difficulty': int(np.random.randint(1, 21)),
        }
        rows.append(row)

    df = pd.DataFrame(rows, columns=NSL_KDD_COLUMNS)
    return df


def load_dataset(dataset: str = "train") -> pd.DataFrame:
    """
    Loads NSL-KDD dataset. Downloads if missing, falls back to synthetic.

    Args:
        dataset: 'train' or 'test'

    Returns:
        Raw DataFrame with canonical column names.
    """
    filename = "KDDTrain+.csv" if dataset == "train" else "KDDTest+.csv"
    filepath = RAW_DIR / filename

    # Attempt download if file is missing
    if not filepath.exists():
        success = download_file(filename)
        if not success:
            print(f"[*] Generating synthetic {dataset} dataset ...")
            df = _generate_synthetic(25000 if dataset == "train" else 10000)
            RAW_DIR.mkdir(parents=True, exist_ok=True)
            df.to_csv(filepath, index=False)
            print(f"[✓] Synthetic {dataset} data saved to {filepath}")
            return df

    # Load from CSV
    print(f"[*] Loading {filename} ...")
    df = pd.read_csv(filepath, header=None)

    # If columns are unlabelled (original NSL-KDD has no header)
    if df.shape[1] == len(NSL_KDD_COLUMNS):
        df.columns = NSL_KDD_COLUMNS
    elif df.shape[1] == len(NSL_KDD_COLUMNS) - 1:
        # Some versions omit difficulty
        df.columns = NSL_KDD_COLUMNS[:-1]
    else:
        # File has headers already
        df = pd.read_csv(filepath)

    print(f"[✓] Loaded {len(df)} records from {filename}")
    return df


def get_dataset_stats(df: pd.DataFrame) -> dict:
    """
    Computes summary statistics for the loaded dataset.

    Args:
        df: Raw NSL-KDD DataFrame.

    Returns:
        Dictionary of statistics.
    """
    mapped = df['label'].map(ATTACK_MAP).fillna('unknown')
    stats = {
        "total_records": len(df),
        "total_features": len([c for c in df.columns if c not in ('label', 'difficulty')]),
        "normal_count": int((mapped == 'normal').sum()),
        "dos_count": int((mapped == 'dos').sum()),
        "probe_count": int((mapped == 'probe').sum()),
        "r2l_count": int((mapped == 'r2l').sum()),
        "u2r_count": int((mapped == 'u2r').sum()),
        "unique_attacks": int(df['label'].nunique()),
    }
    return stats


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="NEXUS-IDS Data Loader")
    parser.add_argument("--dataset", choices=["train", "test"], default="train")
    args = parser.parse_args()

    df = load_dataset(args.dataset)
    print(f"\nShape: {df.shape}")
    print(f"\nFirst 5 rows:\n{df.head()}")
    print(f"\nStatistics: {get_dataset_stats(df)}")

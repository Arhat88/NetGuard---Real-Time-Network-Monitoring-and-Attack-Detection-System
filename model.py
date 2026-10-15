import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import StandardScaler
from imblearn.over_sampling import SMOTE
import joblib
from retrainer import fetch_realtime_data

pd.set_option('display.max_colwidth', None)

COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
    'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
    'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
    'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
    'attack', 'level'
]

DOS   = ['neptune', 'smurf', 'teardrop', 'pod', 'back', 'land',
         'apache2', 'processtable', 'mailbomb', 'udpstorm']
PROBE = ['ipsweep', 'portsweep', 'nmap', 'satan', 'mscan', 'saint']
R2L   = ['warezclient', 'guess_passwd', 'ftp_write', 'imap', 'warezmaster',
         'phf', 'multihop', 'spy', 'snmpguess', 'snmpgetattack',
         'httptunnel', 'named', 'sendmail', 'xlock', 'xsnoop', 'worm']
U2R   = ['buffer_overflow', 'rootkit', 'loadmodule', 'perl',
         'xterm', 'ps', 'sqlattack']


def map_atk(x):
    if x == 'normal':   return 'Normal'
    if x in DOS:        return 'DoS'
    if x in PROBE:      return 'Probe'
    if x in R2L:        return 'R2L'
    if x in U2R:        return 'U2R'
    return 'Other'


def retrain_model():
    import os
    base_path = os.path.dirname(os.path.abspath(__file__))
    train_path = os.path.join(base_path, "dataset", "KDDTrain+.txt")
    test_path  = os.path.join(base_path, "dataset", "KDDTest+.txt")

    train_df = pd.read_csv(train_path, header=None)
    test_df  = pd.read_csv(test_path,  header=None)

    train_df.columns = COLUMNS
    test_df.columns  = COLUMNS

    train_df['attack'] = train_df['attack'].apply(map_atk)
    test_df['attack']  = test_df['attack'].apply(map_atk)

    for df in [train_df, test_df]:
        df.drop(['num_outbound_cmds', 'level'], axis=1, inplace=True)

    # Merge real-time data
    realtime_df = fetch_realtime_data()
    realtime_df.rename(columns={"attack_type": "attack"}, inplace=True)
    for col in train_df.columns:
        if col not in realtime_df.columns:
            realtime_df[col] = 0
    realtime_df = realtime_df[train_df.columns]
    train_df = pd.concat([train_df, realtime_df], ignore_index=True)

    X_train = train_df.drop('attack', axis=1)
    y_train = train_df['attack']
    X_test  = test_df.drop('attack', axis=1)
    y_test  = test_df['attack']

    categorical_col = ["protocol_type", "service", "flag"]
    X_train = pd.get_dummies(X_train, columns=categorical_col)
    X_test  = pd.get_dummies(X_test,  columns=categorical_col)
    X_train, X_test = X_train.align(X_test, join='left', axis=1, fill_value=0)

    smote = SMOTE(
        sampling_strategy={'Probe': 18000, 'R2L': 25000, 'U2R': 4000},
        random_state=42
    )
    X_train_s, y_train_s = smote.fit_resample(X_train, y_train)

    # Feature Scaling
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train_s)
    X_test_scaled = scaler.transform(X_test)

    clf = RandomForestClassifier(n_estimators=200, max_depth=20,
                                 random_state=42, n_jobs=-1)
    clf.fit(X_train_s, y_train_s)

    new_acc = accuracy_score(y_test, clf.predict(X_test_scaled))
    print(f"New accuracy: {new_acc:.4f}")

    if new_acc < 0.70:
        print("Accuracy too low — retraining aborted.")
        return

    joblib.dump(clf, "rf_model.pkl")
    joblib.dump(scaler, "scaler.pkl")
    joblib.dump(X_train.columns, "model_columns.pkl")
    print("Model retrained successfully!")


if __name__ == "__main__":
    retrain_model()

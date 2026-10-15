import joblib
from feature_extractor import prep_for_model
from database import safe_execute

model = joblib.load("rf_model.pkl")
try:
    scaler = joblib.load("scaler.pkl")
except:
    scaler = None


def predict_flow(features, flow, flow_id, user_id):
    model_input = prep_for_model(features)
    
    if scaler:
        model_input = scaler.transform(model_input)

    proba = model.predict_proba(model_input)
    prediction = model.predict(model_input)

    pred_label = str(prediction[0])
    confidence = float(max(proba[0]))

    # FIX: safe_execute handles its own connection + commit; no extra conn needed
    safe_execute(
        """INSERT INTO predictions (flow_id, prediction_label, attack_type, confidence_score)
           VALUES (?, ?, ?, ?)""",
        (flow_id, pred_label, pred_label, confidence)
    )

    alert = "Normal"
    severity = "LOW"

    # 1. Model Prediction with Confidence threshold
    if pred_label != "Normal" and confidence > 0.65:
        alert = pred_label
        severity = "HIGH"

    # 2. Rule-based Fallback (Manual rules override/complement the model)
    # This helps catch attacks the model missed or was "confidently wrong" about.
    if alert == "Normal":
        # DoS Rule: High count + connection errors (S0/REJ)
        if features["count"] > 15 and features["serror_rate"] > 0.4:
            alert = "DoS"
            severity = "HIGH"
        # Probe Rule: High variety of services from same source
        elif features["diff_srv_rate"] > 0.7 and features["count"] > 10:
            alert = "Probe"
            severity = "MEDIUM"

    if alert != "Normal":
        safe_execute(
            """INSERT INTO alerts_logs (flow_id, alert_type, severity_level, status, message, handled_by)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (flow_id, alert, severity, "NEW", f"Intrusion detected: {alert}", user_id)
        )

    print("=" * 30)
    print(f"Duration     : {features['duration']}")
    print(f"Src Bytes    : {features['src_bytes']}")
    print(f"Dst Bytes    : {features['dst_bytes']}")
    print(f"Packets      : {flow['packet_count']}")
    print(f"Protocol     : {features['protocol_type']}")
    print(f"Service      : {features['service']}")
    print(f"Flag         : {features['flag']}")
    print(f"Count        : {features['count']}")
    print(f"Same srv rate: {features['same_srv_rate']}")
    print(f"Dst host cnt : {features['dst_host_count']}")
    print(f"Confidence   : {confidence:.4f}")
    print(f"Prediction   : {pred_label}")
    print(f"Alert        : {alert}")

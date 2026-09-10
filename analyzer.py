from datetime import datetime
from elasticsearch import Elasticsearch
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# 1. الاتصال بقاعدة بيانات Elasticsearch لـ T-Pot
ES_HOST = "https://your-tpot-ip:9200"
ES_USER = "elastic"
ES_PASSWORD = "your_password"

try:
    client = Elasticsearch(
        ES_HOST,
        basic_auth=(ES_USER, ES_PASSWORD),
        verify_certs=False,
    )
    print("[+] Connected to Elasticsearch successfully.")
except Exception as e:
    print(f"[-] Connection failed: {e}")
    exit(1)


# 2. سحب السجلات وتحويلها إلى هيكل بيانات تحليلي
def fetch_and_preprocess_logs(index_pattern="logstash-*", size=10000):
    query = {"query": {"match_all": {}}, "size": size}
    response = client.search(body=query, index=index_pattern)
    hits = response["hits"]["hits"]

    logs = []
    for hit in hits:
        source = hit["_source"]
        timestamp = source.get("@timestamp")
        # استخراج الساعة الزمنية لتحليل الأنماط الزمكانية للهجمات
        hour = (
            datetime.fromisoformat(timestamp.replace("Z", "+00:00")).hour
            if timestamp
            else 0
        )

        logs.append(
            {
                "timestamp": timestamp,
                "src_ip": source.get("src_ip", "unknown"),
                "username": source.get("username", "unknown"),
                "honeypot": source.get("sensor", "unknown"),
                "hour": hour,
            }
        )

    df = pd.DataFrame(logs)
    return df


# 3. هندسة الخصائص (Feature Engineering) للتعلم الآلي
def extract_features(df):
    # تجميع السجلات بناءً على عنوان الـ IP لاستخراج سلوك المهاجم
    ip_behavior = (
        df.groupby("src_ip")
        .agg(
            total_attacks=("src_ip", "count"),
            unique_usernames=("username", "nunique"),
            avg_hour=("hour", "mean"),
        )
        .reset_index()
    )

    return ip_behavior


# 4. تطبيق نموذج الكشف عن الشذوذ (Anomaly Detection - Isolation Forest)
def detect_anomalies(ip_features):
    # تجهيز المتغيرات الرقمية للنموذج
    X = ip_features[["total_attacks", "unique_usernames", "avg_hour"]]

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # بناء نموذج Isolation Forest (contamination يحدد نسبة الشذوذ المتوقعة)
    model = IsolationForest(contamination=0.05, random_state=42)
    ip_features["anomaly_score"] = model.fit_predict(X_scaled)

    # تحويل التسميات: -1 يعني هجوم شاذ/متقدم، 1 يعني هجوم تقليدي
    ip_features["behavior_status"] = ip_features["anomaly_score"].map(
        {1: "Normal/Standard Attack", -1: "Anomalous/Advanced Threat"}
    )

    return ip_features


# التنفيذ الرئيسي للبايبلاين البرمجي
if __name__ == "__main__":
    print("[*] Fetching logs from T-Pot...")
    df_raw = fetch_and_preprocess_logs()

    if not df_raw.empty:
        print("[*] Engineering behavioral features...")
        features_df = extract_features(df_raw)

        print("[*] Running Machine Learning Anomaly Detection Model...")
        analyzed_df = detect_anomalies(features_df)

        # استعراض الهجمات الشاذة المكتشفة
        anomalies = analyzed_df[
            analyzed_df["behavior_status"] == "Anomalous/Advanced Threat"
        ]
        print("\n" + "=" * 60)
        print("          تقرير الهجمات الشاذة المكتشفة بالذكاء الاصطناعي      ")
        print("=" * 60)
        print(anomalies.to_string(index=False))

        # حفظ النتائج لتوثيق المشروع
        analyzed_df.to_csv("tpot_ml_anomalies_report.csv", index=False)
        print(
            "\n[+] تم حفظ تقرير التحليل المتقدم بنجاح في ملف 'tpot_ml_anomalies_report.csv'."
        )
    else:
        print("[-] لم يتم العثور على بيانات كافية للتحليل.")
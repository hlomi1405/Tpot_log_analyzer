from elasticsearch import Elasticsearch
import pandas as pd
import json
from datetime import datetime

# --- عدلي هنا معلومات سيرفرك ---
ES_HOST = "https://[رابط سيرفر سمية:رقم المنفذ]"
ES_USER = "[اسم المستخدم]"
ES_PASSWORD = "[كلمة المرور]"
# --------------------------------

es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASSWORD), verify_certs=False)

print("جاري جلب البيانات...")
res = es.search(index="logstash-*", size=5000, query={"match_all": {}})
logs = [hit["_source"] for hit in res["hits"]["hits"]]
df = pd.DataFrame(logs)

results = {
    "total_logs": len(df),
    "analysis_date": datetime.now().isoformat(),
    "top_ips": df['src_ip'].value_counts().head(10).to_dict() if 'src_ip' in df.columns else {},
}

with open("results.json", "w", encoding="utf-8") as f:
    json.dump(results, f, ensure_ascii=False, indent=2)

print("تم توليد results.json")

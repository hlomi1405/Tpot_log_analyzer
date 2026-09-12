from elasticsearch import Elasticsearch
import pandas as pd
import json
from datetime import datetime
ES_HOST = "https://51.75.122.184:9200"
ES_USER = "elastic"
ES_PASSWORD = "changeme"
es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASSWORD), verify_certs=False)
res = es.search(index="logstash-*", size=5000, query={"match_all": {}})
logs = [hit["_source"] for hit in res["hits"]["hits"]]
df = pd.DataFrame(logs)
results = {"total_logs": len(df), "analysis_date": datetime.now().isoformat()}
with open("results.json", "w", encoding="utf-8") as f:
    json.dump(results, f, ensure_ascii=False, indent=2)
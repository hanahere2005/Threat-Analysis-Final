import json
import psycopg2
from psycopg2.extras import execute_batch
from datetime import datetime

# ===============================
# 🔐 Database Config
# ===============================
DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "Threat-Intelligence-Database-Schema",
    "user": "postgres",
    "password": "root@123"
}

# ===============================
# 📄 JSON file path
# ===============================
JSON_FILE = "osv_opencti_bulk.json"

# ===============================
# 🧾 Insert Query (fixed references)
# ===============================
INSERT_QUERY = """
INSERT INTO "Storing-Threat-Data".cves (
    external_id,
    title,
    description,
    category,
    severity,
    cvss_score,
    cvss_vector,
    cwe_list,
    cwe_ids,
    vendors,
    products,
    affected_products_count,
    references_count,
    "references",
    tags,
    original_source_url,
    actual_url,
    source_name,
    published_date,
    last_updated_from_source,
    ingested_at,
    data_version,
    metadata,
    source
) VALUES (
    %(external_id)s,
    %(title)s,
    %(description)s,
    %(category)s,
    %(severity)s,
    %(cvss_score)s,
    %(cvss_vector)s,
    %(cwe_list)s,
    %(cwe_ids)s,
    %(vendors)s,
    %(products)s,
    %(affected_products_count)s,
    %(references_count)s,
    %(references)s,
    %(tags)s,
    %(original_source_url)s,
    %(actual_url)s,
    %(source_name)s,
    %(published_date)s,
    %(last_updated_from_source)s,
    %(ingested_at)s,
    %(data_version)s,
    %(metadata)s,
    %(source)s
)
ON CONFLICT (external_id) DO NOTHING;
"""

# ===============================
# 🧭 Helper: Parse date safely
# ===============================
def parse_date(date_str):
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except Exception:
        return None

# ===============================
# 🧭 Transform record
# ===============================
def parse_record(entry):
    external_id = None

    # Prefer CVE ID if available, else fallback to source_id
    cve_ids = entry.get("cve_ids", [])
    if cve_ids and len(cve_ids) > 0:
        external_id = cve_ids[0]
    else:
        external_id = entry.get("source_id")

    # Tags array
    tags = entry.get("tags", []) if entry.get("tags") else []

    # References count
    references = entry.get("references", [])
    references_count = len(references) if references else 0

    # Products
    products = entry.get("affected_products", []) if entry.get("affected_products") else []

    # Published and modified dates
    published_date = parse_date(entry.get("published_date"))
    modified_date = parse_date(entry.get("modified_date"))
    ingested_at = parse_date(entry.get("ingested_at")) or datetime.utcnow()

    # CVSS
    cvss = entry.get("cvss")
    cvss_score = None
    cvss_vector = None
    if isinstance(cvss, dict):
        cvss_score = cvss.get("score")
        cvss_vector = cvss.get("vector")

    # Build record for insertion
    return {
        "external_id": external_id,
        "title": entry.get("title", "No title"),
        "description": entry.get("full_description", entry.get("short_description", "")),
        "category": entry.get("record_type"),
        "severity": None,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cwe_list": entry.get("cve_ids", []),
        "cwe_ids": entry.get("cve_ids", []),
        "vendors": None,
        "products": products,
        "affected_products_count": len(products) if products else None,
        "references_count": references_count,
        "references": json.dumps(references),
        "tags": tags,
        "original_source_url": None,
        "actual_url": None,
        "source_name": entry.get("source"),
        "published_date": published_date,
        "last_updated_from_source": modified_date,
        "ingested_at": ingested_at,
        "data_version": None,
        "metadata": json.dumps(entry),
        "source": entry.get("source")
    }

# ===============================
# 🚀 Main
# ===============================
def main():
    print("[*] Connecting to database...")
    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()

    with open(JSON_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    print(f"[*] Loaded {len(data)} records from {JSON_FILE}")

    batch_size = 1000
    batch = []
    total_inserted = 0

    for entry in data:
        record = parse_record(entry)
        batch.append(record)

        if len(batch) >= batch_size:
            execute_batch(cursor, INSERT_QUERY, batch)
            conn.commit()
            total_inserted += len(batch)
            print(f"[+] Inserted {total_inserted} records...")
            batch = []

    # Final flush
    if batch:
        execute_batch(cursor, INSERT_QUERY, batch)
        conn.commit()
        total_inserted += len(batch)

    print(f"[✅] Ingestion complete. Total inserted: {total_inserted}")

    cursor.close()
    conn.close()

if __name__ == "__main__":
    main()

import os
import glob
import json
import datetime
import psycopg2
from psycopg2.extras import Json

# =======================
# 🛠 PostgreSQL Configuration
# =======================
DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "Threat-Intelligence-Database-Schema",
    "user": "postgres",
    "password": "root@123"
}

# =======================
# 📂 CIRCL JSON directory
# =======================
CIRCL_JSON_DIR = r"E:\Threat-Intelligence-Project\ALL-JSONS"

# =======================
# ⚡ Utility Functions
# =======================

def find_latest_circl_json():
    """Find the latest CIRCLE JSON file in CIRCL_JSON_DIR."""
    print(f"🔍 Looking for CIRCL JSON files in: {CIRCL_JSON_DIR}")
    pattern = os.path.join(CIRCL_JSON_DIR, "circl_cve_data*.json")
    files = glob.glob(pattern)
    print(f"📝 Files found: {files}")
    if not files:
        print("❌ No CIRCL JSON files found.")
        return None
    latest_file = max(files, key=os.path.getctime)
    print(f"✅ Latest CIRCL JSON: {latest_file}")
    return latest_file


def parse_timestamp(ts_str):
    """Convert ISO timestamp strings safely."""
    if not ts_str:
        return None
    try:
        return datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return None


def extract_cvss_info(raw_data):
    """
    Extracts CVSS v4.0, v3.1, v3.0, v2.0 and Red Hat fields if present.
    Returns: (score, vector, severity, all_versions_dict)
    """
    possible_paths = [
        raw_data.get("containers", {}).get("cna", {}).get("metrics", []),
        raw_data.get("document", {}).get("containers", {}).get("cna", {}).get("metrics", []),
    ]

    all_cvss = {}
    selected = (None, None, None)

    # 1️⃣ Standard CVSS metrics
    for metrics in possible_paths:
        if not metrics:
            continue
        for metric in metrics:
            for key, val in metric.items():
                if key.lower().startswith("cvss") and isinstance(val, dict):
                    version = val.get("version") or key
                    all_cvss[version] = {
                        "baseScore": val.get("baseScore"),
                        "baseSeverity": val.get("baseSeverity"),
                        "vectorString": val.get("vectorString")
                    }

    # 2️⃣ Red Hat advisory CVSS3 fields
    if "cvss3" in raw_data:
        cvss3 = raw_data["cvss3"]
        all_cvss["3.1"] = {
            "baseScore": cvss3.get("cvss3_base_score"),
            "baseSeverity": cvss3.get("cvss3_base_severity") or raw_data.get("impact"),
            "vectorString": cvss3.get("cvss3_scoring_vector")
        }

    # 3️⃣ Fallback to 'impact' field if no CVSS is found
    if "impact" in raw_data and not all_cvss:
        all_cvss["impact"] = {
            "baseScore": None,
            "baseSeverity": raw_data.get("impact"),
            "vectorString": None
        }

    # 🔸 Optional: Normalize Red Hat severity levels
    severity_map = {
        "Low": "Low",
        "Moderate": "Medium",
        "Important": "High",
        "Critical": "Critical"
    }

    # 4️⃣ Choose best available version
    for version in ["4.0", "3.1", "3.0", "2.0", "impact"]:
        for k, v in all_cvss.items():
            if version in k:
                sev = v.get("baseSeverity")
                if sev in severity_map:
                    sev = severity_map[sev]
                selected = (
                    v.get("baseScore"),
                    v.get("vectorString"),
                    sev
                )
                break
        if selected[0] is not None or selected[2] is not None:
            break

    return selected[0], selected[1], selected[2], all_cvss


# =======================
# 🧠 Main Insert Logic
# =======================
def insert_circl_json_to_postgres(json_file_path: str):
    if not os.path.exists(json_file_path):
        print(f"❌ File not found: {json_file_path}")
        return

    with open(json_file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not data:
        print("❌ No CIRCL items found in JSON.")
        return

    print(f"🔄 Loaded {len(data)} CIRCL items from JSON.")

    # 🛢 Connect to PostgreSQL
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        conn.autocommit = True
        cursor = conn.cursor()
        print("✅ Connected to PostgreSQL.")
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return

    insert_query = """
    INSERT INTO "Storing-Threat-Data".cves (
        external_id, source, title, description, category,
        severity, cvss_score, cvss_vector,
        cwe_list, cwe_ids,
        vendors, products, affected_products_count,
        references_count, "references", tags,
        original_source_url, actual_url, source_name,
        published_date, last_updated_from_source,
        ingested_at, data_version, metadata
    )
    VALUES (
        %(external_id)s, %(source)s, %(title)s, %(description)s, %(category)s,
        %(severity)s, %(cvss_score)s, %(cvss_vector)s,
        %(cwe_list)s, %(cwe_ids)s,
        %(vendors)s, %(products)s, %(affected_products_count)s,
        %(references_count)s, %(references)s::jsonb, %(tags)s,
        %(original_source_url)s, %(actual_url)s, %(source_name)s,
        %(published_date)s, %(last_updated_from_source)s,
        %(ingested_at)s, %(data_version)s, %(metadata)s::jsonb
    )
    ON CONFLICT (external_id) DO UPDATE
    SET
        title = EXCLUDED.title,
        description = EXCLUDED.description,
        category = EXCLUDED.category,
        severity = EXCLUDED.severity,
        cvss_score = EXCLUDED.cvss_score,
        cvss_vector = EXCLUDED.cvss_vector,
        cwe_list = EXCLUDED.cwe_list,
        cwe_ids = EXCLUDED.cwe_ids,
        vendors = EXCLUDED.vendors,
        products = EXCLUDED.products,
        affected_products_count = EXCLUDED.affected_products_count,
        references_count = EXCLUDED.references_count,
        "references" = EXCLUDED."references",
        tags = EXCLUDED.tags,
        last_updated_from_source = EXCLUDED.last_updated_from_source,
        ingested_at = EXCLUDED.ingested_at,
        metadata = EXCLUDED.metadata;
    """

    for item in data:
        raw = item.get("raw_data", {})
        external_id = (
            item.get("title")
            or raw.get("cveMetadata", {}).get("cveId")
            or raw.get("document", {}).get("tracking", {}).get("id")
            or f"UNKNOWN-{datetime.datetime.utcnow().timestamp()}"
        )

        # 🧭 Extract CVSS details
        cvss_score, cvss_vector, severity, all_cvss = extract_cvss_info(raw)
        print(f"→ {external_id} | Score: {cvss_score} | Severity: {severity} | Vector: {cvss_vector}")

        # 🔗 References
        references = (
            raw.get("document", {}).get("references")
            or raw.get("containers", {}).get("cna", {}).get("references", [])
        )

        # 🏢 Vendors & Products
        vendors, products = [], []
        affected = raw.get("containers", {}).get("cna", {}).get("affected", [])
        for a in affected:
            if "vendor" in a:
                vendors.append(a["vendor"])
            if "product" in a:
                products.append(a["product"])

        try:
            cursor.execute(insert_query, {
                "external_id": external_id,
                "source": "CIRCL",
                "title": item.get("title") or external_id,
                "description": (
                    item.get("description")
                    or next((d.get("value") for d in raw.get("containers", {}).get("cna", {}).get("descriptions", []) if d.get("lang") == "en"), None)
                ),
                "category": item.get("category", "vulnerability"),
                "severity": severity,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "cwe_list": [d.get("description") for p in raw.get("containers", {}).get("cna", {}).get("problemTypes", []) for d in p.get("descriptions", []) if "description" in d],
                "cwe_ids": [d.get("cweId") for p in raw.get("containers", {}).get("cna", {}).get("problemTypes", []) for d in p.get("descriptions", []) if "cweId" in d],
                "vendors": vendors,
                "products": products,
                "affected_products_count": len(products),
                "references_count": len(references),
                "references": Json(references),
                "tags": item.get("tags", ["CIRCL"]),
                "original_source_url": item.get("original_source_url"),
                "actual_url": item.get("actual_url"),
                "source_name": "CIRCL",
                "published_date": parse_timestamp(raw.get("cveMetadata", {}).get("datePublished")),
                "last_updated_from_source": parse_timestamp(raw.get("cveMetadata", {}).get("dateUpdated")),
                "ingested_at": parse_timestamp(item.get("ingested_at")),
                "data_version": raw.get("dataVersion", "1.0"),
                "metadata": Json({
                    **item,
                    "cvss_all_versions": all_cvss
                })
            })
        except Exception as e:
            print(f"❌ Failed to insert {external_id}: {e}")

    cursor.close()
    conn.close()
    print("✅ All CIRCL items inserted successfully.")


# =======================
# 🚀 Entry Point
# =======================
if __name__ == "__main__":
    latest_file = find_latest_circl_json()
    if latest_file:
        insert_circl_json_to_postgres(latest_file)

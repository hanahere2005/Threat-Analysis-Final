#!/usr/bin/env python3
import os
import json
from datetime import datetime
import psycopg2
from psycopg2.extras import Json

# --- PostgreSQL configuration ---
DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "Threat-Intelligence-Database-Schema",
    "user": "postgres",
    "password": "root@123"
}

# --- Helpers ---
def robust_isoparse(s):
    if not s:
        return None
    try:
        s2 = str(s).strip()
        if s2.endswith("Z"):
            s2 = s2[:-1] + "+00:00"
        return datetime.fromisoformat(s2)
    except Exception:
        return None

def extract_cvss(description):
    import re
    match = re.search(r"CVSS\s*(v\d\.\d)?\s*base\s*score\s*of\s*([\d\.]+)", description, re.IGNORECASE)
    if match:
        try:
            return float(match.group(2))
        except ValueError:
            return None
    return None

def determine_severity(cvss):
    if cvss is None:
        return "Unknown"
    if cvss >= 9.0:
        return "CRITICAL"
    elif cvss >= 7.0:
        return "HIGH"
    elif cvss >= 4.0:
        return "MEDIUM"
    elif cvss > 0:
        return "LOW"
    return "Unknown"

# --- Main insertion ---
def insert_otx(jsonl_path):
    if not os.path.exists(jsonl_path):
        print(f"❌ File not found: {jsonl_path}")
        return

    # load JSONL
    try:
        with open(jsonl_path, "r", encoding="utf-8") as f:
            records = [json.loads(line) for line in f if line.strip()]
    except Exception as e:
        print(f"❌ Failed to load JSONL: {e}")
        return

    print(f"Loaded {len(records)} OTX records.")

    try:
        conn = psycopg2.connect(**DB_CONFIG)
        conn.autocommit = False
        cur = conn.cursor()
        print("✅ Connected to PostgreSQL.")
    except Exception as e:
        print("❌ DB connection failed:", e)
        return

    insert_sql = """
    INSERT INTO "Storing-Threat-Data".cves (
        external_id, title, description, category, severity,
        cvss_score, cvss_vector, cwe_list, cwe_ids,
        vendors, products, affected_products_count,
        references_count, "references", tags,
        original_source_url, actual_url, source_name,
        published_date, last_updated_from_source,
        ingested_at, data_version, metadata
    ) VALUES (
        %(external_id)s, %(title)s, %(description)s, %(category)s, %(severity)s,
        %(cvss_score)s, %(cvss_vector)s, %(cwe_list)s, %(cwe_ids)s,
        %(vendors)s, %(products)s, %(affected_products_count)s,
        %(references_count)s, %(references)s, %(tags)s,
        %(original_source_url)s, %(actual_url)s, %(source_name)s,
        %(published_date)s, %(last_updated_from_source)s,
        %(ingested_at)s, %(data_version)s, %(metadata)s
    )
    ON CONFLICT (external_id) DO UPDATE
    SET
        title = EXCLUDED.title,
        description = EXCLUDED.description,
        severity = EXCLUDED.severity,
        cvss_score = EXCLUDED.cvss_score,
        last_updated_from_source = EXCLUDED.last_updated_from_source,
        metadata = EXCLUDED.metadata;
    """

    inserted, failed = 0, 0

    for item in records:
        try:
            raw = item.get("raw", {})  # fallback if nested
            indicators = raw.get("indicators", []) or item.get("indicators", [])
            references = raw.get("references", [])
            tags = item.get("tags", []) or raw.get("tags", [])

            # external ID / CVE
            cve_id = next((ind.get("indicator") for ind in indicators if ind.get("type", "").upper() == "CVE"), None)
            if not cve_id:
                cve_id = "OTX-" + str(item.get("source_id", "unknown"))

            title = item.get("name") or raw.get("name") or cve_id
            description = item.get("description") or raw.get("description") or "No description available."

            cvss_score = extract_cvss(description) or 0.0
            severity = determine_severity(cvss_score)
            cvss_vector = "N/A"

            # Vendors / Products
            vendors, products = [], []
            if "oracle" in title.lower():
                vendors.append("Oracle")
                products.append("E-Business Suite")
            elif "microsoft" in title.lower():
                vendors.append("Microsoft")
            elif "linux" in title.lower():
                vendors.append("Linux")
            affected_count = max(1, len(products))

            # Dates
            published_date = robust_isoparse(raw.get("created")) or datetime.utcnow()
            last_updated = robust_isoparse(raw.get("modified")) or published_date

            # References
            all_refs = [{"url": r, "source": "AlienVault OTX"} for r in references]
            for ind in indicators:
                all_refs.append({
                    "indicator": ind.get("indicator"),
                    "type": ind.get("type"),
                    "expiration": ind.get("expiration"),
                    "source": "OTX Indicator"
                })

            original_source_url = f"https://otx.alienvault.com/pulse/{item.get('source_id','')}"
            actual_url = f"https://otx.alienvault.com/api/v1/pulses/{item.get('source_id','')}"

            params = {
                "external_id": cve_id,
                "title": title,
                "description": description,
                "category": "vulnerability",
                "severity": severity,
                "cvss_score": float(cvss_score),
                "cvss_vector": cvss_vector,
                "cwe_list": [],
                "cwe_ids": [],
                "vendors": vendors,
                "products": products,
                "affected_products_count": affected_count,
                "references_count": len(all_refs),
                "references": Json(all_refs),
                "tags": tags,
                "original_source_url": original_source_url,
                "actual_url": actual_url,
                "source_name": "AlienVault OTX",
                "published_date": published_date,
                "last_updated_from_source": last_updated,
                "ingested_at": datetime.utcnow(),
                "data_version": "v1",
                "metadata": Json(item)
            }

            cur.execute(insert_sql, params)
            inserted += 1
        except Exception as e:
            failed += 1
            print(f"❌ Failed to insert {item.get('source_id', 'unknown')}: {e}")

    try:
        conn.commit()
    except Exception as e:
        print("❌ Commit failed:", e)
        conn.rollback()

    cur.close()
    conn.close()

    print(f"\n✅ Done. Inserted/Updated: {inserted}, Failed: {failed}")


if __name__ == "__main__":
    jsonl_path = "otx.jsonl"
    insert_otx(jsonl_path)

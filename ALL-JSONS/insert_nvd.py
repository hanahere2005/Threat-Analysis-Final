import os
import glob
import json
import psycopg2
from psycopg2.extras import Json

# PostgreSQL configuration
DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "Threat-Intelligence-Database-Schema",  # <-- replace with your DB name
    "user": "postgres",        # <-- replace with your DB user
    "password": "root@123"
}

def find_latest_enhanced_json():
    """Find the latest nvd_enhanced_data_*.json file in current directory"""
    files = glob.glob("nvd_enhanced_data_*.json")
    if not files:
        print("❌ No enhanced JSON files found.")
        return None
    latest_file = max(files, key=os.path.getctime)
    print(f"✅ Latest enhanced JSON: {latest_file}")
    return latest_file

def insert_nvd_json_to_postgres(json_file_path: str):
    """Insert NVD enhanced JSON into PostgreSQL table"""
    
    if not os.path.exists(json_file_path):
        print(f"❌ File not found: {json_file_path}")
        return
    
    with open(json_file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    cves = data.get("cves", [])
    if not cves:
        print("❌ No CVEs found in JSON.")
        return
    
    print(f"🔄 Loaded {len(cves)} CVEs from JSON.")
    
    # Connect to PostgreSQL
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
        external_id, title, description, category, severity,
        cvss_score, cvss_vector, cwe_list, cwe_ids,
        vendors, products, affected_products_count,
        references_count, "references", tags,
        original_source_url, actual_url, source_name,
        published_date, last_updated_from_source,
        ingested_at, data_version, metadata
    )
    VALUES (
        %(external_id)s, %(title)s, %(description)s, %(category)s, %(severity)s,
        %(cvss_score)s, %(cvss_vector)s, %(cwe_list)s, %(cwe_ids)s,
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
    
    for cve in cves:
        try:
            cursor.execute(insert_query, {
                "external_id": cve.get("external_id"),
                "title": cve.get("title"),
                "description": cve.get("description"),
                "category": cve.get("category"),
                "severity": cve.get("severity"),
                "cvss_score": cve.get("cvss_score"),
                "cvss_vector": cve.get("metadata", {}).get("cvss_vector"),
                "cwe_list": cve.get("metadata", {}).get("cwe_list", []),
                "cwe_ids": cve.get("metadata", {}).get("cwe_ids", []),
                "vendors": cve.get("metadata", {}).get("vendors", []),
                "products": cve.get("metadata", {}).get("products", []),
                "affected_products_count": cve.get("metadata", {}).get("affected_products_count", 0),
                "references_count": cve.get("metadata", {}).get("references_count", 0),
                "references": Json(cve.get("metadata", {}).get("references_sample", [])),
                "tags": cve.get("tags", []),
                "original_source_url": cve.get("original_source_url"),
                "actual_url": cve.get("actual_url"),
                "source_name": cve.get("source_name"),
                "published_date": cve.get("published_date"),
                "last_updated_from_source": cve.get("last_updated_from_source"),
                "ingested_at": cve.get("ingested_at"),
                "data_version": cve.get("data_version"),
                "metadata": Json(cve.get("metadata", {}))
            })
        except Exception as e:
            print(f"❌ Failed to insert {cve.get('external_id')}: {e}")
    
    cursor.close()
    conn.close()
    print("✅ All CVEs inserted successfully.")

if __name__ == "__main__":
    latest_file = find_latest_enhanced_json()
    if latest_file:
        insert_nvd_json_to_postgres(latest_file)

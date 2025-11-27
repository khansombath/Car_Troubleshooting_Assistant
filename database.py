import sqlite3
import os
import json
from datetime import datetime

# Path to SQLite database file
DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data.db')


def get_db_connection():
    """Get a database connection"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row  # Enables column access by name
    return conn


def init_db():
    """Initialize the database with required tables"""
    conn = get_db_connection()
    
    # Facts table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS facts (
            id TEXT PRIMARY KEY,
            description TEXT NOT NULL,
            value BOOLEAN DEFAULT 0,
            tags TEXT,  -- JSON string of tags list
            category TEXT DEFAULT 'uncategorized',
            display_order INTEGER DEFAULT 0, 
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Rules table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY,
            conditions TEXT NOT NULL,  -- JSON string of conditions list
            conclusion TEXT NOT NULL,
            certainty REAL DEFAULT 1.0,
            explain TEXT,
            recommendation TEXT,
            display_order INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Taxonomy table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS taxonomy (
            child TEXT PRIMARY KEY,
            parent TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # History table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,           -- ISO string
            observations TEXT,        -- JSON string
            expanded_obs TEXT,        -- JSON string
            results TEXT,             -- JSON string
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()


def migrate_json_data():
    """Migrate existing JSON data in Data/ folder to SQLite (only if DB empty)"""
    # Check if database is already populated
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if facts table has data
    cursor.execute("SELECT COUNT(*) FROM facts")
    if cursor.fetchone()[0] > 0:
        conn.close()
        return  # Database already populated
    
    base_dir = os.path.dirname(os.path.abspath(__file__))

    # --- Migrate facts.json ---
    facts_path = os.path.join(base_dir, 'Data', 'facts.json')
    if os.path.exists(facts_path):
        with open(facts_path, 'r', encoding='utf-8') as f:
            facts_data = json.load(f)
            for index, fact in enumerate(facts_data):
                cursor.execute('''
                    INSERT OR REPLACE INTO facts (id, description, value, tags, category, display_order)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    fact['id'],
                    fact.get('description', ''),
                    1 if fact.get('value', False) else 0,
                    json.dumps(fact.get('tags', [])),
                    fact.get('category', 'uncategorized'),
                    index  # ADD display_order value
                ))
    
    # --- Migrate rules.json ---
    rules_path = os.path.join(base_dir, 'Data', 'rules.json')
    if os.path.exists(rules_path):
        with open(rules_path, 'r', encoding='utf-8') as f:
            rules_data = json.load(f)
            for index, rule in enumerate(rules_data):
                cursor.execute('''
                    INSERT OR REPLACE INTO rules (id, conditions, conclusion, certainty, explain, recommendation, display_order)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    rule['id'],
                    json.dumps(rule.get('conditions', [])),
                    rule.get('conclusion', ''),
                    rule.get('certainty', 1.0),
                    rule.get('explain', ''),
                    rule.get('recommendation', ''),
                    index  # ADD display_order value
                ))
    
    # --- Migrate taxonomy.json ---
    taxonomy_path = os.path.join(base_dir, 'Data', 'taxonomy.json')
    if os.path.exists(taxonomy_path):
        with open(taxonomy_path, 'r', encoding='utf-8') as f:
            taxonomy_data = json.load(f)
            parent_data = taxonomy_data.get('parent', {})
            for child, parent in parent_data.items():
                cursor.execute('''
                    INSERT OR REPLACE INTO taxonomy (child, parent)
                    VALUES (?, ?)
                ''', (child, parent))
    
    # --- Migrate history.json ---
    history_path = os.path.join(base_dir, 'Data', 'history.json')
    if os.path.exists(history_path):
        with open(history_path, 'r', encoding='utf-8') as f:
            history_data = json.load(f)
            for item in history_data:
                cursor.execute('''
                    INSERT INTO history (id, timestamp, observations, expanded_obs, results)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    item.get('id'),
                    item.get('timestamp'),
                    json.dumps(item.get('observations', {})),
                    json.dumps(item.get('expanded_obs', {})),
                    json.dumps(item.get('results', []))
                ))
    
    conn.commit()
    conn.close()


# Initialize database when module is imported
init_db()
migrate_json_data()

# ============================================================
#                      FACTS FUNCTIONS
# ============================================================

def get_all_facts():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM facts ORDER BY display_order, id").fetchall()
    conn.close()
    
    facts = []
    for row in rows:
        facts.append({
            "id": row["id"],
            "description": row["description"],
            "value": bool(row["value"]),
            "tags": json.loads(row["tags"]) if row["tags"] else [],
            "category": row["category"] or "uncategorized"
        })
    
    # FIX: Natural sorting for fact IDs (f1, f2, f3, ..., f10, f11, ..., f21)
    def natural_sort_key(fact):
        fact_id = fact["id"]
        # Extract the number part after 'f' and convert to integer for proper numerical sorting
        if fact_id.startswith('f') and fact_id[1:].isdigit():
            return int(fact_id[1:])
        else:
            return float('inf')  # Put non-numeric IDs at the end
    
    facts.sort(key=natural_sort_key)
    return facts


def get_fact(fid):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM facts WHERE id = ?", (fid,)).fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row["id"],
        "description": row["description"],
        "value": bool(row["value"]),
        "tags": json.loads(row["tags"]) if row["tags"] else [],
        "category": row["category"] or "uncategorized"
    }


def save_fact(fact):
    """
    Insert or update a fact.
    fact = {id, description, value, tags, category}
    """
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO facts (id, description, value, tags, category, updated_at)
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(id) DO UPDATE SET
            description = excluded.description,
            value       = excluded.value,
            tags        = excluded.tags,
            category    = excluded.category,
            updated_at  = CURRENT_TIMESTAMP
    """, (
        fact["id"],
        fact.get("description", ""),
        1 if fact.get("value", False) else 0,
        json.dumps(fact.get("tags", [])),
        fact.get("category", "uncategorized")
    ))
    conn.commit()
    conn.close()


def delete_fact(fid):
    conn = get_db_connection()
    conn.execute("DELETE FROM facts WHERE id = ?", (fid,))
    conn.commit()
    conn.close()


# ============================================================
#                      RULES FUNCTIONS
# ============================================================

def get_all_rules():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM rules ORDER BY display_order, id").fetchall()
    conn.close()
    
    rules = []
    for row in rows:
        rules.append({
            "id": row["id"],
            "conditions": json.loads(row["conditions"]) if row["conditions"] else [],
            "conclusion": row["conclusion"],
            "certainty": float(row["certainty"]) if row["certainty"] is not None else 1.0,
            "explain": row["explain"] or "",
            "recommendation": row["recommendation"] or "",
        })
    
    # FIX: Natural sorting for rule IDs (r1, r2, r3, ..., r10, r11, ...)
    def natural_sort_key(rule):
        rule_id = rule["id"]
        # Extract the number part after 'r' and convert to integer for proper numerical sorting
        if rule_id.startswith('r') and rule_id[1:].isdigit():
            return int(rule_id[1:])
        else:
            return float('inf')  # Put non-numeric IDs at the end
    
    rules.sort(key=natural_sort_key)
    return rules


def save_rule(rule):
    """
    Insert or update a rule.
    rule = {id, conditions, conclusion, certainty, explain, recommendation}
    """
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO rules (id, conditions, conclusion, certainty, explain, recommendation, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(id) DO UPDATE SET
            conditions    = excluded.conditions,
            conclusion    = excluded.conclusion,
            certainty     = excluded.certainty,
            explain       = excluded.explain,
            recommendation= excluded.recommendation,
            updated_at    = CURRENT_TIMESTAMP
    """, (
        rule["id"],
        json.dumps(rule.get("conditions", [])),
        rule.get("conclusion", ""),
        float(rule.get("certainty", 1.0)),
        rule.get("explain", ""),
        rule.get("recommendation", "")
    ))
    conn.commit()
    conn.close()


def delete_rule(rid):
    conn = get_db_connection()
    conn.execute("DELETE FROM rules WHERE id = ?", (rid,))
    conn.commit()
    conn.close()


# ============================================================
#                    TAXONOMY FUNCTIONS
# ============================================================

def get_taxonomy():
    """
    Return taxonomy as a dict: {"parent": {child: parent, ...}}
    Always safe: if empty, returns {"parent": {}}.
    """
    conn = get_db_connection()
    rows = conn.execute("SELECT child, parent FROM taxonomy").fetchall()
    conn.close()
    
    parent_map = {}
    for row in rows:
        parent_map[row["child"]] = row["parent"]
    
    return {"parent": parent_map}


def save_taxonomy(taxonomy):
    """
    Replace entire taxonomy table with provided taxonomy dict.
    taxonomy = {"parent": {child: parent, ...}}
    """
    parent_map = taxonomy.get("parent", {}) if isinstance(taxonomy, dict) else {}
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Clear existing data
    cur.execute("DELETE FROM taxonomy")
    
    # Insert new data
    for child, parent in parent_map.items():
        cur.execute("""
            INSERT OR REPLACE INTO taxonomy (child, parent)
            VALUES (?, ?)
        """, (child, parent))
    
    conn.commit()
    conn.close()


def update_taxonomy_relationship(child, parent):
    """
    Set or update a single child -> parent relationship.
    Used by update_taxonomy_with_fact and other app routes.
    """
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO taxonomy (child, parent, created_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(child) DO UPDATE SET
            parent = excluded.parent
    """, (child, parent))
    conn.commit()
    conn.close()


def delete_taxonomy_relationship(child):
    conn = get_db_connection()
    conn.execute("DELETE FROM taxonomy WHERE child = ?", (child,))
    conn.commit()
    conn.close()


# ============================================================
#                    HISTORY FUNCTIONS
# ============================================================

def get_history():
    """
    Return a list of history items:
    {id, timestamp, observations, expanded_obs, results}
    """
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT id, timestamp, observations, expanded_obs, results
        FROM history
        ORDER BY id ASC  -- ASCENDING ORDER (1, 2, 3...)
    """).fetchall()
    conn.close()
    
    items = []
    for row in rows:
        items.append({
            "id": row["id"],
            "timestamp": row["timestamp"],
            "observations": json.loads(row["observations"]) if row["observations"] else {},
            "expanded_obs": json.loads(row["expanded_obs"]) if row["expanded_obs"] else {},
            "results": json.loads(row["results"]) if row["results"] else [],
        })
    return items

def save_history_item(item):
    """
    Insert a history item, return new id.
    item = {timestamp, observations, expanded_obs, results}
    """
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO history (timestamp, observations, expanded_obs, results)
        VALUES (?, ?, ?, ?)
    """, (
        item.get("timestamp"),
        json.dumps(item.get("observations", {})),
        json.dumps(item.get("expanded_obs", {})),
        json.dumps(item.get("results", [])),
    ))
    conn.commit()
    new_id = cur.lastrowid
    conn.close()
    return new_id


def delete_history_item(hid):
    conn = get_db_connection()
    conn.execute("DELETE FROM history WHERE id = ?", (hid,))
    conn.commit()
    conn.close()
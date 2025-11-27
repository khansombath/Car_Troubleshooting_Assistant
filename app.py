from flask import Flask, jsonify, request, render_template, redirect, url_for, flash, session
import json
import os
import importlib.util
from jsonschema import validate, ValidationError
from datetime import datetime

# Import database functions
from database import (
    get_all_facts, get_fact, save_fact, delete_fact,
    get_all_rules, save_rule, delete_rule,
    get_taxonomy, save_taxonomy, update_taxonomy_relationship, delete_taxonomy_relationship,
    get_history, save_history_item, delete_history_item
)

# --- Setup ---
APP_ROOT = os.path.dirname(os.path.abspath(__file__))

# Path to the schemas file
SCHEMAS_FILE = os.getenv(
    "SCHEMAS_FILE",
    os.path.join(APP_ROOT, "schemas", "schemas.py")
)

def _load_schemas_from_file(path: str):
    """Dynamically load facts/rules schemas from a Python file."""
    spec = importlib.util.spec_from_file_location("external_schemas", path)
    if spec is None or spec.loader is None:
        raise FileNotFoundError(f"Cannot load schemas module from: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        return module.facts_array_schema, module.rules_array_schema
    except AttributeError as e:
        raise AttributeError(
            f"'{path}' must expose 'facts_array_schema' and 'rules_array_schema'."
        ) from e

try:
    facts_array_schema, rules_array_schema = _load_schemas_from_file(SCHEMAS_FILE)
except Exception as e:
    raise RuntimeError(
        f"Failed to load JSON Schemas from '{SCHEMAS_FILE}': {e}.\n"
        "Ensure schemas/schemas.py exists and defines the required schemas."
    )

# --- Helpers ---
def clamp01(x) -> float:
    try:
        return max(0.0, min(1.0, float(x)))
    except Exception:
        return 0.0

def error_payload(e: ValidationError, filelabel: str):
    return {
        "file": filelabel,
        "error": e.message,
        "path": list(e.path),
        "schema_path": list(e.schema_path)
    }

# --- Taxonomy helpers ---
def get_taxonomy_data():
    """Get fresh taxonomy data from database"""
    taxonomy = get_taxonomy()
    return taxonomy.get("parent", {})

def ancestors(concept: str):
    """Yield all ancestors of a concept using PARENT map."""
    parent_map = get_taxonomy_data()
    seen = set()
    cur = concept
    while cur in parent_map:
        parent = parent_map[cur]
        if parent in seen:
            break
        seen.add(parent)
        yield parent
        cur = parent

def expand_observations(obs_conf: dict) -> dict:
    """Propagate evidence up the taxonomy tree."""
    parent_map = get_taxonomy_data()
    if not parent_map:
        return obs_conf

    expanded = dict(obs_conf)
    for fid, c in list(obs_conf.items()):
        for anc in ancestors(fid):
            expanded[anc] = max(expanded.get(anc, 0.0), c)
    return expanded

def evaluate_rule(rule: dict, obs_conf: dict):
    """Return (fired: bool, confidence: float) for a rule."""
    cond_ids = rule.get("conditions", [])
    if not cond_ids:
        return (False, 0.0)

    cond_scores = []
    for cid in cond_ids:
        c = clamp01(obs_conf.get(cid, 0.0))
        cond_scores.append(c)

    if min(cond_scores) <= 0.0:
        return (False, 0.0)

    base = min(cond_scores)
    cf = clamp01(rule.get("certainty", 1.0))
    return (True, base * cf)

def get_taxonomy_stats():
    """Get comprehensive taxonomy statistics - SAFE VERSION"""
    try:
        facts = get_all_facts()
        taxonomy = get_taxonomy_data()
        
        if not facts or not taxonomy:
            return {
                "total_facts": 0,
                "facts_in_taxonomy": 0,
                "missing_facts": 0,
                "orphaned_facts": 0,
                "categorized_facts": 0,
                "uncategorized_facts": 0
            }

        all_fact_ids = {f["id"] for f in facts if "id" in f}
        taxonomy_fact_ids = set(taxonomy.keys())

        missing_facts = all_fact_ids - taxonomy_fact_ids
        orphaned_facts = taxonomy_fact_ids - all_fact_ids
        
        categorized_facts = [fid for fid in taxonomy_fact_ids
                             if taxonomy.get(fid) != "uncategorized"]
        uncategorized_facts = [fid for fid in taxonomy_fact_ids
                               if taxonomy.get(fid) == "uncategorized"]

        return {
            "total_facts": len(all_fact_ids),
            "facts_in_taxonomy": len(taxonomy_fact_ids & all_fact_ids),
            "missing_facts": len(missing_facts),
            "orphaned_facts": len(orphaned_facts),
            "categorized_facts": len(categorized_facts),
            "uncategorized_facts": len(uncategorized_facts)
        }
    except Exception as e:
        print(f"ERROR in get_taxonomy_stats: {e}")
        return {
            "total_facts": 0, "facts_in_taxonomy": 0, "missing_facts": 0,
            "orphaned_facts": 0, "categorized_facts": 0, "uncategorized_facts": 0
        }

def update_taxonomy_with_fact(fact_id, category):
    """Force update taxonomy with fact-category relationship"""
    try:
        taxonomy_before = get_taxonomy_data()
        print(f"📊 Before update - {fact_id} was: {taxonomy_before.get(fact_id, 'NOT_FOUND')}")

        update_taxonomy_relationship(fact_id, category)
        print(f"✅ Set {fact_id} -> {category} in taxonomy")

        category_hierarchy = {
            'electrical_symptom': 'electrical_issue',
            'starting_symptom': 'starting_issue',
            'running_symptom': 'running_issue',
            'fuel_symptom': 'fuel_issue',
            'environment_context': 'engine_problem',
            'uncategorized': 'engine_problem',
            'electrical_issue': 'engine_problem',
            'starting_issue': 'engine_problem',
            'running_issue': 'engine_problem',
            'fuel_issue': 'engine_problem',
            'diagnosed_issue': 'engine_problem'
        }

        for cat, parent in category_hierarchy.items():
            if cat not in taxonomy_before:
                update_taxonomy_relationship(cat, parent)
                print(f"🏗️ Added hierarchy: {cat} -> {parent}")

        taxonomy_after = get_taxonomy_data()
        final_value = taxonomy_after.get(fact_id, 'STILL_MISSING')
        print(f"🔍 Verification: {fact_id} -> {final_value}")

        if final_value != category:
            print(f"🚨 CRITICAL: Taxonomy update failed! Expected {category}, got {final_value}")

    except Exception as e:
        print(f"❌ Error in update_taxonomy_with_fact: {e}")

# --- Flask app & routes ---
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret")

@app.route("/")
def home():
    stats = get_taxonomy_stats()
    facts_count = len(get_all_facts())
    rules_count = len(get_all_rules())
    return render_template(
        "home.html",
        facts_count=facts_count,
        rules_count=rules_count,
        stats=stats
    )

# --- Facts Routes ---
@app.get("/facts")
def facts_list():
    # ALWAYS get fresh data from database
    fresh_facts = get_all_facts()
    return render_template("facts_list.html", facts=fresh_facts)

@app.route("/facts/new", methods=["GET", "POST"])
def facts_new():
    if request.method == "POST":
        fid = (request.form.get("id") or "").strip()
        description = (request.form.get("description") or "").strip()
        value = request.form.get("value") == "on"
        tags_raw = request.form.get("tags") or ""
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
        category = request.form.get("category", "uncategorized")

        if not fid:
            flash("ID is required", "danger")
            return render_template("fact_form.html", mode="new", fact={
                "id": fid, "description": description, "value": value, 
                "tags": tags, "category": category
            })

        existing_fact = get_fact(fid)
        if existing_fact:
            flash(f"Fact ID '{fid}' already exists", "danger")
            return render_template("fact_form.html", mode="new", fact={
                "id": fid, "description": description, "value": value, 
                "tags": tags, "category": category
            })

        new_item = {
            "id": fid, "description": description, "value": bool(value), 
            "tags": tags, "category": category
        }

        try:
            all_facts = get_all_facts()
            test_facts = all_facts + [new_item]
            validate(test_facts, facts_array_schema)
            save_fact(new_item)
            update_taxonomy_with_fact(fid, category)
        except ValidationError as e:
            flash(f"Validation error: {e.message}", "danger")
            return render_template("fact_form.html", mode="new", fact=new_item)

        flash(f"Fact '{fid}' created with category '{category}'", "success")
        return redirect(url_for("facts_list"))

    return render_template("fact_form.html", mode="new", fact=None)

@app.route("/facts/<fid>/edit", methods=["GET", "POST"])
def facts_edit(fid):
    # Get fresh data for the specific fact
    fact = get_fact(fid)
    if not fact:
        flash("Fact not found", "warning")
        return redirect(url_for("facts_list"))

    if request.method == "POST":
        description = (request.form.get("description") or "").strip()
        value = request.form.get("value") == "on"
        tags_raw = request.form.get("tags") or ""
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
        category = request.form.get("category", "uncategorized")

        updated_fact = {
            "id": fid, "description": description, "value": bool(value), 
            "tags": tags, "category": category
        }

        try:
            all_facts = get_all_facts()
            test_facts = [updated_fact if f["id"] == fid else f for f in all_facts]
            validate(test_facts, facts_array_schema)
            save_fact(updated_fact)
            update_taxonomy_with_fact(fid, category)
        except ValidationError as e:
            flash(f"Validation error: {e.message}", "danger")
            return render_template("fact_form.html", mode="edit", fact=updated_fact)

        flash(f"Fact '{fid}' updated with category '{category}'", "success")
        return redirect(url_for("facts_list"))

    return render_template("fact_form.html", mode="edit", fact=fact)

@app.post("/facts/<fid>/delete")
def facts_delete(fid):
    delete_fact(fid)
    delete_taxonomy_relationship(fid)
    flash(f"Fact '{fid}' deleted from facts and taxonomy", "success")
    return redirect(url_for("facts_list"))

@app.route("/facts/toggle/<fid>", methods=["POST"])
def facts_toggle(fid):
    try:
        fact = get_fact(fid)
        if fact:
            fact["value"] = not fact["value"]
            save_fact(fact)
            flash(f'Fact "{fid}" updated to {fact["value"]}', 'success')
        else:
            flash(f'Fact "{fid}" not found', 'error')
    except Exception as e:
        flash(f'Error toggling fact: {str(e)}', 'danger')
    return redirect(url_for('facts_list'))

# --- Rules Routes ---
@app.get("/rules")
def rules_list():
    fresh_rules = get_all_rules()
    return render_template("rules_list.html", rules=fresh_rules)

@app.route("/rules/new", methods=["GET", "POST"])
def rules_new():
    if request.method == "POST":
        rid = (request.form.get("id") or "").strip()
        conditions_raw = (request.form.get("conditions") or "").strip()
        conclusion = (request.form.get("conclusion") or "").strip()
        certainty = clamp01(request.form.get("certainty") or "1.0")
        explain = (request.form.get("explain") or "").strip()
        recommendation = (request.form.get("recommendation") or "").strip()
        conditions = [c.strip() for c in conditions_raw.split(",") if c.strip()]
        
        new_item = {
            "id": rid, "conditions": conditions, "conclusion": conclusion,
            "certainty": certainty, "explain": explain, "recommendation": recommendation
        }

        if not rid:
            flash("ID is required", "danger")
            return render_template("rule_form.html", mode="new", rule=new_item)

        all_rules = get_all_rules()
        if any(r.get("id") == rid for r in all_rules):
            flash(f"Rule ID '{rid}' already exists", "danger")
            return render_template("rule_form.html", mode="new", rule=new_item)

        try:
            test_rules = all_rules + [new_item]
            validate(test_rules, rules_array_schema)
            save_rule(new_item)
        except ValidationError as e:
            flash(f"Validation error: {e.message}", "danger")
            return render_template("rule_form.html", mode="new", rule=new_item)

        flash("Rule created", "success")
        return redirect(url_for("rules_list"))

    return render_template("rule_form.html", mode="new", rule={"certainty": 0.8})

@app.route("/rules/<rid>/edit", methods=["GET", "POST"])
def rules_edit(rid):
    all_rules = get_all_rules()
    rule = next((r for r in all_rules if r.get("id") == rid), None)
    if not rule:
        flash("Rule not found", "warning")
        return redirect(url_for("rules_list"))

    if request.method == "POST":
        conditions_raw = (request.form.get("conditions") or "").strip()
        conclusion = (request.form.get("conclusion") or "").strip()
        certainty = clamp01(request.form.get("certainty") or "1.0")
        explain = (request.form.get("explain") or "").strip()
        recommendation = (request.form.get("recommendation") or "").strip()

        updated = {
            "id": rule["id"],
            "conditions": [c.strip() for c in conditions_raw.split(",") if c.strip()],
            "conclusion": conclusion, "certainty": certainty,
            "explain": explain, "recommendation": recommendation
        }

        try:
            test_rules = [updated if r["id"] == rule["id"] else r for r in all_rules]
            validate(test_rules, rules_array_schema)
            save_rule(updated)
        except ValidationError as e:
            flash(f"Validation error: {e.message}", "danger")
            return render_template("rule_form.html", mode="edit", rule=updated)

        flash("Rule updated", "success")
        return redirect(url_for("rules_list"))

    return render_template("rule_form.html", mode="edit", rule=rule)

@app.post("/rules/<rid>/delete")
def rules_delete(rid):
    delete_rule(rid)
    flash("Rule deleted", "success")
    return redirect(url_for("rules_list"))

# --- Taxonomy Routes ---
@app.get("/taxonomy")
def taxonomy_view():
    stats = get_taxonomy_stats()
    taxonomy_data = get_taxonomy_data()
    facts_data = get_all_facts()
    fact_ids_in_taxonomy = [fid for fid in taxonomy_data.keys() if fid.startswith('f')]
    raw_json = json.dumps({"parent": taxonomy_data}, indent=2, ensure_ascii=False)
    return render_template("taxonomy.html",
                         taxonomy={"parent": taxonomy_data}, raw_json=raw_json, stats=stats,
                         facts=facts_data, fact_ids_in_taxonomy=fact_ids_in_taxonomy)

@app.post("/taxonomy/add_missing_facts")
def taxonomy_add_missing_facts():
    try:
        facts_data = get_all_facts()
        taxonomy_data = get_taxonomy_data()
        missing_count = 0
        added_facts = []
        for fact in facts_data:
            fid = fact["id"]
            if fid not in taxonomy_data:
                update_taxonomy_relationship(fid, "uncategorized")
                missing_count += 1
                added_facts.append(fid)
        
        if missing_count > 0:
            flash(f"✅ Added {missing_count} facts to taxonomy: {', '.join(added_facts)}", "success")
        else:
            flash("ℹ️ All facts are already in taxonomy", "info")
    except Exception as e:
        flash(f"❌ Error adding missing facts: {str(e)}", "danger")
    return redirect(url_for("taxonomy_view"))

@app.post("/taxonomy/add_rule_conclusions")
def taxonomy_add_rule_conclusions():
    try:
        rules_data = get_all_rules()
        facts_data = get_all_facts()
        taxonomy_data = get_taxonomy_data()
        added_count = 0
        added_conclusions = []
        for rule in rules_data:
            conclusion = rule["conclusion"]
            if (not any(f["id"] == conclusion for f in facts_data) and 
                conclusion not in taxonomy_data):
                update_taxonomy_relationship(conclusion, "diagnosed_issue")
                added_count += 1
                added_conclusions.append(conclusion)
        
        if "diagnosed_issue" not in taxonomy_data:
            update_taxonomy_relationship("diagnosed_issue", "engine_problem")

        if added_count > 0:
            flash(f"✅ Added {added_count} rule conclusions to taxonomy: {', '.join(added_conclusions)}", "success")
        else:
            flash("ℹ️ All rule conclusions are already in taxonomy", "info")
    except Exception as e:
        flash(f"❌ Error adding rule conclusions: {e}", "danger")
    return redirect(url_for("taxonomy_view"))

@app.post("/taxonomy")
def taxonomy_save():
    raw = request.form.get("raw_json") or "{}"
    try:
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("Taxonomy must be a JSON object (dictionary).")
        if "parent" in parsed and not isinstance(parsed["parent"], dict):
            raise ValueError("taxonomy.parent must be a JSON object (dictionary).")
        save_taxonomy(parsed)
        flash("Taxonomy saved", "success")
    except Exception as e:
        flash(f"Failed to save taxonomy: {e}", "danger")
        taxonomy_data = get_taxonomy_data()
        return render_template("taxonomy.html", taxonomy={"parent": taxonomy_data}, raw_json=raw)
    return redirect(url_for("taxonomy_view"))

@app.route("/update_fact_category", methods=["POST"])
def update_fact_category():
    try:
        fact_id = request.form.get("fact_id")
        category = request.form.get("category")
        if not fact_id:
            flash("Fact ID is required", "danger")
            return redirect(url_for("taxonomy_view"))
        
        if category:
            update_taxonomy_relationship(fact_id, category)
        else:
            delete_taxonomy_relationship(fact_id)
        
        flash(f"Updated category for fact {fact_id}", "success")
    except Exception as e:
        flash(f"Error updating category: {str(e)}", "danger")
    return redirect(url_for("taxonomy_view"))

@app.route("/sync_all_categories")
def sync_all_categories():
    try:
        facts_data = get_all_facts()
        updated_count = 0
        for fact in facts_data:
            fact_id = fact['id']
            category = fact.get('category', 'uncategorized')
            update_taxonomy_with_fact(fact_id, category)
            updated_count += 1
        flash(f"✅ Synced {updated_count} facts to taxonomy", "success")
    except Exception as e:
        flash(f"❌ Error syncing categories: {e}", "danger")
    return redirect(url_for('taxonomy_view'))

# --- Inference Routes ---
@app.route("/infer", methods=["GET", "POST"])
def infer():
    facts_data = get_all_facts()
    rules_data = get_all_rules()
    active_facts = [fact for fact in facts_data if fact.get("value", False)]
    
    if request.method == "POST":
        try:
            obs_conf = {}
            for fact in active_facts:
                fid = fact["id"]
                confidence_str = request.form.get(f"conf_{fid}", "0.0")
                try:
                    confidence = clamp01(float(confidence_str))
                    obs_conf[fid] = confidence
                except ValueError:
                    obs_conf[fid] = 0.0

            expanded_obs = expand_observations(obs_conf)
            results = []
            for rule in rules_data:
                fired, confidence = evaluate_rule(rule, expanded_obs)
                if fired:
                    results.append({
                        "rule_id": rule["id"], "conclusion": rule["conclusion"],
                        "confidence": confidence, "explanation": rule.get("explain", ""),
                        "triggered_conditions": rule["conditions"],
                        "recommendation": rule.get("recommendation", ""),
                        "severity": rule.get("severity", "medium"),
                    })

            results.sort(key=lambda x: x["confidence"], reverse=True)
            session['obs_conf'] = obs_conf
            session['results'] = results
            session['expanded_obs'] = expanded_obs
            session.modified = True

            try:
                history_item = {
                    "timestamp": datetime.now().isoformat(timespec="seconds"),
                    "observations": obs_conf, "expanded_obs": expanded_obs, "results": results
                }
                history_id = save_history_item(history_item)
                flash(f"Diagnosis completed and saved to history (ID: {history_id})", "success")
            except Exception as hist_e:
                flash("Diagnosis completed but failed to save to history", "warning")

            return render_template("infer.html", facts=active_facts, obs_conf=obs_conf,
                                 results=results, expanded_obs=expanded_obs)
            
        except Exception as e:
            flash(f"Inference error: {str(e)}", "danger")
            return redirect(url_for("infer"))
    
    obs_conf = session.get('obs_conf', {})
    results = session.get('results', [])
    expanded_obs = session.get('expanded_obs', {})
    return render_template("infer.html", facts=active_facts, results=results, 
                         obs_conf=obs_conf, expanded_obs=expanded_obs)

@app.route("/reset_inference", methods=["POST"])
def reset_inference():
    session.pop('obs_conf', None)
    session.pop('results', None)
    session.pop('expanded_obs', None)
    session.modified = True
    flash("All confidence values and results have been reset", "success")
    return redirect(url_for("infer"))

# --- History Routes ---
@app.route("/history")
def history_list():
    try:
        items = get_history()
        if items is None:
            items = []
            
        items = sorted(items, key=lambda x: x.get("id", 0))

        processed_items = []
        for item in items:
            processed_item = dict(item)
            
            if processed_item.get("timestamp"):
                processed_item["formatted_timestamp"] = processed_item["timestamp"].replace('T', ' ')
            else:
                processed_item["formatted_timestamp"] = "Unknown time"
            
            if processed_item.get("results"):
                sorted_results = sorted(processed_item["results"], key=lambda r: r.get("confidence", 0), reverse=True)
                if sorted_results:
                    top = sorted_results[0]
                    processed_item["top_conclusion"] = top.get("conclusion", "Unknown")
                    confidence_value = top.get("confidence", 0)
                    confidence_value = max(0.0, min(1.0, float(confidence_value)))
                    processed_item["top_confidence"] = int(confidence_value * 100)
                else:
                    processed_item["top_conclusion"] = "No conclusions"
                    processed_item["top_confidence"] = 0
            else:
                processed_item["top_conclusion"] = "No diagnosis results"
                processed_item["top_confidence"] = 0
            
            processed_items.append(processed_item)

        return render_template("history_list.html", items=processed_items)
    
    except Exception as e:
        print(f"ERROR in history_list: {e}")
        flash("Error loading history", "danger")
        return render_template("history_list.html", items=[])

@app.route("/history/<int:hid>")
def history_detail(hid):
    items = get_history()
    item = next((x for x in items if x.get("id") == hid), None)
    if not item:
        flash("History item not found", "warning")
        return redirect(url_for("history_list"))
    return render_template("history_detail.html", item=item)

@app.route("/history/delete/<int:hid>", methods=["POST"])
def delete_history(hid):
    delete_history_item(hid)
    flash(f"History item {hid} deleted", "success")
    return redirect(url_for("history_list"))

# --- Other Routes ---
@app.get("/readme")
def readme():
    return render_template("README.html")

@app.get("/debug")
def debug_stats():
    stats = get_taxonomy_stats()
    facts_count = len(get_all_facts())
    taxonomy_data = get_taxonomy_data()
    return jsonify({
        "stats": stats,
        "facts_count": facts_count,
        "taxonomy_keys": list(taxonomy_data.keys())[:5] if taxonomy_data else "No taxonomy"
    })

@app.route('/debug_taxonomy')
def debug_taxonomy():
    facts_data = get_all_facts()
    taxonomy_data = get_taxonomy_data()
    result = "<h1>Taxonomy Debug Info</h1>"
    result += "<h2>Facts and their categories:</h2>"
    for fact in facts_data:
        fact_id = fact['id']
        fact_category = fact.get('category', 'NO_CATEGORY_IN_FACT')
        taxonomy_category = taxonomy_data.get(fact_id, 'NOT_IN_TAXONOMY')
        result += f"<p>{fact_id}: fact_category='{fact_category}', taxonomy_category='{taxonomy_category}'</p>"
    result += "<h2>Full Taxonomy:</h2>"
    for key, value in taxonomy_data.items():
        result += f"<p>{key} -> {value}</p>"
    return result

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=os.getenv("FLASK_DEBUG") == "1")
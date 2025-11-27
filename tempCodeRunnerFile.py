@app.route("/history/<int:hid>")
def history_detail(hid):
    items = get_history()
    item = next((x for x in items if x.get("id") == hid), None)
    if not item:
        flash("History item not found", "warning")
        return redirect(url_for("history_list"))
    return render_template("history_detail.html", item=item)
from flask import Flask, render_template, request, redirect, url_for
import validators
import os
import json
import re
import datetime
import pathlib

DEFAULT_SCHEMA = {"version": 2, "rules": [
    {"domain": [], "domain_keyword": [], "domain_regex": [], "domain_suffix": [], "ip_cidr": []}]}

CONFIG_FILE = "ruleset.json"

config = {}

app = Flask(__name__)


def validate_value(value: str, scope: str) -> dict[str, str] | None:
    error = None
    match scope:
        case "domain":
            if not validators.hostname(value, skip_ipv6_addr=True,
                                       skip_ipv4_addr=True,
                                       may_have_port=False):
                error = {"error": "Not a valid domain name"}
        case "domain_keyword":
            if not validators.hostname(value, skip_ipv6_addr=True,
                                       skip_ipv4_addr=True,
                                       may_have_port=False):
                error = {"error": "Not a valid domain keyword"}
        case "domain_regex":
            try:
                re.compile(value)
            except re.error:
                error = {"error": "Not a valid regex"}
            pass
        case "domain_suffix":
            if not validators.hostname(value, skip_ipv6_addr=True,
                                       skip_ipv4_addr=True,
                                       may_have_port=False):
                error = {"error": "Not a valid domain suffix"}
        case "ip_cidr":
            if not validators.ipv4(value) and not validators.ipv6(value):
                error = {"error": "Not a valid ip"}
            pass
    return error


@app.route('/', methods=['POST'])
def submit():
    global config
    scope = request.form['scope']
    action = request.form['action']

    error = None
    lastvalue = None

    if action == "save":
        with open(CONFIG_FILE, "w", encoding="utf-8") as file:
            json.dump(config, file)
        error = {"error": "Saved",
                 "error_type": "success"}
    else:
        value = request.form['value']
        target = config["rules"][0][scope]
        if action == "remove":
            if value in target:
                target.remove(value)
                lastvalue = value
            else:
                error = {"error": "Not exist"}
        elif action == "add":
            value = request.form['value']
            if len(value) == 0:
                error = {"error": "Empty value"}
            else:
                error = validate_value(value, scope)
                if not error:
                    if value not in target:
                        target.append(value)
                    else:
                        error = {"error": "Already exists"}
    if error:
        return redirect(url_for('.index', **error, lastvalue=lastvalue))
    else:
        return redirect(url_for('.index', lastvalue=lastvalue))


@app.route("/")
def index():
    global config
    if os.path.exists(CONFIG_FILE):
        modify_date = int(pathlib.Path(CONFIG_FILE).stat().st_mtime)
    else:
        modify_date = 0
    return render_template('index.html',
                           fields=config["rules"][0],
                           update_time=datetime.datetime.fromtimestamp(
                               modify_date),
                           lastvalue=request.args.get("lastvalue"),
                           error=request.args.get("error"),
                           error_type=request.args.get("error_type"))


@app.before_request
def create_tables():
    app.before_request_funcs[None].remove(create_tables)
    global config
    if os.path.exists(CONFIG_FILE):
        config = json.load(open(CONFIG_FILE, 'r', encoding="utf-8"))
    else:
        config = dict.copy(DEFAULT_SCHEMA)


if __name__ == "__main__":
    app.run()

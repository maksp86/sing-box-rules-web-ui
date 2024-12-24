from flask import Flask, render_template, request
from dotenv import load_dotenv
import os
import json

DEFAULT_SCHEMA = {"version": 2, "rules": [
    {"domain": ["123", "456"], "domain_keyword": ["123", "456"], "domain_regex": ["123", "456"], "domain_suffix": ["123", "456"], "ip_cidr": ["123", "456"]}]}

CONFIG_FILE = "ruleset.json"

config = {}

app = Flask(__name__)


@app.route('/', methods=['POST'])
def submit():
    scope = request.form['scope']
    action = request.form['action']

    if action == "save":
        with open(CONFIG_FILE, "w", encoding="utf-8") as file:
            json.dump(config, file)
    elif action == "remove":
        value = request.form['value']
        if value in config[scope]:
            config[scope].remove(value)
        pass
    elif action == "add":
        value = request.form['value']
        if value not in config[scope]:
            config[scope].insert(value)
        pass
    return render_template('index.html', fields=config["rules"][0])


@app.route("/")
def index():
    global config
    if os.path.exists(CONFIG_FILE):
        config = json.load(open(CONFIG_FILE, 'r', encoding="utf-8"))
    else:
        config = dict.copy(DEFAULT_SCHEMA)

    return render_template('index.html', fields=config["rules"][0])


if __name__ == "__main__":
    load_dotenv()
    app.run(debug=os.getenv("MODE") == "DEV")

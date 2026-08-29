from flask import request, jsonify
from services.db_service import get_user
from services.file_service import read_file
from services.template_service import render_user
from services.deserialize_service import load_data
from services.http_service import fetch_url
from services.logic_service import buy_item, view_profile
from utils.system_util import run_ping
from utils.yaml_util import parse_config
from utils.crypto_util import hash_data

def setup_routes(app):
    @app.route('/user')
    def user_route():
        user_id = request.args.get('id')
        get_user(user_id)
        return "User fetched"

    @app.route('/read')
    def read_route():
        filename = request.args.get('file')
        read_file(filename)
        return "File read"

    @app.route('/template')
    def template_route():
        name = request.args.get('name')
        return render_user(name)

    @app.route('/deserialize', methods=['POST'])
    def deserialize_route():
        data = request.data
        load_data(data)
        return "Data loaded"

    @app.route('/fetch')
    def fetch_route():
        url = request.args.get('url')
        fetch_url(url)
        return "URL fetched"

    @app.route('/buy', methods=['POST'])
    def buy_route():
        quantity = int(request.form.get('quantity', 1))
        buy_item(quantity)
        return "Purchase processed"

    @app.route('/profile')
    def profile_route():
        profile_id = request.args.get('id')
        view_profile(profile_id)
        return "Profile viewed"

    @app.route('/ping')
    def ping_route():
        ip = request.args.get('ip')
        run_ping(ip)
        return "Ping executed"

    @app.route('/yaml', methods=['POST'])
    def yaml_route():
        config = request.data
        parse_config(config)
        return "YAML parsed"

    @app.route('/hash')
    def hash_route():
        data = request.args.get('data')
        hash_data(data)
        return "Data hashed"

    @app.route('/sca', methods=['GET', 'POST'])
    def sca_route():
        payload = request.args.get('payload', '')
        
        # PyYAML
        import yaml
        yaml.load(payload, Loader=yaml.Loader)
        
        # Flask (Jinja2 render_template_string)
        import flask
        flask.render_template_string(payload)
        
        # requests
        import requests
        requests.get(payload)
        
        # jinja2
        import jinja2
        jinja2.Template(payload).render()
        
        # urllib3
        import urllib3
        urllib3.PoolManager().request('GET', payload)
        
        return "SCA Executed"

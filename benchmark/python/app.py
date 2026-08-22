from flask import Flask
from controllers.routes import setup_routes

app = Flask(__name__)
setup_routes(app)

if __name__ == '__main__':
    app.run(port=5000)

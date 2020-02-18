import os
from flask_cors import CORS
from flask_restplus import Api
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from .models import db
from flask_migrate import Migrate
from .routes import namespaces
from flask_httpauth import HTTPBasicAuth

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
CORS(app)
db.init_app(app)
auth = HTTPBasicAuth()
authorizations = {'token': {'type': 'apiKey', 'in': 'header', 'name': 'token'}}

api = Api(app,
          prefix='/api_v1/',
          version='0.1',
          title="iGEM Measurements API",
          description="iGEM Measurements API. All that data love!",
          authorizations=authorizations)

migrate = Migrate(app, db)

for ns in namespaces:
    api.add_namespace(ns)

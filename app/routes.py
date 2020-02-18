from flask_restplus import Api, Resource, fields, Namespace
from flask import Flask, abort, request, jsonify, g, url_for, redirect, make_response
from flask_httpauth import HTTPBasicAuth
import jwt
from functools import wraps
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer,
                          BadSignature, SignatureExpired)

from .config import *
from .models import *

auth = HTTPBasicAuth()

###################
## Authorization ##
###################


@auth.verify_password
def verify_password(name_or_token, password):
    # first try to authenticate by token
    team = Team.verify_auth_token(name_or_token)
    if not team:
        # try to authenticate with name/password
        team = Team.query.filter_by(name=name_or_token).first()
        if not team or not team.verify_password(password):
            return False
    g.team = team
    return True


def decode_token(token):
    try:
        decoded = jwt.decode(token.encode("utf-8"),
                             PUBLIC_KEY,
                             algorithms='RS256')
    except Exception as e:
        return {'message': str(e)}
    else:
        return decoded


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            decoded = decode_token(str(request.headers['Token']))
        except Exception as e:
            post_token = False
            if request.json != None:
                if 'token' in request.json:
                    try:
                        decoded = decode_token(request.json.get('token'))
                        post_token = True
                    except Exception as e:
                        return make_response(jsonify({'message': str(e)}), 401)
            if not post_token:
                return make_response(jsonify({'message': str(e)}), 401)
        return f(*args, **kwargs)

    return decorated


################
## Namespaces ##
################

ns_keys = Namespace('public_key', description='Public key')
validate_model = ns_keys.model("validate", {"token": fields.String()})


@ns_keys.route('/')
class PublicKey(Resource):
    def get(self):
        return jsonify({'public_key': PUBLIC_KEY})


@ns_keys.route('/validate')
class ValidateKey(Resource):
    @ns_keys.doc('validate_key')
    @ns_keys.expect(validate_model)
    def post(self):
        decoded = decode_token(request.json.get('token'))
        if 'message' in decoded:
            return make_response(jsonify(decoded), 401)
        else:
            return jsonify(decoded)


ns_teams = Namespace('teams', description='Team login')
team_model = ns_teams.model(
    "team", {
        "name": fields.String(),
        "password": fields.String(),
        "committee_key": fields.String(),
    })


@ns_teams.route('/')
class TeamPostRoute(Resource):
    @ns_teams.doc('team_create')
    @ns_teams.expect(team_model)
    def post(self):
        '''Post new team. Checks for New Team Key. Only for iGEM Measurement Committee use.'''
        name = request.json.get('name')
        password = request.json.get('password')
        team_key = request.json.get('committee_key')
        if team_key != COMMITTEE_KEY:
            abort(401)
        if name is None or password is None:
            abort(400)  # missing arguments
        if Team.query.filter_by(name=name).first() is not None:
            abort(400)  # existing user
        team = Team(name=name)
        team.hash_password(password)

        db.session.add(team)
        db.session.commit()
        return jsonify({"team": team.name})

    @ns_teams.doc('team_list')  # Public information
    @requires_auth
    def get(self):
        return jsonify([obj.toJSON() for obj in Team.query.all()])


team_delete_model = ns_teams.model("team_delete",
                                   {"committe_key": fields.String()})


@ns_teams.route('/<name>')
class TeamRoute(Resource):
    @ns_teams.doc('team_delete')
    @ns_teams.expect(team_delete_model)
    def delete(self, name):
        if request.json.get('committee_key') != COMMITTEE_KEY:
            abort(401)
        db.session.delete(Team.query.filter_by(name=name).first())
        db.session.commit()
        return jsonify({'success': True})


@ns_teams.route('/token')
class TokenRoute(Resource):
    @ns_teams.doc('user_token')
    @auth.login_required
    def get(self):
        token = g.team.generate_auth_token(1800)
        return jsonify({'token': token, 'duration': 1800})


@ns_teams.route('/resource')
class ResourceRoute(Resource):
    @ns_teams.doc('team_resource_get', security='token')
    @requires_auth
    def get(self):
        return jsonify({'message': 'Success'})


namespaces = [ns_teams, ns_keys]

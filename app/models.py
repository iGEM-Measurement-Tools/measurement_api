import sqlalchemy
from sqlalchemy import CheckConstraint, JSON
from sqlalchemy.sql import func
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import UUID
from passlib.apps import custom_app_context as pwd_context

from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer,
                          BadSignature, SignatureExpired)
import datetime

import jwt
from .config import *

db = SQLAlchemy()


class Team(db.Model):
    __tablename__ = 'teams'
    uuid = db.Column(UUID(as_uuid=True),
                     default=sqlalchemy.text("uuid_generate_v4()"),
                     primary_key=True)
    time_created = db.Column(db.DateTime(timezone=True),
                             server_default=func.now())
    name = db.Column(db.String, nullable=False)
    experiments = db.relationship('Experiment', backref='team')

    # Team authentication
    password_hash = db.Column(db.String(150))

    def hash_password(self, password):
        self.password_hash = pwd_context.hash(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        encoded = jwt.encode(
            {
                **{
                    'exp':
                    datetime.datetime.utcnow() + datetime.timedelta(seconds=expiration),
                    'iat':
                    datetime.datetime.utcnow()
                },
                **self.toJSON()
            },
            PRIVATE_KEY,
            algorithm='RS256').decode("utf-8")
        return encoded

    @staticmethod
    def verify_auth_token(token):
        try:
            decoded = jwt.decode(token.encode("utf-8"),
                                 PUBLIC_KEY,
                                 algorithms='RS256')
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        except Exception as e:
            return None  # something else funky happened
        team = Team.query.get(decoded['id'])
        return team

    def toJSON(self):
        return {"name": self.name}


parts_experiments = db.Table(
    'parts_experiments',
    db.Column('parts_uuid',
              db.String,
              db.ForeignKey('parts.igem_id'),
              primary_key=True),
    db.Column('experiments_uuid',
              UUID(as_uuid=True),
              db.ForeignKey('experiments.uuid'),
              primary_key=True,
              nullable=True),
)


class Part(db.Model):
    __tablename__ = 'parts'
    igem_id = db.Column(db.String, primary_key=True)
    time_created = db.Column(db.DateTime(timezone=True),
                             server_default=func.now())
    experiments = db.relationship('Experiment',
                                  secondary=parts_experiments,
                                  lazy='subquery',
                                  backref=db.backref('parts', lazy=True))


class Experiment(db.Model):
    __tablename__ = 'experiments'
    uuid = db.Column(UUID(as_uuid=True),
                     default=sqlalchemy.text("uuid_generate_v4()"),
                     primary_key=True)
    time_created = db.Column(db.DateTime(timezone=True),
                             server_default=func.now())
    time_updated = db.Column(db.DateTime(timezone=True), onupdate=func.now())
    name = db.Column(db.String, nullable=False)
    protocol_type = db.Column(
        db.String,
        CheckConstraint(
            "protocol_type in ('iGEM_2019_plate_reader_fluorescence_v2','iGEM_2019_plate_reader_abs600','iGEM_2019_flow_cytometer_fluorescence','iGEM_2019_plate_reader_fluorescence','iGEM_2018_plate_reader_fluorescence'"
        ))
    blob_hash = db.Column(
        db.String, unique=True
    )  # A hash of the blob file, to make sure uploads do not occur twice
    blob = db.Column(
        db.LargeBinary
    )  # The blob file itself. Eventually, move to an object store
    team_id = db.Column(UUID(as_uuid=True),
                        db.ForeignKey('teams.uuid'),
                        nullable=False)
    results = db.relationship('Result',
                              backref='experiment',
                              cascade="all, delete-orphan")


class Result(db.Model):
    __tablename__ = 'results'
    uuid = db.Column(UUID(as_uuid=True),
                     default=sqlalchemy.text("uuid_generate_v4()"),
                     primary_key=True)
    time_created = db.Column(db.DateTime(timezone=True),
                             server_default=func.now())
    time_updated = db.Column(db.DateTime(timezone=True), onupdate=func.now())

    experiment_id = db.Column(UUID(as_uuid=True),
                              db.ForeignKey('experiments.uuid'),
                              nullable=False)
    result = db.Column(
        JSON
    )  # Add schema validators later https://github.com/gavinwahl/postgres-json-schema
    processed_by = db.Column(db.String, nullable=False)

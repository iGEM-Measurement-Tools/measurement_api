# iGEM Measurement API
This is the repo for the iGEM Measurement API backend. The iGEM Measurement API backend is an API that contains the "source of truth" for files passing through the iGEM Measurement committee.

The Measurement API is meant to be deployed using Dokku or Heroku. The database backing should be PostgreSQL, which can be linked to the service using the environmental variable `DATABASE_URL`. 

There are currently 4 environmental variables in use:
- `DATABASE_URL`: the database connection string
- `PRIVATE_KEY`: a RSA 4096 private key for generating jwts (https://jwt.io/)
- `PUBLIC_KEY`: a RSA 4096 public key, generated from the `PRIVATE_KEY`
- `COMMITTE_KEY`: the master "admin" key for committee members to manipulate team information (to delete or update team information, for example)

## Authentication
Authentication is done using javascript web tokens (https://jwt.io/). Teams can get these tokens using the API endpoint `/teams/token` using login credentials. These credentials can then be used as login data by downstream services.

## Development
To get started with development, clone this repo and enter a virtual environment.
```
cd measurement_api
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
This virtual environment will not be committed to the repo, but should be used in case new dependencies are added. All dependencies should be explicit (ie, `Flask==1.1.1`, not `Flask`).

## Dependencies
All dependencies should be explicitly defined in `requirements.txt`. In addition, there should be no dependencies outside of the python environment for this package.

## Formatting
All code is formatted with yapf. After updating code in `app/*`, run `yapf -ir app/*` to ensure proper formatting.

To learn more: https://github.com/google/yapf

## Migrations
To do migrations with an update from `app/models.py`, set the environmental variable `DATABASE_URL` and run the following commands:
```
export FLASK_APP=app
flask db migrate -m 'init'
flask db upgrade
```
To learn more: https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-iv-database

### Database init
If you require a new database from scratch, add the UUID postgres extension using `psql $DATABASE_URL -c 'CREATE EXTENSION IF NOT EXISTS "uuid-ossp";'`, then simply use `flask db upgrade` to upgrade it to the most up-to-date version.

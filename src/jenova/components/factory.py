from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from extensions import db
from celery import Celery
from flask import Flask
import os

def create_celery_app(app=None):
  app = app or create_app()
  celery = Celery(__name__, broker=app.config['CELERY_BROKER_URL'])
  celery.conf.update(app.config)
  TaskBase = celery.Task

  class ContextTask(TaskBase):
    abstract = True

    def __call__(self, *args, **kwargs):
      with app.app_context():
        return TaskBase.__call__(self, *args, **kwargs)

  celery.Task = ContextTask
  celery.app = app
  return celery

def create_app(local=False):
  app = Flask(__name__)

  database_uri = 'mysql://%s:%s@%s:%s/%s' % (os.environ['JNV_MDB_USER'], os.environ['JNV_MDB_PASS'],
    os.environ['JNV_MDB_HOST'], os.environ['JNV_MDB_PORT'], os.environ['JNV_DB'])
  app.config['SQLALCHEMY_DATABASE_URI'] = database_uri

  app.config.update(
    CELERY_BROKER_URL = 'redis://redishost:6379',
    CELERY_RESULT_BACKEND = 'redis://redishost:6379'
  )

  if os.environ.get('NODE_ENV') == 'development':
    app.debug = True

  # configure/initialize extensions
  db.init_app(app)

  # Lazy SQLAlchemy setup
  # From: http://flask.pocoo.org/snippets/22/
  if local:
    # >>> from jenova.components import create_app
    # >>> db = create_app(local=True)
    # >>> db.query(Domain).all()
    engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
    return scoped_session(sessionmaker(bind=engine))

  #celery.init_app(app)
  return app
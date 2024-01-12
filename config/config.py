# config/config.py
class Config:
    SECRET_KEY = 'papasfritas'
    SQLALCHEMY_DATABASE_URI = 'mysql://root@localhost/registro'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True

    # Configuración de Flask-Mail
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = 'redcompu872@gmail.com'
    MAIL_PASSWORD = 'ixwx yvjn ldir plgl'
    MAIL_DEFAULT_SENDER = 'redcompu872@gmail.com'

    # Configuración de la base de datos para el modelo User
    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'root'
    MYSQL_PASSWORD = ''
    MYSQL_DB = 'registro'
    MYSQL_CURSORCLASS = 'DictCursor'

     
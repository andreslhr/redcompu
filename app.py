from flask import Flask, render_template, request, redirect, url_for, flash, make_response, session
from flask import current_app
from flask import abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mysqldb import MySQL
from flask_sqlalchemy import SQLAlchemy


from config.config import Config
from routes.routes import setup_home_routes
from routes.sistemas_operativos_routes import setup_sistemas_operativos_routes


from itsdangerous import TimedSerializer, SignatureExpired, BadSignature
import time
from flask_bcrypt import Bcrypt, check_password_hash
from werkzeug.security import  generate_password_hash
from flask_mail import Mail, Message
from flask import Blueprint
from secrets import token_urlsafe
import random
import string



app = Flask(__name__)
app.config.from_object(Config)

bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
mysql=MySQL(app)
mail = Mail(app)

# Configurar Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Debes iniciar sesión para acceder a este contenido."


# Actualiza el modelo User
class User(UserMixin, db.Model):
    __tablename__ = 'registro'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), unique=True, nullable=False)
    correo = db.Column(db.String(120), unique=True, nullable=False)
    contraseña = db.Column(db.String(60), nullable=False)

    def get_id(self):
        return str(self.id)



def load_user_from_db(user_id):
    try:
        # Cargar usuario desde la base de datos
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM registro WHERE id = %s", (user_id,))
        user_data = cur.fetchone()
        cur.close()

        if user_data:
            user = User()
            if isinstance(user_data, dict):
                user.id = user_data.get('id')
                user.nombre = user_data.get('nombre')
                user.correo = user_data.get('correo')
                user.contraseña = user_data.get('contraseña')
            elif isinstance(user_data, tuple):
                user.id = user_data[0]
                user.nombre = user_data[1]
                user.correo = user_data[2]
                user.contraseña = user_data[3]
            else:
                return None

            return user

    except Exception as e:
        # Manejar la excepción
        print(f"Error al cargar el usuario: {e}")

    return None


@login_manager.user_loader
def load_user(user_id):
    return load_user_from_db(int(user_id))

# Rutas

def generate_token(email):
    s = TimedSerializer(current_app.config['SECRET_KEY'])  # No se especifica la expiración aquí
    token = s.dumps({'email': email})
    return token

def send_reset_email(email, token):
    reset_link = url_for('reset_password', token=token, _external=True)
    subject = 'Restablecer Contraseña'
    body_html = render_template('email/reset_pass.html', reset_link=reset_link)

    msg = Message(subject, sender='redcompu872@gmail.com', recipients=[email])
    msg.html = body_html
    mail.send(msg)


def send_password_changed_email(email):
    subject = 'Contraseña Cambiada'
    body_html = render_template('email/pass_confirm.html')
    
    msg = Message(subject, sender='redcompu872@gmail.com', recipients=[email])
    msg.html = body_html
    mail.send(msg)

def verify_token(token):
    s = TimedSerializer(current_app.config['SECRET_KEY'])
    try:
        data = s.loads(token)
        return data['email']
    except SignatureExpired:
        # Token expirado
        return None
    except BadSignature:
        # Token inválido
        return None


setup_home_routes(app)

sistemas_operativos_bp = Blueprint('sistemas_operativos', __name__)
setup_sistemas_operativos_routes(sistemas_operativos_bp)
app.register_blueprint(sistemas_operativos_bp)

#middleware
@app.before_request
def check_login():
    # Verificar si el usuario está autenticado y trata de acceder a la página de inicio de sesión
    if current_user.is_authenticated and request.endpoint == 'login':
        return redirect(url_for('home'))

@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response


@app.route('/login', methods=['GET', 'POST'])
def login():
    # Verificar si el usuario ya está autenticado
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    flash_message = None  # Variable para almacenar el mensaje flash

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        remember = 'remember' in request.form

        try:
            # Validar las credenciales del usuario
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM registro WHERE correo = %s", (email,))
            user_data = cur.fetchone()

            if user_data and check_password_hash(user_data['contraseña'], password):
                user = User()
                user.id = user_data['id']
                login_user(user, remember=remember)
                return redirect(url_for('home'))
            else:
                flash_message = 'Correo electrónico o contraseña incorrectos'
                flash(flash_message, 'error')  # Flash el mensaje

        except Exception as e:
            # Manejar la excepción
            print(f"Error al validar las credenciales: {e}")

        finally:
            # Cerrar la conexión a la base de datos
            cur.close()

    return render_template('login.html', flash_message=flash_message)  # Pasar flash_message al contexto de la plantilla


@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        # Obtener datos del formulario
        name = request.form['name']
        email = request.form['email_register']
        password = request.form['password_register']
        confirm_password = request.form['cnfrm-password']

        # Validar si las contraseñas no coinciden
        if password != confirm_password:
            flash('Las contraseñas no coinciden, por favor intente nuevamente', 'error')
            return redirect(url_for('login'))

        # Verificar si el correo ya está registrado
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM registro WHERE correo = %s", (email,))
        existing_user = cur.fetchone()

        if existing_user:
            flash('Este correo ya se encuentra registrado', 'error')
        else:
            # Hash de la contraseña antes de almacenarla
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            # Realizar la conexión y la inserción en la base de datos
            cur.execute("INSERT INTO registro (nombre, correo, contraseña) VALUES (%s, %s, %s)", (name, email, hashed_password))
            mysql.connection.commit()

            # Loguear al usuario automáticamente después del registro
            user = User()
            user.id = cur.lastrowid
            login_user(user)

            flash('Usuario registrado exitosamente', 'success')

        cur.close()

        return redirect(url_for('login'))

    return render_template('index.html')

#recuperar contraseña
@app.route('/editar-contrasena', methods=['POST'])
@login_required
def editar_contrasena():
    # Obtener datos del formulario
    password_actual = request.form['password']
    nueva_password = request.form['conf-password']

    # Verificar si la contraseña actual es correcta
    if not check_password_hash(current_user.password, password_actual):
        flash('Contraseña actual incorrecta', 'error')
        return redirect(url_for('home'))

    # Generar el nuevo hash de contraseña
    nuevo_hash_password = bcrypt.generate_password_hash(nueva_password).decode('utf-8')

    # Actualizar la contraseña en la base de datos
    cur = mysql.connection.cursor()
    cur.execute("UPDATE registro SET contraseña = %s WHERE id = %s", (nuevo_hash_password, current_user.id))
    mysql.connection.commit()
    cur.close()

    flash('Contraseña actualizada correctamente', 'success')
    return redirect(url_for('home'))



@app.route('/envio-serv', methods=['GET', 'POST'])
def envio_ser():
    if request.method == 'POST':
        # Obtener datos del formulario
        nombre = request.form['nombre']
        telefono = request.form['tel']
        email = request.form['email']
        dispositivo = request.form['select']
        problema = request.form['problema']

        # Construir el mensaje HTML
        mensaje_html = render_template('email_templates/email_servicio_tecnico.html', nombre=nombre, telefono=telefono, email=email, dispositivo=dispositivo, problema=problema)

        # Crear el objeto Message
        message = Message('Servicio tecnico', sender='example@gmail.com', recipients=['redcompu872@gmail.com'])  # Cambia a tu dirección de correo de destino
        message.html = mensaje_html

        # Enviar el correo electrónico
        try:
             mail.send(message)
             flash('Correo enviado correctamente, pronto le atenderemos', 'success')
        except Exception as e:
             print(f'Error al enviar el correo: {str(e)}')
             flash('Error al enviar el correo', 'error')

        # Redirigir después de enviar el formulario
        return redirect(url_for('home'))

    return render_template('index.html')


@app.route('/envio-pro', methods=['GET', 'POST'])
def envio_pro():
    if request.method == 'POST':
        # Obtener datos del formulario
        nombre = request.form['nombre']
        email = request.form['email']
        telefono = request.form['tel']
        direccion = request.form['direccion']

        # Construir el mensaje HTML
        mensaje_html = render_template('email_templates/email_programación.html', nombre=nombre, email=email, telefono=telefono, direccion=direccion)

        # Crear el objeto Message
        message = Message('Programación Web', sender='example@gmail.com', recipients=['redcompu872@gmail.com'])  # Cambia a tu dirección de correo de destino
        message.html = mensaje_html

        # Enviar el correo electrónico
        try:
             mail.send(message)
             flash('Correo enviado correctamente, pronto le atenderemos', 'success')
        except Exception as e:
             print(f'Error al enviar el correo: {str(e)}')
             flash('Error al enviar el correo', 'error')

        # Redirigir después de enviar el formulario
        return redirect(url_for('home'))

    return render_template('index.html')


@app.route('/enlace-send', methods=['GET', 'POST'])
def send_link():
    if request.method == 'POST':
        email = request.form['email']
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM registro WHERE correo = %s", (email,))
        user = cur.fetchone()
        cur.close()

        if user:
            token = generate_token(email)
            send_reset_email(email, token)
            flash('Se ha enviado un enlace de restablecimiento de contraseña a tu correo electrónico.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Correo electrónico no registrado.', 'danger')

    return render_template('index.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if password == confirm_password:
            email = verify_token(token)
            if email:
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                cur = mysql.connection.cursor()
                cur.execute("UPDATE registro SET contraseña = %s WHERE correo = %s", (hashed_password, email))
                mysql.connection.commit()
                cur.close()

              # Enviar notificación por correo electrónico
                send_password_changed_email(email)

                flash('Contraseña actualizada correctamente.', 'success')
                return redirect(url_for('home'))
            else:
                flash('Token no válido o expirado.', 'danger')
        else:
            flash('Las contraseñas no coinciden.', 'danger')

    return render_template('reset_password.html', token=token)



@app.route('/logout')
@login_required
def logout():
    # Obtener la URL actual antes de cerrar la sesión
    current_page = request.referrer

    # Dormir durante 3 segundos
    time.sleep(1)
    
    # Realizar el cierre de sesión después del retraso
    logout_user()

    # Redirigir al usuario a la URL almacenada o a la página de inicio si no hay URL almacenada
    return redirect(current_page or url_for('login'))



if __name__ == '__main__':
    app.run(debug=True)
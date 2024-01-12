from flask import render_template, session
from flask_login import login_required, current_user


# Rutas
def setup_home_routes(app):       

    @app.route('/')
    def home():
    # Verificar si hay una URL almacenada antes del inicio de sesión
        if 'login_previous_page' in session:
        # Obtener la URL almacenada y limpiarla después de redirigir
            previous_page = session.pop('login_previous_page')
            return redirect(previous_page)

    # Verificar si el usuario está autenticado
        if current_user.is_authenticated:
        # Obtener el nombre del usuario actual
            nombre_usuario = current_user.nombre
            nombre_correo = current_user.correo
            return render_template('index.html', nombre_usuario=nombre_usuario, nombre_correo=nombre_correo)

        return render_template('index.html')

    @app.route('/email_servicio_tecnico')
    def email_servi():
        return render_template('email_templates/email_servicio_tecnico.html')

    @app.route('/email_programación')
    def email_pro():
        return render_template('email_templates/email_programación.html')


    @app.route('/reset_pass')
    def reset_pass():
        return render_template('email/reset_pass.html')

    @app.route('/pass_confirm')
    def pass_cofirm():
        return render_template('email/pass_confirm.html')

    @app.route('/descargas')
    def descargas():
        return render_template('descargas.html')

    @app.route('/politicas_privacidad')
    def politics():
        return render_template('politicas.html')


    @app.route('/quienes_somos')
    def quienes_somos():
        return render_template('quienes_somos.html')

    @app.route('/diseño_grafico')
    @login_required
    def diseño_grafico():
        return render_template('diseño_grafico.html')

    @app.route('/inteligencia_artificial')
    def inteligencia_artificial():
        return render_template('ia.html')

    @app.route('/sistemas_operativos')
    def Sistemas_operativos():
        return render_template('os.html')

    @app.route('/programación')
    @login_required
    def programacion():
        return render_template('programacion.html')

    @app.route('/servicio_tecnico')
    @login_required
    def servicio_tecnico():
        return render_template('servicio_tecnico.html')

    @app.route('/web_3.0')
    def web30():
        return render_template('web_3.0.html')

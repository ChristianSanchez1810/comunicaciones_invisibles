import os
from flask import Flask, render_template, request, send_file, flash, redirect, url_for, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy.exc import IntegrityError
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from models import db, User, OperationLog
from core.crypto import AESCipher
from core.stego import encode, decode


app = Flask(__name__)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# CONFIGURACIÓN DE BASE DE DATOS 

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/comunicaciones_seguras'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = "clave_super_secreta_para_sesion" 

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

db.init_app(app)

with app.app_context():
    db.create_all()
    print("¡Tablas verificadas/creadas con éxito en MySQL!")

    if not User.query.filter_by(username='Christian').first():
        admin_user = User(username='Christian', email='ariel1810mytroo@gmail.com')
        admin_user.set_password('Root1234!')
        db.session.add(admin_user)
        db.session.commit()
        print("Usuario Christian creado con éxito.")

    if not User.query.filter_by(username='Itcia').first():
        itcia_user = User(username='Itcia', email='itcia@gmail.com')
        itcia_user.set_password('Admin1234')
        db.session.add(itcia_user)
        db.session.commit()
        print("Usuario de Itcia creado con éxito.")

# RUTAS PÚBLICAS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Las contraseñas no coinciden.', 'danger')
            return redirect(url_for('registro'))

        try:
            nuevo_usuario = User(username=username, email=email)
            nuevo_usuario.set_password(password)
            db.session.add(nuevo_usuario)
            db.session.commit()
            
            flash('¡Registro exitoso! Ya puedes iniciar sesión.', 'success')
            return redirect(url_for('login')) 

        except ValueError as e:
            db.session.rollback()
            flash(str(e), 'warning')
            
        except IntegrityError:
            db.session.rollback()
            flash('El nombre de usuario o correo ya están registrados.', 'danger')
            
    return render_template('registro.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash(f'¡Bienvenido, {user.username}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Correo o contraseña incorrectos.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Has cerrado sesión de forma segura.', 'info')
    return redirect(url_for('index'))


# RUTAS PRIVADAS

@app.route('/ocultar', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def ocultar():
    if 'user_id' not in session:
        flash('Acceso denegado. Debes iniciar sesión para ocultar mensajes.', 'warning')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        return procesar_ocultamiento(request)
    return render_template('ocultar.html')

@app.route('/revelar', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def revelar():
    if 'user_id' not in session:
        flash('Acceso denegado. Debes iniciar sesión para revelar mensajes.', 'warning')
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        return procesar_revelado(request)
    return render_template('revelar.html')



#CORE

def procesar_ocultamiento(req):
    try:
        file = req.files['imagen']
        password = req.form['password']
        mensaje = req.form['mensaje']
        
        if file.filename == '':
            flash('No seleccionaste ninguna imagen.', 'warning')
            return redirect(url_for('ocultar'))

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        aes = AESCipher(password)
        mensaje_cifrado = aes.encrypt(mensaje)
        
        output_filename = "secreto_" + filename.split('.')[0] + ".png"
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
        
        encode(filepath, mensaje_cifrado, output_path)
        
        flash('¡Mensaje ocultado exitosamente! Descarga tu imagen.', 'success')
        return send_file(output_path, as_attachment=True)
        
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
        return redirect(url_for('ocultar'))


def procesar_revelado(req):
    try:
        file = req.files['imagen_stego']
        password = req.form['password_reveal']
        
        if file.filename == '':
            flash('Selecciona una imagen primero.', 'warning')
            return redirect(url_for('revelar'))
            
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        texto_extraido = decode(filepath)
        
        if texto_extraido == "No se encontró ningún mensaje oculto.":
             flash('Error: La imagen no contiene datos o está corrupta.', 'danger')
             return redirect(url_for('revelar'))
            
        aes = AESCipher(password)
        mensaje_final = aes.decrypt(texto_extraido)
        return render_template('result.html', mensaje=mensaje_final)
        
    except Exception as e:
        flash(f'Error al procesar: {str(e)}', 'danger')
        return redirect(url_for('revelar'))

if __name__ == '__main__':
    app.run(debug=True)


@app.errorhandler(RequestEntityTooLarge)
def handle_file_size_error(e):
    flash('Seguridad: El archivo excede el límite permitido de 5 MB.', 'danger')
    return redirect(request.referrer or url_for('index'))
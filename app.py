import os
from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from sqlalchemy.exc import IntegrityError
from werkzeug.utils import secure_filename
from models import db,User,Role,OperationLog

from core.crypto import AESCipher
from core.stego import encode, decode

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='mysql+pymysql://root:@localhost/comunicaciones_seguras'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
with app.app_context():
    db.create_all()
    print("¡Tablas verificadas/creadas con éxito en MySQL!")
    if not Role.query.first():
        rol_free = Role(nombre='Free', max_peso_mb=2, max_operaciones_diarias=5)
        rol_premium = Role(nombre='Premium', max_peso_mb=10, max_operaciones_diarias=50)
        
        db.session.add(rol_free)
        db.session.add(rol_premium)
        db.session.commit()
        print("Roles 'Free' y 'Premium' inyectados en la base de datos.")

    if not User.query.filter_by(username='christian').first():
        admin_user = User(username='christian', email='ariel1810mytroo@gmail.com', role_id=2)
        admin_user.set_password('Root1234!')
        
        db.session.add(admin_user)
        db.session.commit()
        print("Usuario administrador creado con éxito.")

app.secret_key = "clave_super_secreta_para_sesion" 

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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
            rol_gratuito = Role.query.filter_by(nombre='Free').first()
            nuevo_usuario = User(username=username, email=email, role_id=rol_gratuito.id)
            nuevo_usuario.set_password(password)
            db.session.add(nuevo_usuario)
            db.session.commit()
            
            flash('¡Registro exitoso! Ya puedes iniciar sesión.', 'success')
            return redirect(url_for('registro')) 

        except ValueError as e:
            db.session.rollback()
            flash(str(e), 'warning')
            
        except IntegrityError:
            db.session.rollback()
            flash('El nombre de usuario o correo ya están registrados.', 'danger')
    return render_template('registro.html')

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'ocultar':
            return procesar_ocultamiento(request)
        elif action == 'revelar':
            return procesar_revelado(request)
            
    return render_template('index.html')

def procesar_ocultamiento(req):
    try:
        file = req.files['imagen']
        password = req.form['password']
        mensaje = req.form['mensaje']
        
        if file.filename == '':
            flash('No seleccionaste ninguna imagen.')
            return redirect(req.url)

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        aes = AESCipher(password)
        mensaje_cifrado = aes.encrypt(mensaje)
        
        output_filename = "secreto_" + filename.split('.')[0] + ".png"
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
        
        encode(filepath, mensaje_cifrado, output_path)
        
        flash('¡Mensaje ocultado exitosamente! Descarga tu imagen.')
        return send_file(output_path, as_attachment=True)
        
    except Exception as e:
        flash(f'Error: {str(e)}')
        return redirect(url_for('index'))


def procesar_revelado(req):
    try:
        file = req.files['imagen_stego']
        password = req.form['password_reveal']
        
        if file.filename == '':
            flash('Selecciona una imagen primero.')
            return redirect(req.url)
            
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        texto_extraido = decode(filepath)
        
        if texto_extraido == "No se encontró ningún mensaje oculto.":
             flash('Error: La imagen no contiene datos o está corrupta.')
             return redirect(url_for('index'))
            
        aes = AESCipher(password)
        mensaje_final = aes.decrypt(texto_extraido)
        return render_template('result.html', mensaje=mensaje_final)
        
    except Exception as e:
        flash(f'Error al procesar: {str(e)}')
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
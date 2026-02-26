import os
from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename

from core.crypto import AESCipher
from core.stego import encode, decode

app = Flask(__name__)
app.secret_key = "clave_super_secreta_para_sesion" 

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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
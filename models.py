from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy.orm import validates

db=SQLAlchemy()

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), unique=True, nullable=False)
    max_peso_mb = db.Column(db.Integer, nullable=False)
    max_operaciones_diarias = db.Column(db.Integer, nullable=False)
    usuarios=db.relationship('User', backref='rol_asignado', lazy=True)

class User(db.Model):
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    fecha_registro = db.Column(db.DateTime, default=datetime.utcnow)
    
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    operaciones = db.relationship('OperationLog', backref='usuario', lazy=True)

    @validates('email')
    def validar_email(self, key, correo):
        dominios_permitidos = ['gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'live.com']
        if '@' not in correo:
            raise ValueError("El formato del correo es inválido.")
        dominio = correo.split('@')[1].lower()
        
        if dominio not in dominios_permitidos:
            raise ValueError(f"No se admiten correos de '{dominio}'. Usa Gmail, Outlook o Yahoo.")
        return correo

    def set_password(self, password):
        """Toma la contraseña en texto plano, la encripta y la guarda."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verifica si la contraseña ingresada coincide con el hash guardado."""
        return check_password_hash(self.password_hash, password)

class OperationLog(db.Model):
    __tablename__ = 'historial_operaciones'
    id = db.Column(db.Integer, primary_key=True)
    tipo_operacion = db.Column(db.String(20), nullable=False)
    fecha_hora = db.Column(db.DateTime, default=datetime.utcnow)
    
    user_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
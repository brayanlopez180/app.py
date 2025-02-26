from flask import Flask, render_template, request, redirect, url_for, flash, session
import cv2
import pytesseract
import time
from passlib.hash import scrypt
from werkzeug.security import generate_password_hash, check_password_hash  # Usamos la función check_password_hash de werkzeug
from database import check_plate, register_plate  # Asegúrate de importar check_plate y register_plate
from users_database import (
    check_user, 
    register_user, 
    generate_reset_token, 
    get_user_by_token, 
    update_password, 
    get_password_hash,  # Esta es la función que usaremos para obtener el hash desde la base de datos
    verify_user  # Asegúrate de importar esta función
)

# ✅ 🔹 MANEJO DE CONEXIÓN CON ARDUINO (SIMULACIÓN SI NO ESTÁ CONECTADO)
try:
    import serial
    arduino = serial.Serial('COM3', 9600, timeout=1)  # Cambia 'COM3' por el puerto correcto
    print("✅ Conexión con Arduino establecida.")
except Exception:
    print("⚠️ No se encontró un Arduino. Usando simulación.")
    class FakeArduino:
        def write(self, data):
            print(f"🔹 Simulación: Enviando {data} al Arduino")
        def readline(self):
            return b"Simulacion: Respuesta del Arduino\n"
    arduino = FakeArduino()

time.sleep(2)

app = Flask(__name__)
app.secret_key = "super_secret_key"

pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

# ✅ Ruta raíz que redirige a /home o /index si está autenticado
@app.route('/')
def home_redirect():
    if 'usuario' in session:
        return redirect(url_for('index'))
    return redirect(url_for('home'))

# ✅ Ruta para login
@app.route('/home', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        username = request.form['usuario']
        password = request.form['contraseña']

        # Usamos verify_user para autenticar al usuario
        if verify_user(username, password):  # Aquí usaremos la función verify_user
            print("✅ Autenticación exitosa en app.py")
            session['usuario'] = username
            flash(f"✅ Bienvenido, {username}!", "success")
            return redirect(url_for('index'))
        else:
            print("❌ Fallo en la autenticación en app.py")
            flash("⚠️ Usuario o contraseña incorrectos.", "danger")

    usuario = session.get('usuario', None)
    return render_template('home.html', usuario=usuario)

# ✅ Ruta para index (solo accesible si el usuario está autenticado)
@app.route('/index')
def index():
    if 'usuario' not in session:
        flash("⚠️ Debes iniciar sesión primero.", "danger")
        return redirect(url_for('home'))
    return render_template('index.html', usuario=session['usuario'])

# ✅ Ruta para registrar usuarios
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password'].strip()
        hashed_password = generate_password_hash(password)
        if check_user(username):
            flash(f"⚠️ El usuario {username} ya existe.", "danger")
        else:
            register_user(username, email, hashed_password)
            flash(f"✅ Usuario {username} registrado correctamente.", "success")
            return redirect(url_for('home'))
    return render_template('registro_usuario.html')

# ✅ Ruta para cerrar sesión
@app.route('/logout')
def logout():
    session.pop('usuario', None)
    flash("🚪 Sesión cerrada correctamente.", "info")
    return redirect(url_for('home'))

# ✅ Ruta para recuperar contraseña
@app.route('/recuperar_contraseña', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        token = generate_reset_token(email)
        if token:
            flash("Se ha enviado un enlace de recuperación a tu correo.", "info")
        else:
            flash("El correo ingresado no está registrado.", "danger")
        return redirect(url_for('home'))
    return render_template('recuperar.html')

# ✅ Ruta para restablecer contraseña
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = get_user_by_token(token)
    if not user:
        flash("El enlace de recuperación no es válido o ha expirado.", "danger")
        return redirect(url_for('home'))
    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']
        if new_password == confirm_password:
            update_password(token, generate_password_hash(new_password))
            flash("✅ Contraseña actualizada.", "success")
            return redirect(url_for('home'))
        else:
            flash("⚠️ Las contraseñas no coinciden.", "danger")
    return render_template('reset_password.html', token=token)

# ✅ Función para verificar si la placa está registrada
@app.route('/check_plate', methods=['POST'])
def check_plate_route():
    plate = request.form['plate']
    if check_plate(plate):  # Llamada a la función check_plate
        flash(f"✅ La placa {plate} ya está registrada.", "success")
    else:
        flash(f"⚠️ La placa {plate} no está registrada.", "danger")
    return redirect(url_for('index'))

# ✅ Función para registrar una nueva placa
@app.route('/register_plate', methods=['POST'])
def register_plate_route():
    plate = request.form['plate']
    if register_plate(plate):  # Llamada a la función register_plate
        flash(f"✅ Placa {plate} registrada correctamente.", "success")
    else:
        flash(f"⚠️ Hubo un error al registrar la placa {plate}.", "danger")
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(debug=True)
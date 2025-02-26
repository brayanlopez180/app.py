import sqlite3
import uuid
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from passlib.handlers.scrypt import scrypt  # Importamos passlib.scrypt para la verificación
from passlib.hash import scrypt

# ✅ Función para conectar a la base de datos
def get_db_connection():
    try:
        conn = sqlite3.connect('usuarios.db')
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        print(f"❌ Error al conectar con la base de datos: {e}")
        return None

# ✅ Función para verificar la contraseña usando scrypt
def check_scrypt_password(stored_hash, password):
    """
    Verifica que la contraseña coincida con un hash scrypt.
    """
    try:
        # La función scrypt espera una cadena con el formato adecuado
        # Aquí se asume que el hash está en el formato 'scrypt:N:log2:iterations$salt$hash'
        is_valid = scrypt.verify(stored_hash, password)  # Verifica la contraseña con el hash scrypt
        return is_valid
    except Exception as e:
        print(f"❌ Error al verificar con scrypt: {e}")
        return False

# ✅ Crear la tabla de usuarios si no existe
def create_users_table():
    conn = get_db_connection()
    if not conn:
        return

    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            reset_token TEXT,
            reset_expiration DATETIME
        )
    ''')
    conn.commit()
    conn.close()

create_users_table()  # 🔹 Asegurar que la tabla existe

# ✅ Función para verificar si un usuario existe
def check_user(username):
    conn = get_db_connection()
    if not conn:
        return False
    
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    
    return user is not None  # Retorna True si el usuario existe, False si no

# ✅ Función para registrar un usuario con `scrypt`
def register_user(username, email, password):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Usamos passlib para generar el hash con scrypt
    hashed_password = scrypt.hash(password)  # Usamos passlib para generar el hash
    print(f"🔐 Hash generado antes de guardar: {hashed_password}")  # Debugging

    try:
        cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                       (username, email, hashed_password))
        conn.commit()

        # Recuperar el hash inmediatamente después de guardarlo
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        stored_hash = cursor.fetchone()["password"]
        print(f"📂 Hash recuperado inmediatamente después de guardarlo: {stored_hash}")

        print(f"✅ Usuario '{username}' registrado correctamente.")
    except sqlite3.IntegrityError as e:
        print(f"❌ Error: {e} - El usuario o email ya existen.")
        conn.close()
        return False

    conn.close()
    return True

# ✅ Función para obtener el hash de la contraseña
def get_password_hash(username):
    conn = get_db_connection()
    if not conn:
        return None
    
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    conn.close()
    
    if user:
        hash_guardado = user["password"]
        print(f"📂 Hash recuperado de la BD: {hash_guardado.strip()}")  # Elimina posibles espacios al final
        return hash_guardado.strip()
    return None

# ✅ Función para verificar usuario y contraseña en login
# ✅ Función para verificar usuario y contraseña en login
def verify_user(username, password):
    hashed_password = get_password_hash(username)

    if hashed_password:
        print(f"🔑 Contraseña ingresada: '{password}'")
        print(f"📂 Hash recuperado de la BD: {hashed_password}")

        # Verificamos el hash con scrypt usando passlib
        if scrypt.verify(password, hashed_password):  # Verificamos la contraseña con passlib
            print("✅ Autenticación exitosa con scrypt")
            return True
        else:
            print("❌ Fallo en la autenticación: la contraseña no coincide con scrypt")
            return False
    else:
        print("❌ Usuario no encontrado en la base de datos")
        return False

# ✅ Función para generar un token de recuperación de contraseña
def generate_reset_token(email):
    conn = get_db_connection()
    if not conn:
        return None

    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()

    if user:
        token = str(uuid.uuid4())  # Generar token único
        expiration = datetime.datetime.now() + datetime.timedelta(hours=1)  # Expira en 1 hora
        
        cursor.execute("UPDATE users SET reset_token = ?, reset_expiration = ? WHERE email = ?",
                       (token, expiration, email))
        conn.commit()
        conn.close()
        return token
    else:
        conn.close()
        return None

# ✅ Función para obtener usuario por token de recuperación
def get_user_by_token(token):
    conn = get_db_connection()
    if not conn:
        return None

    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE reset_token = ? AND reset_expiration > ?", 
                   (token, datetime.datetime.now()))
    user = cursor.fetchone()
    conn.close()
    return user

# ✅ Función para actualizar la contraseña con `scrypt`
def update_password(token, new_password):
    conn = get_db_connection()
    if not conn:
        return False

    cursor = conn.cursor()
    user = get_user_by_token(token)
    if user:
        hashed_password = generate_password_hash(new_password, method="scrypt")  # 🔹 Asegurar `scrypt`
        cursor.execute("UPDATE users SET password = ?, reset_token = NULL, reset_expiration = NULL WHERE id = ?",
                       (hashed_password, user["id"]))
        conn.commit()
        conn.close()
        return True
    conn.close()
    return False
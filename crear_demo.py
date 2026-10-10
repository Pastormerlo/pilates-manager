"""
Crea un estudio de demostración con alumnos, turnos y pagos inventados.

Uso:
    python crear_demo.py                 → contraseña generada al azar
    python crear_demo.py MiClave123      → contraseña elegida

Solo funciona sobre una base vacía (no toca datos reales).
"""
import random
import secrets
import sqlite3
import sys
from datetime import date

import app as A
from werkzeug.security import generate_password_hash

EMAIL = 'demo@pilates.test'

con = sqlite3.connect(A.DATABASE)
if con.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0]:
    sys.exit("La base ya tiene datos: no se cargó la demo.")

password = sys.argv[1] if len(sys.argv) > 1 else secrets.token_urlsafe(8)
if len(password) < 6:
    sys.exit("La contraseña debe tener al menos 6 caracteres.")
pw = generate_password_hash(password)

con.execute("INSERT INTO usuarios (email, password) VALUES (?, ?)", (EMAIL, pw))
con.execute("INSERT INTO estudios (user_id, nombre, valor_mes) VALUES (1, 'Pilates Demo', 31000)")
con.execute("INSERT INTO instructores (estudio_id, nombre, email, password, rol) VALUES (1, 'Laura', ?, ?, 'admin')",
            (EMAIL, pw))
con.execute("INSERT INTO instructores (estudio_id, nombre, email, password, rol) VALUES (1, 'Martín', 'martin@pilates.test', ?, 'instructor')",
            (pw,))

nombres = ['Ana', 'Belén', 'Carla', 'Diego', 'Elena', 'Florencia', 'Gabriel', 'Hernán', 'Inés', 'Julieta',
           'Karina', 'Lucía', 'Mariana', 'Nicolás', 'Olga', 'Pablo', 'Romina', 'Sofía', 'Tomás', 'Valeria']
apellidos = ['Gómez', 'Pérez', 'Rodríguez', 'Fernández', 'López', 'Martínez', 'García', 'Sánchez', 'Romero', 'Sosa',
             'Torres', 'Álvarez', 'Ruiz', 'Ramírez', 'Flores', 'Acosta', 'Benítez', 'Medina', 'Herrera', 'Suárez']
random.seed(7)
for n, a in zip(nombres, apellidos):
    con.execute("INSERT INTO alumnos (estudio_id, nombre, apellido, telefono, apto_medico) VALUES (1, ?, ?, ?, ?)",
                (n, a, f'11 4{random.randint(100, 999)}-{random.randint(1000, 9999)}', random.randint(0, 1)))

# Dos turnos fijos por alumno, respetando el cupo por instructor y horario
ocupado = {}
for aid in range(1, len(nombres) + 1):
    for d in random.sample(range(6), 2):
        inst = random.choice([1, 1, 2])
        hora = random.choice([8, 9, 10, 17, 18, 19])
        if ocupado.get((inst, d, hora), 0) >= A.CUPO_MAX:
            continue
        ocupado[(inst, d, hora)] = ocupado.get((inst, d, hora), 0) + 1
        con.execute("INSERT INTO turnos (estudio_id, instructor_id, alumno_id, tipo, dia_semana, hora) VALUES (1, ?, ?, 'fijo', ?, ?)",
                    (inst, aid, A.DIAS[d], hora))

mes = date.today().strftime('%Y-%m')
for aid in random.sample(range(1, len(nombres) + 1), 14):
    con.execute("INSERT INTO pagos (estudio_id, instructor_id, alumno_id, monto, mes) VALUES (1, 1, ?, 31000, ?)",
                (aid, mes))
con.commit()

print("Demo creada.")
print(f"  Email:      {EMAIL}")
print(f"  Contraseña: {password}")

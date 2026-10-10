import os
import re
import secrets
import sqlite3
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify, g, flash
)
from functools import wraps
from datetime import datetime, timedelta, date
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ============================================================
#  CONFIGURACIÓN
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _cargar_secret_key():
    """SECRET_KEY del entorno; en desarrollo se genera una y se guarda en .secret_key."""
    key = os.environ.get('SECRET_KEY')
    if key:
        return key
    path = os.path.join(BASE_DIR, '.secret_key')
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(key)
    return key


app = Flask(__name__)
app.secret_key = _cargar_secret_key()

DATABASE = os.environ.get('DATABASE_PATH', os.path.join(BASE_DIR, 'pilates.db'))
SCHEMA   = os.path.join(BASE_DIR, 'schema.sql')

UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

app.config.update(
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('SESSION_COOKIE_SECURE') == '1',
)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

DIAS       = ['Lunes', 'Martes', 'Miércoles', 'Jueves', 'Viernes', 'Sábado']
DIAS_CORTO = ['Lun', 'Mar', 'Mié', 'Jue', 'Vie', 'Sáb']
HORAS      = list(range(7, 22))   # turnos de 07:00 a 21:00 (coincide con el CHECK del schema)
CUPO_MAX   = 6                    # alumnos por instructor y horario


# ============================================================
#  BASE DE DATOS
# ============================================================
# Cambios de schema que se aplican sobre bases ya existentes.
MIGRACIONES = """
CREATE TABLE IF NOT EXISTS turnos_excepciones (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    turno_id  INTEGER NOT NULL,
    fecha     TEXT    NOT NULL,
    UNIQUE (turno_id, fecha),
    FOREIGN KEY (turno_id) REFERENCES turnos(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_excepciones_fecha ON turnos_excepciones (fecha);

CREATE TABLE IF NOT EXISTS faltas (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    estudio_id     INTEGER NOT NULL,
    alumno_id      INTEGER NOT NULL,
    instructor_id  INTEGER NOT NULL,
    turno_id       INTEGER,
    fecha          TEXT    NOT NULL,
    hora           INTEGER NOT NULL,
    descartada     INTEGER DEFAULT 0,
    creado_en      TEXT    DEFAULT (datetime('now')),
    FOREIGN KEY (estudio_id)    REFERENCES estudios(id)     ON DELETE CASCADE,
    FOREIGN KEY (alumno_id)     REFERENCES alumnos(id)      ON DELETE CASCADE,
    FOREIGN KEY (instructor_id) REFERENCES instructores(id) ON DELETE CASCADE,
    FOREIGN KEY (turno_id)      REFERENCES turnos(id)       ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_faltas_alumno ON faltas (alumno_id);
"""


def preparar_db():
    nueva = not os.path.exists(DATABASE)
    db = sqlite3.connect(DATABASE)
    try:
        if nueva:
            with open(SCHEMA, 'r', encoding='utf-8') as f:
                db.executescript(f.read())
            print(f"Base de datos creada: {DATABASE}")
        else:
            db.executescript(MIGRACIONES)
            columnas = [c[1] for c in db.execute("PRAGMA table_info(turnos)")]
            if 'recupera_falta_id' not in columnas:
                db.execute("ALTER TABLE turnos ADD COLUMN recupera_falta_id INTEGER "
                           "REFERENCES faltas(id) ON DELETE SET NULL")
        db.commit()
    finally:
        db.close()


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
    return db


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def query(sql, args=(), one=False):
    cur = get_db().execute(sql, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv


def execute(sql, args=()):
    db = get_db()
    cur = db.execute(sql, args)
    db.commit()
    return cur.lastrowid


# ============================================================
#  CSRF
# ============================================================
def csrf_token():
    if '_csrf' not in session:
        session['_csrf'] = secrets.token_urlsafe(32)
    return session['_csrf']


app.jinja_env.globals['csrf_token'] = csrf_token


@app.before_request
def verificar_csrf():
    if request.method != 'POST':
        return None
    enviado  = request.form.get('_csrf') or request.headers.get('X-CSRFToken') or ''
    esperado = session.get('_csrf', '')
    if esperado and secrets.compare_digest(enviado, esperado):
        return None
    if request.is_json:
        return jsonify({'ok': False, 'error': 'La sesión expiró. Recargá la página.'}), 400
    flash('La sesión expiró. Volvé a intentarlo.', 'warning')
    return redirect(request.referrer or url_for('login'))


@app.errorhandler(413)
def archivo_grande(e):
    flash('El archivo es demasiado grande (máximo 2 MB).', 'danger')
    return redirect(request.referrer or url_for('agenda'))


# ============================================================
#  HELPERS
# ============================================================
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        iid = session.get('instructor_id')
        if not iid:
            return redirect(url_for('login'))
        # Se revalida en cada request: un instructor desactivado pierde el acceso al instante
        inst = query("SELECT rol, activo, estudio_id FROM instructores WHERE id=?", (iid,), one=True)
        if not inst or not inst['activo'] or inst['estudio_id'] != session.get('estudio_id'):
            session.clear()
            if request.is_json:
                return jsonify({'ok': False, 'error': 'Sesión cerrada'}), 401
            return redirect(url_for('login'))
        session['rol'] = inst['rol']
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('rol') != 'admin':
            return redirect(url_for('agenda'))
        return f(*args, **kwargs)
    return decorated


def estudio_id():
    return session.get('estudio_id')


def instructor_id():
    return session.get('instructor_id')


def es_admin():
    return session.get('rol') == 'admin'


def get_estudio():
    return query("SELECT * FROM estudios WHERE id=?", (estudio_id(),), one=True)


def parse_int(valor, default=None):
    try:
        return int(valor)
    except (TypeError, ValueError):
        return default


def parse_float(valor, default=None):
    try:
        return float(valor)
    except (TypeError, ValueError):
        return default


def parse_fecha(valor):
    try:
        return datetime.strptime(valor or '', '%Y-%m-%d').date()
    except ValueError:
        return None


def parse_mes(valor):
    return valor if valor and re.fullmatch(r'\d{4}-(0[1-9]|1[0-2])', valor) else None


def alumno_del_estudio(aid):
    return query("SELECT * FROM alumnos WHERE id=? AND estudio_id=? AND activo=1",
                 (parse_int(aid, -1), estudio_id()), one=True)


def instructor_del_estudio(iid):
    return query("SELECT * FROM instructores WHERE id=? AND estudio_id=? AND activo=1",
                 (parse_int(iid, -1), estudio_id()), one=True)


def turno_editable(tid):
    """Turno del estudio; si no es admin, solo los propios."""
    if es_admin():
        return query("SELECT * FROM turnos WHERE id=? AND estudio_id=?",
                     (parse_int(tid, -1), estudio_id()), one=True)
    return query("SELECT * FROM turnos WHERE id=? AND estudio_id=? AND instructor_id=?",
                 (parse_int(tid, -1), estudio_id(), instructor_id()), one=True)


def dia_de(fecha):
    """Nombre del día para una fecha (None si es domingo)."""
    return DIAS[fecha.weekday()] if fecha.weekday() < 6 else None


def ocupacion_fija(iid, dia, hora, excluir=-1):
    return query(
        """SELECT COUNT(*) AS c FROM turnos t JOIN alumnos a ON a.id = t.alumno_id
           WHERE t.estudio_id=? AND t.instructor_id=? AND t.tipo='fijo'
             AND t.dia_semana=? AND t.hora=? AND t.id!=? AND a.activo=1""",
        (estudio_id(), iid, dia, hora, excluir), one=True
    )['c']


def ocupacion_fecha(iid, fecha, hora, excluir=-1):
    """Alumnos de un instructor en una fecha y hora concretas (fijos sin excepción + puntuales)."""
    return query(
        """SELECT COUNT(*) AS c FROM turnos t JOIN alumnos a ON a.id = t.alumno_id
           WHERE t.estudio_id=? AND t.instructor_id=? AND t.hora=? AND t.id!=? AND a.activo=1
             AND (
                 (t.tipo='puntual' AND t.fecha=?)
                 OR (t.tipo='fijo' AND t.dia_semana=? AND NOT EXISTS (
                        SELECT 1 FROM turnos_excepciones e
                        WHERE e.turno_id = t.id AND e.fecha=?))
             )""",
        (estudio_id(), iid, hora, excluir, fecha.isoformat(), dia_de(fecha), fecha.isoformat()),
        one=True
    )['c']


def alumno_ocupado(aid, hora, dia=None, fecha=None, excluir=-1):
    """True si el alumno ya tiene turno en ese horario (fijo por día, o en una fecha concreta)."""
    if fecha is None:
        sql = """SELECT 1 FROM turnos WHERE estudio_id=? AND alumno_id=? AND tipo='fijo'
                 AND dia_semana=? AND hora=? AND id!=?"""
        args = (estudio_id(), aid, dia, hora, excluir)
    else:
        sql = """SELECT 1 FROM turnos t WHERE t.estudio_id=? AND t.alumno_id=? AND t.hora=? AND t.id!=?
                 AND ((t.tipo='puntual' AND t.fecha=?)
                      OR (t.tipo='fijo' AND t.dia_semana=? AND NOT EXISTS (
                             SELECT 1 FROM turnos_excepciones e
                             WHERE e.turno_id = t.id AND e.fecha=?)))"""
        args = (estudio_id(), aid, hora, excluir, fecha.isoformat(), dia_de(fecha), fecha.isoformat())
    return query(sql, args, one=True) is not None


def deudores_del_mes(mes, iid=None):
    """Alumnos activos sin ningún pago en el mes. Con iid: solo los que tienen turno con ese instructor."""
    if iid is None:
        return query(
            """SELECT a.id, a.nombre, a.apellido FROM alumnos a
               WHERE a.estudio_id=? AND a.activo=1
                 AND a.id NOT IN (SELECT alumno_id FROM pagos WHERE estudio_id=? AND mes=?)
               ORDER BY a.apellido, a.nombre""",
            (estudio_id(), estudio_id(), mes)
        )
    return query(
        """SELECT DISTINCT a.id, a.nombre, a.apellido FROM alumnos a
           JOIN turnos t ON t.alumno_id = a.id
           WHERE t.estudio_id=? AND t.instructor_id=? AND a.activo=1
             AND a.id NOT IN (SELECT alumno_id FROM pagos WHERE estudio_id=? AND mes=?)
           ORDER BY a.apellido, a.nombre""",
        (estudio_id(), iid, estudio_id(), mes)
    )


def faltas_pendientes():
    """Clases perdidas que todavía no se recuperaron. Admin ve todas; instructor, las suyas."""
    return query(
        f"""SELECT f.id, f.alumno_id, f.instructor_id, f.fecha, f.hora,
                   a.nombre, a.apellido, a.telefono, i.nombre AS instructor_nombre
            FROM faltas f
            JOIN alumnos a ON a.id = f.alumno_id
            JOIN instructores i ON i.id = f.instructor_id
            WHERE f.estudio_id=? AND a.activo=1 AND f.descartada=0
              AND NOT EXISTS (SELECT 1 FROM turnos t WHERE t.recupera_falta_id = f.id)
              {'' if es_admin() else 'AND f.instructor_id=?'}
            ORDER BY f.fecha, f.hora""",
        (estudio_id(),) + (() if es_admin() else (instructor_id(),))
    )


def falta_editable(fid):
    """Falta pendiente del estudio; si no es admin, solo las propias."""
    pendientes = {f['id']: f for f in faltas_pendientes()}
    return pendientes.get(parse_int(fid, -1))


def registrar_falta(db, turno, fecha):
    """Anota la clase perdida de un turno fijo en esa fecha. Devuelve el id de la falta."""
    return db.execute(
        "INSERT INTO faltas (estudio_id, alumno_id, instructor_id, turno_id, fecha, hora) VALUES (?,?,?,?,?,?)",
        (turno['estudio_id'], turno['alumno_id'], turno['instructor_id'], turno['id'],
         fecha.isoformat(), turno['hora'])
    ).lastrowid


# ============================================================
#  AUTH — REGISTRO / LOGIN / LOGOUT
# ============================================================
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    error = None
    if request.method == 'POST':
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        nombre   = request.form.get('nombre_estudio', '').strip()

        if not email or not password or not nombre:
            error = 'Todos los campos son obligatorios.'
        elif len(password) < 6:
            error = 'La contraseña debe tener al menos 6 caracteres.'
        elif (query("SELECT id FROM usuarios WHERE email=?", (email,), one=True)
              or query("SELECT id FROM instructores WHERE email=?", (email,), one=True)):
            error = 'Ese email ya está registrado.'
        else:
            # Usuario dueño + estudio + instructor admin, todo o nada
            db = get_db()
            with db:
                pw  = generate_password_hash(password)
                uid = db.execute("INSERT INTO usuarios (email, password) VALUES (?,?)",
                                 (email, pw)).lastrowid
                eid = db.execute("INSERT INTO estudios (user_id, nombre) VALUES (?,?)",
                                 (uid, nombre)).lastrowid
                db.execute(
                    "INSERT INTO instructores (estudio_id, nombre, email, password, rol) VALUES (?,?,?,?,?)",
                    (eid, nombre, email, pw, 'admin')
                )
            flash('Cuenta creada. Ya podés ingresar.', 'success')
            return redirect(url_for('login'))

    return render_template('registro.html', error=error)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        inst = query("SELECT * FROM instructores WHERE email=? AND activo=1", (email,), one=True)

        if inst and check_password_hash(inst['password'], password):
            estudio = query("SELECT * FROM estudios WHERE id=?", (inst['estudio_id'],), one=True)
            session.clear()
            session['instructor_id']  = inst['id']
            session['estudio_id']     = inst['estudio_id']
            session['nombre']         = inst['nombre']
            session['rol']            = inst['rol']
            session['logo']           = estudio['logo_url'] if estudio else None
            session['estudio_nombre'] = estudio['nombre'] if estudio else 'Mi Estudio'
            return redirect(url_for('agenda'))
        error = 'Email o contraseña incorrectos.'

    return render_template('login.html', error=error)


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))


# ============================================================
#  PERFIL DEL ESTUDIO  (solo admin)
# ============================================================
@app.route('/perfil', methods=['GET', 'POST'])
@login_required
@admin_required
def perfil():
    estudio = get_estudio()
    if request.method == 'POST':
        nombre      = request.form.get('nombre_estudio', '').strip()
        valor_clase = max(parse_float(request.form.get('valor_clase'), 0) or 0, 0)
        valor_mes   = max(parse_float(request.form.get('valor_mes'), 0) or 0, 0)
        logo_url    = estudio['logo_url'] if estudio else None

        if not nombre:
            flash('El nombre del estudio es obligatorio.', 'danger')
            return redirect(url_for('perfil'))

        file = request.files.get('logo')
        if file and file.filename:
            if not allowed_file(file.filename):
                flash('El logo tiene que ser una imagen (png, jpg, gif o webp).', 'danger')
                return redirect(url_for('perfil'))
            ext = file.filename.rsplit('.', 1)[1].lower()
            filename = secure_filename(f"logo_{estudio_id()}_{secrets.token_hex(4)}.{ext}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            if logo_url and logo_url != filename:
                anterior = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(logo_url))
                if os.path.isfile(anterior):
                    os.remove(anterior)
            logo_url = filename

        execute(
            "UPDATE estudios SET nombre=?, logo_url=?, valor_clase=?, valor_mes=? WHERE id=?",
            (nombre, logo_url, valor_clase, valor_mes, estudio_id())
        )
        session['estudio_nombre'] = nombre
        session['logo']           = logo_url
        flash('Datos del estudio guardados.', 'success')
        return redirect(url_for('agenda'))

    return render_template('perfil.html', estudio=estudio)


# ============================================================
#  GESTIÓN DE INSTRUCTORES  (solo admin)
# ============================================================
@app.route('/instructores')
@login_required
@admin_required
def instructores():
    lista = query(
        "SELECT * FROM instructores WHERE estudio_id=? ORDER BY activo DESC, nombre",
        (estudio_id(),)
    )
    return render_template('instructores.html', instructores=lista)


@app.route('/agregar_instructor', methods=['POST'])
@login_required
@admin_required
def agregar_instructor():
    nombre   = request.form.get('nombre', '').strip()
    email    = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    rol      = request.form.get('rol', 'instructor')

    if not nombre or not email:
        flash('Nombre y email son obligatorios.', 'danger')
    elif len(password) < 6:
        flash('La contraseña debe tener al menos 6 caracteres.', 'danger')
    elif rol not in ('admin', 'instructor'):
        flash('Rol inválido.', 'danger')
    elif query("SELECT id FROM instructores WHERE email=?", (email,), one=True):
        flash('Ya existe un instructor con ese email.', 'danger')
    else:
        execute(
            "INSERT INTO instructores (estudio_id, nombre, email, password, rol) VALUES (?,?,?,?,?)",
            (estudio_id(), nombre, email, generate_password_hash(password), rol)
        )
        flash(f'{nombre} fue agregado al equipo.', 'success')
    return redirect(url_for('instructores'))


@app.route('/editar_instructor/<int:iid>', methods=['POST'])
@login_required
@admin_required
def editar_instructor(iid):
    nombre   = request.form.get('nombre', '').strip()
    rol      = request.form.get('rol', 'instructor')
    password = request.form.get('password', '').strip()

    actual = query("SELECT * FROM instructores WHERE id=? AND estudio_id=?",
                   (iid, estudio_id()), one=True)
    if not actual:
        return redirect(url_for('instructores'))
    if iid == instructor_id():
        rol = actual['rol']   # nadie puede cambiarse su propio rol
    if not nombre or rol not in ('admin', 'instructor'):
        flash('Datos inválidos.', 'danger')
        return redirect(url_for('instructores'))
    if password and len(password) < 6:
        flash('La contraseña debe tener al menos 6 caracteres.', 'danger')
        return redirect(url_for('instructores'))

    if password:
        execute(
            "UPDATE instructores SET nombre=?, rol=?, password=? WHERE id=? AND estudio_id=?",
            (nombre, rol, generate_password_hash(password), iid, estudio_id())
        )
    else:
        execute(
            "UPDATE instructores SET nombre=?, rol=? WHERE id=? AND estudio_id=?",
            (nombre, rol, iid, estudio_id())
        )
    if iid == instructor_id():
        session['nombre'] = nombre
    flash('Instructor actualizado.', 'success')
    return redirect(url_for('instructores'))


@app.route('/desactivar_instructor/<int:iid>', methods=['POST'])
@login_required
@admin_required
def desactivar_instructor(iid):
    if iid != instructor_id():   # no puede desactivarse a sí mismo
        execute("UPDATE instructores SET activo=0 WHERE id=? AND estudio_id=?", (iid, estudio_id()))
        flash('Instructor desactivado. Ya no puede ingresar.', 'success')
    return redirect(url_for('instructores'))


@app.route('/activar_instructor/<int:iid>', methods=['POST'])
@login_required
@admin_required
def activar_instructor(iid):
    execute("UPDATE instructores SET activo=1 WHERE id=? AND estudio_id=?", (iid, estudio_id()))
    flash('Instructor reactivado.', 'success')
    return redirect(url_for('instructores'))


# ============================================================
#  AGENDA  (pantalla principal)
# ============================================================
@app.route('/')
@app.route('/agenda')
@login_required
def agenda():
    eid = estudio_id()
    iid = instructor_id()
    hoy = date.today()

    fecha_ref = parse_fecha(request.args.get('fecha')) or hoy
    if fecha_ref.weekday() == 6:          # domingo → mostrar la semana que empieza
        fecha_ref += timedelta(days=1)
    inicio = fecha_ref - timedelta(days=fecha_ref.weekday())
    fechas = [inicio + timedelta(days=i) for i in range(6)]
    fin    = fechas[-1]

    # Admin ve todos los turnos, instructor solo los suyos
    filtro_inst = () if es_admin() else (iid,)
    cond_inst   = "" if es_admin() else "AND t.instructor_id=?"
    columnas = """t.id, t.tipo, t.dia_semana, t.fecha, t.hora, t.alumno_id, t.instructor_id,
                  t.recupera_falta_id, a.nombre, a.apellido, a.telefono, i.nombre AS instructor_nombre"""

    turnos_fijos = query(
        f"""SELECT {columnas} FROM turnos t
            JOIN alumnos a ON t.alumno_id = a.id
            JOIN instructores i ON t.instructor_id = i.id
            WHERE t.estudio_id=? AND t.tipo='fijo' AND a.activo=1 {cond_inst}""",
        (eid,) + filtro_inst
    )
    turnos_puntuales = query(
        f"""SELECT {columnas} FROM turnos t
            JOIN alumnos a ON t.alumno_id = a.id
            JOIN instructores i ON t.instructor_id = i.id
            WHERE t.estudio_id=? AND t.tipo='puntual' AND a.activo=1
              AND t.fecha BETWEEN ? AND ? {cond_inst}""",
        (eid, inicio.isoformat(), fin.isoformat()) + filtro_inst
    )
    excepciones = {
        (e['turno_id'], e['fecha']) for e in query(
            """SELECT e.turno_id, e.fecha FROM turnos_excepciones e
               JOIN turnos t ON t.id = e.turno_id
               WHERE t.estudio_id=? AND e.fecha BETWEEN ? AND ?""",
            (eid, inicio.isoformat(), fin.isoformat())
        )
    }
    mes_actual = hoy.strftime('%Y-%m')
    pagados = {p['alumno_id'] for p in query(
        "SELECT DISTINCT alumno_id FROM pagos WHERE estudio_id=? AND mes=?", (eid, mes_actual)
    )}

    # celdas[(índice_día, hora)] → lista de turnos que ocurren ese día y hora
    celdas = {(d, h): [] for d in range(6) for h in HORAS}

    def agregar(t, d, fecha):
        if t['hora'] not in HORAS:
            return
        item = dict(t)
        item['fecha_turno'] = fecha.isoformat()
        item['pagado'] = t['alumno_id'] in pagados
        celdas[(d, t['hora'])].append(item)

    for t in turnos_fijos:
        if t['dia_semana'] in DIAS:
            d = DIAS.index(t['dia_semana'])
            if (t['id'], fechas[d].isoformat()) not in excepciones:
                agregar(t, d, fechas[d])
    for t in turnos_puntuales:
        f = parse_fecha(t['fecha'])
        if f and f.weekday() < 6:
            agregar(t, f.weekday(), f)

    for lista in celdas.values():
        lista.sort(key=lambda t: (t['apellido'].lower(), t['nombre'].lower()))
    por_dia = [sum(len(celdas[(d, h)]) for h in HORAS) for d in range(6)]

    alumnos_list = query(
        "SELECT id, nombre, apellido FROM alumnos WHERE estudio_id=? AND activo=1 ORDER BY apellido, nombre",
        (eid,)
    )
    instructores_list = query(
        "SELECT id, nombre FROM instructores WHERE estudio_id=? AND activo=1 ORDER BY nombre", (eid,)
    ) if es_admin() else []

    # Clases pendientes de recuperar (lista + cantidad por alumno para marcar las pastillas)
    pendientes = [dict(f) for f in faltas_pendientes()]
    pendientes_por_alumno = {}
    for f in pendientes:
        pendientes_por_alumno.setdefault(f['alumno_id'], []).append(f['id'])

    # Resumen (se muestra como "pastillas" arriba de la agenda)
    deudores = deudores_del_mes(mes_actual, None if es_admin() else iid)
    cobrado_mes = query(
        "SELECT COALESCE(SUM(monto),0) AS t FROM pagos WHERE estudio_id=? AND mes=?" +
        ("" if es_admin() else " AND instructor_id=?"),
        (eid, mes_actual) + (() if es_admin() else (iid,)), one=True
    )['t']

    return render_template('agenda.html',
        celdas=celdas,
        por_dia=por_dia,
        fechas=fechas,
        inicio=inicio,
        fin=fin,
        hoy=hoy,
        dias=DIAS,
        dias_corto=DIAS_CORTO,
        horas=HORAS,
        cupo_max=CUPO_MAX,
        alumnos=alumnos_list,
        instructores=instructores_list,
        deudores=deudores,
        cobrado_mes=cobrado_mes,
        pendientes=pendientes,
        pendientes_por_alumno=pendientes_por_alumno,
        semana_anterior=(inicio - timedelta(days=7)).isoformat(),
        semana_siguiente=(inicio + timedelta(days=7)).isoformat(),
        es_admin=es_admin(),
        multi=es_admin() and len(instructores_list) > 1,   # varios instructores → filtro y etiquetas
        mi_instructor_id=iid
    )


@app.route('/agregar_turno', methods=['POST'])
@login_required
def agregar_turno():
    f         = request.form
    fecha_ref = f.get('fecha_ref', '')
    volver    = redirect(url_for('agenda', fecha=fecha_ref) if parse_fecha(fecha_ref) else url_for('agenda'))

    alumno = alumno_del_estudio(f.get('alumno_id'))
    tipo   = f.get('tipo', 'fijo')
    hora   = parse_int(f.get('hora'))
    inst   = instructor_del_estudio(f.get('instructor_id')) if es_admin() else instructor_del_estudio(instructor_id())

    if not alumno:
        flash('Elegí un alumno válido.', 'danger')
        return volver
    if not inst:
        flash('Elegí un instructor válido.', 'danger')
        return volver
    if hora not in HORAS or tipo not in ('fijo', 'puntual'):
        flash('Horario inválido.', 'danger')
        return volver

    if tipo == 'fijo':
        dia = f.get('dia_semana')
        if dia not in DIAS:
            flash('Día inválido.', 'danger')
            return volver
        if alumno_ocupado(alumno['id'], hora, dia=dia):
            flash(f"{alumno['nombre']} ya tiene turno fijo el {dia} a las {hora:02d}:00.", 'warning')
            return volver
        if ocupacion_fija(inst['id'], dia, hora) >= CUPO_MAX:
            flash(f'El horario {dia} {hora:02d}:00 de {inst["nombre"]} está completo.', 'warning')
            return volver
        execute(
            "INSERT INTO turnos (estudio_id, instructor_id, alumno_id, tipo, dia_semana, hora) VALUES (?,?,?,?,?,?)",
            (estudio_id(), inst['id'], alumno['id'], 'fijo', dia, hora)
        )
    else:
        fecha = parse_fecha(f.get('fecha'))
        if not fecha or not dia_de(fecha):
            flash('Fecha inválida (no se dan clases los domingos).', 'danger')
            return volver
        if alumno_ocupado(alumno['id'], hora, fecha=fecha):
            flash(f"{alumno['nombre']} ya tiene turno ese día a las {hora:02d}:00.", 'warning')
            return volver
        if ocupacion_fecha(inst['id'], fecha, hora) >= CUPO_MAX:
            flash(f'Ese horario de {inst["nombre"]} está completo.', 'warning')
            return volver
        execute(
            "INSERT INTO turnos (estudio_id, instructor_id, alumno_id, tipo, fecha, hora) VALUES (?,?,?,?,?,?)",
            (estudio_id(), inst['id'], alumno['id'], 'puntual', fecha.isoformat(), hora)
        )
        fecha_ref = fecha.isoformat()

    return redirect(url_for('agenda', fecha=fecha_ref) if parse_fecha(fecha_ref) else url_for('agenda'))


@app.route('/mover_turno', methods=['POST'])
@login_required
def mover_turno():
    """
    Mueve un turno a otra fecha/hora.
    Turno fijo + modo 'siempre' → cambia el día/hora de todas las semanas.
    Turno fijo + modo 'semana'  → solo esa semana: se saltea la fecha original
                                  y se crea un turno puntual en el destino.
    """
    data   = request.get_json(silent=True) or {}
    turno  = turno_editable(data.get('id'))
    hora   = parse_int(data.get('hora'))
    fecha  = parse_fecha(data.get('fecha'))
    modo   = data.get('modo', 'siempre')

    if not turno:
        return jsonify({'ok': False, 'error': 'No autorizado'}), 403
    if hora not in HORAS or not fecha or not dia_de(fecha):
        return jsonify({'ok': False, 'error': 'Horario inválido'}), 400

    dia  = dia_de(fecha)
    tid  = turno['id']
    lleno = {'ok': False, 'error': f'Ese horario ya tiene {CUPO_MAX} alumnos'}
    ocupado = {'ok': False, 'error': 'El alumno ya tiene turno en ese horario'}

    if turno['tipo'] == 'fijo' and modo == 'semana':
        origen = parse_fecha(data.get('fecha_origen'))
        if not origen or dia_de(origen) != turno['dia_semana']:
            return jsonify({'ok': False, 'error': 'Fecha de origen inválida'}), 400
        if origen == fecha and hora == turno['hora']:
            return jsonify({'ok': True})
        if alumno_ocupado(turno['alumno_id'], hora, fecha=fecha, excluir=tid):
            return jsonify(ocupado), 409
        if ocupacion_fecha(turno['instructor_id'], fecha, hora, excluir=tid) >= CUPO_MAX:
            return jsonify(lleno), 409
        db = get_db()
        with db:
            db.execute("INSERT OR IGNORE INTO turnos_excepciones (turno_id, fecha) VALUES (?,?)",
                       (tid, origen.isoformat()))
            # Queda registrada como falta ya recuperada: si después se quita la clase
            # nueva, la falta vuelve a estar pendiente de recuperar.
            fid = registrar_falta(db, turno, origen)
            db.execute(
                """INSERT INTO turnos (estudio_id, instructor_id, alumno_id, tipo, fecha, hora, recupera_falta_id)
                   VALUES (?,?,?,?,?,?,?)""",
                (turno['estudio_id'], turno['instructor_id'], turno['alumno_id'], 'puntual',
                 fecha.isoformat(), hora, fid)
            )
    elif turno['tipo'] == 'fijo':
        if dia == turno['dia_semana'] and hora == turno['hora']:
            return jsonify({'ok': True})
        if alumno_ocupado(turno['alumno_id'], hora, dia=dia, excluir=tid):
            return jsonify(ocupado), 409
        if ocupacion_fija(turno['instructor_id'], dia, hora, excluir=tid) >= CUPO_MAX:
            return jsonify(lleno), 409
        db = get_db()
        with db:
            db.execute("UPDATE turnos SET dia_semana=?, hora=? WHERE id=?", (dia, hora, tid))
            db.execute("DELETE FROM turnos_excepciones WHERE turno_id=?", (tid,))
    else:
        if alumno_ocupado(turno['alumno_id'], hora, fecha=fecha, excluir=tid):
            return jsonify(ocupado), 409
        if ocupacion_fecha(turno['instructor_id'], fecha, hora, excluir=tid) >= CUPO_MAX:
            return jsonify(lleno), 409
        execute("UPDATE turnos SET fecha=?, hora=? WHERE id=?", (fecha.isoformat(), hora, tid))

    return jsonify({'ok': True})


@app.route('/quitar_turno', methods=['POST'])
@login_required
def quitar_turno():
    """Turno fijo + modo 'semana' → solo se saltea esa fecha. Si no, se borra el turno."""
    data  = request.get_json(silent=True) or {}
    turno = turno_editable(data.get('id'))
    if not turno:
        return jsonify({'ok': False, 'error': 'No autorizado'}), 403

    if turno['tipo'] == 'fijo' and data.get('modo') == 'semana':
        fecha = parse_fecha(data.get('fecha'))
        if not fecha or dia_de(fecha) != turno['dia_semana']:
            return jsonify({'ok': False, 'error': 'Fecha inválida'}), 400
        db = get_db()
        with db:
            nueva = db.execute("INSERT OR IGNORE INTO turnos_excepciones (turno_id, fecha) VALUES (?,?)",
                               (turno['id'], fecha.isoformat())).rowcount
            if nueva:   # falta avisada → queda pendiente de recuperar
                registrar_falta(db, turno, fecha)
    else:
        execute("DELETE FROM turnos WHERE id=?", (turno['id'],))
    return jsonify({'ok': True})


# ============================================================
#  RECUPERACIÓN DE CLASES
# ============================================================
@app.route('/recuperar', methods=['POST'])
@login_required
def recuperar():
    """Agenda la recuperación de una falta pendiente como turno puntual."""
    data  = request.get_json(silent=True) or {}
    falta = falta_editable(data.get('falta_id'))
    hora  = parse_int(data.get('hora'))
    fecha = parse_fecha(data.get('fecha'))

    if not falta:
        return jsonify({'ok': False, 'error': 'Esa clase ya no está pendiente de recuperar'}), 404
    if hora not in HORAS or not fecha or not dia_de(fecha):
        return jsonify({'ok': False, 'error': 'Horario inválido'}), 400
    if not instructor_del_estudio(falta['instructor_id']):
        return jsonify({'ok': False, 'error': 'El instructor de esa clase está inactivo'}), 409
    if alumno_ocupado(falta['alumno_id'], hora, fecha=fecha):
        return jsonify({'ok': False, 'error': 'El alumno ya tiene turno en ese horario'}), 409
    if ocupacion_fecha(falta['instructor_id'], fecha, hora) >= CUPO_MAX:
        return jsonify({'ok': False, 'error': f'Ese horario ya tiene {CUPO_MAX} alumnos'}), 409

    execute(
        """INSERT INTO turnos (estudio_id, instructor_id, alumno_id, tipo, fecha, hora, recupera_falta_id)
           VALUES (?,?,?,?,?,?,?)""",
        (estudio_id(), falta['instructor_id'], falta['alumno_id'], 'puntual', fecha.isoformat(), hora, falta['id'])
    )
    return jsonify({'ok': True})


@app.route('/descartar_falta', methods=['POST'])
@login_required
def descartar_falta():
    """La clase no se va a recuperar: deja de figurar como pendiente."""
    falta = falta_editable((request.get_json(silent=True) or {}).get('falta_id'))
    if not falta:
        return jsonify({'ok': False, 'error': 'Esa clase ya no está pendiente'}), 404
    execute("UPDATE faltas SET descartada=1 WHERE id=?", (falta['id'],))
    return jsonify({'ok': True})


@app.route('/anular_falta', methods=['POST'])
@login_required
def anular_falta():
    """La falta se marcó por error: se borra y el alumno vuelve a su clase de esa fecha."""
    falta = falta_editable((request.get_json(silent=True) or {}).get('falta_id'))
    if not falta:
        return jsonify({'ok': False, 'error': 'Esa clase ya no está pendiente'}), 404
    origen = query("SELECT turno_id FROM faltas WHERE id=?", (falta['id'],), one=True)['turno_id']
    db = get_db()
    with db:
        if origen:
            db.execute("DELETE FROM turnos_excepciones WHERE turno_id=? AND fecha=?", (origen, falta['fecha']))
        db.execute("DELETE FROM faltas WHERE id=?", (falta['id'],))
    return jsonify({'ok': True})


# ============================================================
#  ALUMNOS  (todos del estudio, visibles para todos)
# ============================================================
CAMPOS_ALUMNO = ('nombre', 'apellido', 'dni', 'fecha_nacimiento', 'sexo', 'domicilio',
                 'telefono', 'contacto_emergencia', 'obra_social', 'medico_cabecera',
                 'apto_medico', 'patologias_columna', 'cirugias', 'notas_medicas', 'observaciones')


def datos_alumno_form(f):
    def txt(campo):
        return f.get(campo, '').strip() or None
    fecha_nac = parse_fecha(f.get('fecha_nacimiento'))
    sexo = f.get('sexo')
    return (
        f.get('nombre', '').strip(),
        f.get('apellido', '').strip(),
        txt('dni'),
        fecha_nac.isoformat() if fecha_nac else None,
        sexo if sexo in ('F', 'M', 'X') else None,
        txt('domicilio'),
        txt('telefono'),
        txt('contacto_emergencia'),
        txt('obra_social'),
        txt('medico_cabecera'),
        1 if f.get('apto_medico') else 0,
        txt('patologias_columna'),
        txt('cirugias'),
        txt('notas_medicas'),
        txt('observaciones'),
    )


@app.route('/alumnos')
@login_required
def alumnos():
    eid    = estudio_id()
    buscar = request.args.get('q', '').strip()

    if buscar:
        patron = f'%{buscar}%'
        alumnos_data = query(
            """SELECT * FROM alumnos WHERE estudio_id=? AND activo=1
               AND (nombre LIKE ? OR apellido LIKE ? OR dni LIKE ?)
               ORDER BY apellido, nombre""",
            (eid, patron, patron, patron)
        )
    else:
        alumnos_data = query(
            "SELECT * FROM alumnos WHERE estudio_id=? AND activo=1 ORDER BY apellido, nombre",
            (eid,)
        )

    # Horarios fijos de cada alumno, para mostrarlos en la lista
    horarios = {}
    for t in query(
        """SELECT t.alumno_id, t.dia_semana, t.hora FROM turnos t
           WHERE t.estudio_id=? AND t.tipo='fijo'""", (eid,)
    ):
        if t['dia_semana'] in DIAS:
            horarios.setdefault(t['alumno_id'], []).append((DIAS.index(t['dia_semana']), t['hora']))
    horarios = {
        aid: [f"{DIAS_CORTO[d]} {h:02d}" for d, h in sorted(lista)]
        for aid, lista in horarios.items()
    }

    por_recuperar = {}
    for f in faltas_pendientes():
        por_recuperar[f['alumno_id']] = por_recuperar.get(f['alumno_id'], 0) + 1

    return render_template('alumnos.html', alumnos=alumnos_data, buscar=buscar,
                           horarios=horarios, por_recuperar=por_recuperar)


@app.route('/agregar_alumno', methods=['POST'])
@login_required
def agregar_alumno():
    datos = datos_alumno_form(request.form)
    if not datos[0] or not datos[1]:
        flash('Nombre y apellido son obligatorios.', 'danger')
        return redirect(url_for('alumnos'))
    execute(
        f"""INSERT INTO alumnos (estudio_id, {', '.join(CAMPOS_ALUMNO)})
            VALUES (?{', ?' * len(CAMPOS_ALUMNO)})""",
        (estudio_id(),) + datos
    )
    flash(f'{datos[0]} {datos[1]} fue registrado.', 'success')
    return redirect(url_for('alumnos'))


@app.route('/editar_alumno/<int:aid>', methods=['POST'])
@login_required
def editar_alumno(aid):
    datos = datos_alumno_form(request.form)
    if not datos[0] or not datos[1]:
        flash('Nombre y apellido son obligatorios.', 'danger')
        return redirect(url_for('alumnos'))
    execute(
        f"""UPDATE alumnos SET {', '.join(c + '=?' for c in CAMPOS_ALUMNO)}
            WHERE id=? AND estudio_id=?""",
        datos + (aid, estudio_id())
    )
    flash('Ficha actualizada.', 'success')
    return redirect(url_for('alumnos'))


@app.route('/eliminar_alumno/<int:aid>', methods=['POST'])
@login_required
def eliminar_alumno(aid):
    alumno = alumno_del_estudio(aid)
    if alumno:
        db = get_db()
        with db:
            db.execute("UPDATE alumnos SET activo=0 WHERE id=?", (aid,))
            db.execute("DELETE FROM turnos WHERE alumno_id=? AND estudio_id=?", (aid, estudio_id()))
        flash(f"{alumno['nombre']} {alumno['apellido']} fue dado de baja y se liberaron sus turnos.", 'success')
    return redirect(url_for('alumnos'))


# ============================================================
#  FACTURACIÓN
# ============================================================
@app.route('/facturacion')
@login_required
def facturacion():
    eid        = estudio_id()
    iid        = instructor_id()
    mes_filtro = parse_mes(request.args.get('mes')) or date.today().strftime('%Y-%m')

    alumnos_list = query(
        "SELECT id, nombre, apellido FROM alumnos WHERE estudio_id=? AND activo=1 ORDER BY apellido, nombre",
        (eid,)
    )

    # Admin ve todos los pagos, instructor solo los que cobró él
    if es_admin():
        pagos_list = query(
            """SELECT p.*, a.nombre||' '||a.apellido AS alumno_nombre, i.nombre AS instructor_nombre
               FROM pagos p
               JOIN alumnos a ON p.alumno_id = a.id
               JOIN instructores i ON p.instructor_id = i.id
               WHERE p.estudio_id=? AND p.mes=?
               ORDER BY p.fecha DESC, p.id DESC""",
            (eid, mes_filtro)
        )
        meses_con_pagos = query(
            "SELECT DISTINCT mes FROM pagos WHERE estudio_id=? ORDER BY mes DESC LIMIT 12", (eid,)
        )
    else:
        pagos_list = query(
            """SELECT p.*, a.nombre||' '||a.apellido AS alumno_nombre, ? AS instructor_nombre
               FROM pagos p
               JOIN alumnos a ON p.alumno_id = a.id
               WHERE p.estudio_id=? AND p.instructor_id=? AND p.mes=?
               ORDER BY p.fecha DESC, p.id DESC""",
            (session.get('nombre'), eid, iid, mes_filtro)
        )
        meses_con_pagos = query(
            "SELECT DISTINCT mes FROM pagos WHERE estudio_id=? AND instructor_id=? ORDER BY mes DESC LIMIT 12",
            (eid, iid)
        )

    estudio = get_estudio()
    alumno_pre = alumno_del_estudio(request.args.get('alumno')) if request.args.get('alumno') else None

    return render_template('facturacion.html',
        alumnos=alumnos_list,
        pagos=pagos_list,
        total_mes=sum(p['monto'] for p in pagos_list),
        deudores=deudores_del_mes(mes_filtro, None if es_admin() else iid),
        mes_filtro=mes_filtro,
        meses_con_pagos=meses_con_pagos,
        nombre_estudio=estudio['nombre'] if estudio else 'Mi Estudio',
        valor_mes=(estudio['valor_mes'] or 0) if estudio else 0,
        alumno_pre=alumno_pre['id'] if alumno_pre else None,
        now_mes=date.today().strftime('%Y-%m'),
        es_admin=es_admin()
    )


@app.route('/registrar_pago', methods=['POST'])
@login_required
def registrar_pago():
    f        = request.form
    alumno   = alumno_del_estudio(f.get('alumno_id'))
    monto    = parse_float(f.get('monto'))
    mes      = parse_mes(f.get('mes'))
    concepto = (f.get('concepto') or '').strip()[:100] or 'Cuota Mensual'

    if not alumno:
        flash('Elegí un alumno válido.', 'danger')
    elif not monto or monto <= 0:
        flash('El monto tiene que ser mayor a cero.', 'danger')
    elif not mes:
        flash('Mes inválido.', 'danger')
    else:
        execute(
            "INSERT INTO pagos (estudio_id, instructor_id, alumno_id, monto, concepto, mes) VALUES (?,?,?,?,?,?)",
            (estudio_id(), instructor_id(), alumno['id'], monto, concepto, mes)
        )
        flash(f"Pago de {alumno['nombre']} {alumno['apellido']} registrado.", 'success')
    return redirect(url_for('facturacion', mes=mes or None))


@app.route('/eliminar_pago/<int:pid>', methods=['POST'])
@login_required
def eliminar_pago(pid):
    mes = parse_mes(request.form.get('mes'))
    if es_admin():
        execute("DELETE FROM pagos WHERE id=? AND estudio_id=?", (pid, estudio_id()))
    else:
        execute("DELETE FROM pagos WHERE id=? AND estudio_id=? AND instructor_id=?",
                (pid, estudio_id(), instructor_id()))
    flash('Pago eliminado.', 'success')
    return redirect(url_for('facturacion', mes=mes))


# ============================================================
#  API JSON
# ============================================================
@app.route('/api/alumnos')
@login_required
def api_alumnos():
    data = query(
        "SELECT id, nombre, apellido, telefono FROM alumnos WHERE estudio_id=? AND activo=1 ORDER BY apellido",
        (estudio_id(),)
    )
    return jsonify([dict(a) for a in data])


# ============================================================
#  INICIO
# ============================================================
preparar_db()

if __name__ == '__main__':
    port  = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG') == '1'   # el debugger solo si se pide explícitamente
    app.run(host=os.environ.get('HOST', '0.0.0.0'), port=port, debug=debug)

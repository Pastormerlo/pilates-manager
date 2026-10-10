-- ============================================================
--  PILATES MANAGER — Schema v3.1
--  ATENCIÓN: este script BORRA todas las tablas. Solo se usa para crear
--  una base nueva (app.py lo ejecuta si pilates.db no existe).
--  Soporte multi-instructor por estudio
-- ============================================================

DROP TABLE IF EXISTS turnos_excepciones;
DROP TABLE IF EXISTS pagos;
DROP TABLE IF EXISTS turnos;
DROP TABLE IF EXISTS alumnos;
DROP TABLE IF EXISTS instructores;
DROP TABLE IF EXISTS estudios;
DROP TABLE IF EXISTS usuarios;
DROP TABLE IF EXISTS configuracion;

-- ------------------------------------------------------------
-- 1. USUARIOS  (dueños de estudio que se registran)
-- ------------------------------------------------------------
CREATE TABLE usuarios (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    email       TEXT    NOT NULL UNIQUE,
    password    TEXT    NOT NULL,
    creado_en   TEXT    DEFAULT (datetime('now'))
);

-- ------------------------------------------------------------
-- 2. ESTUDIOS  (uno por usuario/dueño)
-- ------------------------------------------------------------
CREATE TABLE estudios (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL UNIQUE,
    nombre      TEXT    NOT NULL DEFAULT 'Mi Estudio',
    logo_url    TEXT,
    valor_clase REAL    DEFAULT 0,
    valor_mes   REAL    DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

-- ------------------------------------------------------------
-- 3. INSTRUCTORES
--    rol = 'admin'      → dueño, ve y hace todo
--    rol = 'instructor' → solo su agenda y sus cobros
-- ------------------------------------------------------------
CREATE TABLE instructores (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    estudio_id  INTEGER NOT NULL,
    nombre      TEXT    NOT NULL,
    email       TEXT    NOT NULL UNIQUE,
    password    TEXT    NOT NULL,
    rol         TEXT    NOT NULL DEFAULT 'instructor'
                CHECK (rol IN ('admin', 'instructor')),
    activo      INTEGER DEFAULT 1,
    creado_en   TEXT    DEFAULT (datetime('now')),
    FOREIGN KEY (estudio_id) REFERENCES estudios(id) ON DELETE CASCADE
);

-- ------------------------------------------------------------
-- 4. ALUMNOS  (del estudio, no de un instructor específico)
-- ------------------------------------------------------------
CREATE TABLE alumnos (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    estudio_id           INTEGER NOT NULL,
    nombre               TEXT    NOT NULL,
    apellido             TEXT    NOT NULL DEFAULT '',
    dni                  TEXT,
    fecha_nacimiento     TEXT,
    sexo                 TEXT,
    domicilio            TEXT,
    telefono             TEXT,
    contacto_emergencia  TEXT,
    obra_social          TEXT,
    medico_cabecera      TEXT,
    apto_medico          INTEGER DEFAULT 0,
    patologias_columna   TEXT,
    cirugias             TEXT,
    notas_medicas        TEXT,
    activo               INTEGER DEFAULT 1,
    fecha_inicio         TEXT    DEFAULT (date('now')),
    observaciones        TEXT,
    FOREIGN KEY (estudio_id) REFERENCES estudios(id) ON DELETE CASCADE
);

-- ------------------------------------------------------------
-- 5. TURNOS  (cada turno pertenece a un instructor)
-- ------------------------------------------------------------
CREATE TABLE turnos (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    estudio_id      INTEGER NOT NULL,
    instructor_id   INTEGER NOT NULL,
    alumno_id       INTEGER NOT NULL,
    tipo            TEXT    NOT NULL DEFAULT 'fijo'
                    CHECK (tipo IN ('fijo', 'puntual')),
    dia_semana      TEXT    CHECK (dia_semana IN
                        ('Lunes','Martes','Miércoles','Jueves','Viernes','Sábado')),
    fecha           TEXT,
    hora            INTEGER NOT NULL CHECK (hora BETWEEN 7 AND 22),
    FOREIGN KEY (estudio_id)    REFERENCES estudios(id)     ON DELETE CASCADE,
    FOREIGN KEY (instructor_id) REFERENCES instructores(id) ON DELETE CASCADE,
    FOREIGN KEY (alumno_id)     REFERENCES alumnos(id)      ON DELETE CASCADE
);

-- ------------------------------------------------------------
-- 5b. EXCEPCIONES  (fechas en que un turno fijo NO ocurre:
--     falta avisada o clase movida solo por esa semana)
-- ------------------------------------------------------------
CREATE TABLE turnos_excepciones (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    turno_id  INTEGER NOT NULL,
    fecha     TEXT    NOT NULL,
    UNIQUE (turno_id, fecha),
    FOREIGN KEY (turno_id) REFERENCES turnos(id) ON DELETE CASCADE
);

-- ------------------------------------------------------------
-- 6. PAGOS  (cada pago pertenece a un instructor)
-- ------------------------------------------------------------
CREATE TABLE pagos (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    estudio_id      INTEGER NOT NULL,
    instructor_id   INTEGER NOT NULL,
    alumno_id       INTEGER NOT NULL,
    monto           REAL    NOT NULL,
    concepto        TEXT    NOT NULL DEFAULT 'Cuota Mensual',
    mes             TEXT    NOT NULL,
    fecha           TEXT    DEFAULT (date('now')),
    FOREIGN KEY (estudio_id)    REFERENCES estudios(id)     ON DELETE CASCADE,
    FOREIGN KEY (instructor_id) REFERENCES instructores(id) ON DELETE CASCADE,
    FOREIGN KEY (alumno_id)     REFERENCES alumnos(id)      ON DELETE CASCADE
);

-- ------------------------------------------------------------
-- 7. CONFIGURACION
-- ------------------------------------------------------------
CREATE TABLE configuracion (
    clave TEXT PRIMARY KEY,
    valor TEXT
);

INSERT INTO configuracion VALUES ('version_schema', '3.1');

-- ------------------------------------------------------------
-- Índices
-- ------------------------------------------------------------
CREATE INDEX idx_instructores_estudio ON instructores (estudio_id);
CREATE INDEX idx_alumnos_estudio      ON alumnos      (estudio_id);
CREATE INDEX idx_turnos_estudio       ON turnos       (estudio_id);
CREATE INDEX idx_turnos_instructor    ON turnos       (instructor_id);
CREATE INDEX idx_turnos_alumno        ON turnos       (alumno_id);
CREATE INDEX idx_pagos_estudio        ON pagos        (estudio_id);
CREATE INDEX idx_pagos_instructor     ON pagos        (instructor_id);
CREATE INDEX idx_pagos_alumno         ON pagos        (alumno_id);
CREATE INDEX idx_pagos_mes            ON pagos        (mes);
CREATE INDEX idx_excepciones_fecha    ON turnos_excepciones (fecha);

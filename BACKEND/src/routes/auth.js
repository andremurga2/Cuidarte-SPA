const express = require("express");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { pool } = require("../db");
const validate = require("../middleware/validate");
const { loginSchema, registerSchema } = require("../validations/auth");
const { normalizeRut } = require("../utils/rut");
const { JWT_SECRET } = require("../config");
const { hashPassword, verifyPassword } = require("../utils/password");
const { revoke } = require("../utils/revoked");
const router = express.Router();

const MAX_INTENTOS = 5;
const BLOQUEO_MS = 15 * 60 * 1000;
const intentos = new Map();
function estaBloqueado(u) {
  const a = intentos.get(u);
  if (!a || !a.hasta) return false;
  if (Date.now() >= a.hasta) { intentos.delete(u); return false; }
  return true;
}
function registrarFallo(u) {
  const a = intentos.get(u) || { n: 0, hasta: 0 };
  a.n += 1;
  if (a.n >= MAX_INTENTOS) a.hasta = Date.now() + BLOQUEO_MS;
  intentos.set(u, a);
}

router.post("/login", validate(loginSchema), async (req, res) => {
  const { nombre_usuario, password } = req.body;
  try {
    if (estaBloqueado(nombre_usuario)) {
      return res.status(429).json({ error: "Demasiados intentos", glosa: "Cuenta bloqueada temporalmente. Intente más tarde" });
    }
    const result = await pool.query(
      "SELECT id, nombre_usuario, contrasena, correo FROM usuarios WHERE nombre_usuario = $1",
      [nombre_usuario]
    );
    const user = result.rows[0];
    const ok = user ? await verifyPassword(password, user.contrasena) : false;
    if (!ok) {
      registrarFallo(nombre_usuario);
      return res.status(401).json({ error: "Credenciales inválidas" });
    }
    intentos.delete(nombre_usuario);

    const rolesResult = await pool.query(
      `SELECT r.id, r.nombre FROM usuario_roles ur JOIN roles r ON r.id = ur.rol_id WHERE ur.usuario_id = $1`,
      [user.id]
    );
    const roles = rolesResult.rows.map((r) => ({ id: r.id, nombre: r.nombre }));
    const rolNombre = roles.length > 0 ? roles[0].nombre : null;
    const rolId = roles.length > 0 ? roles[0].id : null;
    const pacienteResult = await pool.query("SELECT id FROM pacientes WHERE usuario_id = $1", [user.id]);
    const pacienteId = pacienteResult.rows.length > 0 ? pacienteResult.rows[0].id : null;

    const token = jwt.sign(
      { usuarioId: user.id, nombreUsuario: user.nombre_usuario, rolId, rolNombre, pacienteId, roles },
      JWT_SECRET,
      { expiresIn: "2h", algorithm: "HS256", jwtid: crypto.randomUUID() }
    );
    await pool.query("INSERT INTO auditoria (usuario_id, accion) VALUES ($1, $2)", [user.id, "LOGIN: usuario inició sesión"]);
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error en login" });
  }
});

router.post("/logout", async (req, res) => {
  try {
    const h = req.headers.authorization || "";
    if (!h.startsWith("Bearer ")) return res.status(401).json({ error: "No autorizado" });
    const d = jwt.verify(h.slice(7), JWT_SECRET);
    revoke(d.jti, d.exp);
    await pool.query("INSERT INTO auditoria (usuario_id, accion) VALUES ($1, $2)", [d.usuarioId, "LOGOUT: usuario cerró sesión"]);
    res.json({ message: "Sesión cerrada" });
  } catch {
    res.status(401).json({ error: "No autorizado" });
  }
});

router.post("/registro", validate(registerSchema), async (req, res) => {
  const { nombre_usuario, password, correo, rut } = req.body;
  try {
    const normalizedRut = rut ? normalizeRut(rut) : null;
    let pacienteExistente = null;
    if (normalizedRut) {
      const rutCheck = await pool.query("SELECT id, usuario_id FROM pacientes WHERE rut = $1", [normalizedRut]);
      if (rutCheck.rows.length > 0) {
        pacienteExistente = rutCheck.rows[0];
        if (pacienteExistente.usuario_id) {
          return res.status(400).json({ error: "RUT ya registrado", glosa: "Este RUT ya tiene una cuenta de usuario asociada" });
        }
      }
    }
    const usuarioCheck = await pool.query("SELECT id FROM usuarios WHERE nombre_usuario = $1 OR correo = $2", [nombre_usuario, correo]);
    if (usuarioCheck.rows.length > 0) {
      return res.status(400).json({ error: "Usuario o correo duplicado", glosa: "El nombre de usuario o correo electrónico ya está en uso" });
    }
    const userResult = await pool.query(
      "INSERT INTO usuarios (nombre_usuario, contrasena, correo) VALUES ($1, $2, $3) RETURNING id, nombre_usuario, correo, created_at",
      [nombre_usuario, await hashPassword(password), correo]
    );
    const user = userResult.rows[0];
    const rolPacienteResult = await pool.query("SELECT id FROM roles WHERE nombre = 'paciente'");
    if (rolPacienteResult.rows.length > 0) {
      await pool.query("INSERT INTO usuario_roles (usuario_id, rol_id) VALUES ($1, $2)", [user.id, rolPacienteResult.rows[0].id]);
    }
    if (normalizedRut) {
      if (pacienteExistente) {
        await pool.query("UPDATE pacientes SET usuario_id = $1 WHERE rut = $2", [user.id, normalizedRut]);
      } else {
        await pool.query(
          `INSERT INTO pacientes (rut, primer_nombre, apellido_paterno, email, fecha_nacimiento, sexo, usuario_id)
           VALUES ($1, $2, $3, $4, '2000-01-01', 'M', $5)`,
          [normalizedRut, nombre_usuario, "", correo, user.id]
        );
      }
    }
    await pool.query("INSERT INTO auditoria (usuario_id, accion) VALUES ($1, $2)", [user.id, "REGISTRO: nuevo usuario registrado"]);
    res.status(201).json({ message: "Usuario registrado exitosamente", usuario: user });
  } catch (err) {
    console.error(err);
    if (err.code === "23505") {
      return res.status(400).json({ error: "Error al registrar", glosa: "El nombre de usuario o correo ya existe" });
    }
    res.status(500).json({ error: "Error al registrar" });
  }
});

module.exports = router;

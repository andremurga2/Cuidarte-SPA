const jwt = require("jsonwebtoken");
const { pool } = require("../db");
const { JWT_SECRET } = require("../config");

function requireAuth(req, res, next) {
  const h = req.headers.authorization || "";
  try {
    if (!h.startsWith("Bearer ")) throw new Error("sin token");
    req.authUser = jwt.verify(h.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "No autorizado", glosa: "Token inválido" });
  }
}

const requireRoles = (permitidos) => (req, res, next) =>
  requireAuth(req, res, async () => {
    try {
      const r = await pool.query(
        `SELECT r.nombre FROM usuario_roles ur JOIN roles r ON r.id = ur.rol_id WHERE ur.usuario_id = $1`,
        [req.authUser.usuarioId]
      );
      if (!r.rows.some((x) => permitidos.includes(x.nombre))) {
        return res.status(403).json({ error: "No autorizado", glosa: "No tiene permisos para realizar esta acción" });
      }
      next();
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: "Error al verificar roles" });
    }
  });

module.exports = { requireAuth, requireRoles };
const express = require("express");
const multer = require("multer");
const { pool } = require("../db");
const jwt = require("jsonwebtoken");
const delayMiddleware = require("../middleware/delay");
const router = express.Router();
const JWT_SECRET = require("../config").JWT_SECRET;

const ALLOWED_MIMES = [
  "application/pdf",
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.ms-powerpoint",
  "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  "image/jpeg",
  "image/jpg",
  "image/png"
];

const ALLOWED_EXTS = [".pdf", ".doc", ".docx", ".ppt", ".pptx", ".jpg", ".jpeg", ".png"];

function sanitizeFilename(name) {
  const base = Buffer.from(String(name || "documento"), "latin1").toString("utf8").normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[\\/]/g, "_").replace(/[^a-zA-Z0-9._-]/g, "_");
  const collapsed = base.replace(/_+/g, "_").replace(/^[._]+/, "");
  return (collapsed || "documento").slice(0, 120);
}

function hasValidMagicBytes(buf, ext) {
  if (!Buffer.isBuffer(buf) || buf.length < 4) return false;
  if (ext === ".pdf") {
    return buf.subarray(0, 5).toString("latin1") === "%PDF-";
  }
  if (ext === ".jpg" || ext === ".jpeg") {
    return buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff;
  }
  if (ext === ".png") {
    if (buf.length < 8) return false;
    return buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47 &&
           buf[4] === 0x0d && buf[5] === 0x0a && buf[6] === 0x1a && buf[7] === 0x0a;
  }
  if (ext === ".doc" || ext === ".ppt") {
    if (buf.length < 8) return false;
    return buf[0] === 0xd0 && buf[1] === 0xcf && buf[2] === 0x11 && buf[3] === 0xe0 &&
           buf[4] === 0xa1 && buf[5] === 0xb1 && buf[6] === 0x1a && buf[7] === 0xe1;
  }
  if (ext === ".docx" || ext === ".pptx") {
    const isZip = buf[0] === 0x50 && buf[1] === 0x4b &&
      ((buf[2] === 0x03 && buf[3] === 0x04) || (buf[2] === 0x05 && buf[3] === 0x06) || (buf[2] === 0x07 && buf[3] === 0x08));
    if (!isZip) return false;
    const raw = buf.toString("latin1");
    if (ext === ".docx") return raw.includes("word/");
    if (ext === ".pptx") return raw.includes("ppt/");
  }
  return false;
}

// Configurar multer para almacenar en memoria
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB
  },
  fileFilter: (req, file, cb) => {
    const ext = require("path").extname(file.originalname || "").toLowerCase();
    if (ALLOWED_MIMES.includes(file.mimetype) && ALLOWED_EXTS.includes(ext)) {
      cb(null, true);
    } else {
      const err = new Error("Solo se permiten archivos PDF, DOC, DOCX, PPT, PPTX, JPG o PNG");
      err.statusCode = 400;
      cb(err, false);
    }
  },
});

function getUserFromAuthHeader(req) {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Bearer ")) return null;
  try {
    const token = auth.substring(7);
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

function requireRole(req, allowedRoles) {
  const authUser = getUserFromAuthHeader(req);
  if (!authUser) {
    return Promise.resolve({ error: "No autorizado", status: 401 });
  }
  
  return pool.query(
    `SELECT r.nombre 
     FROM usuario_roles ur
     JOIN roles r ON r.id = ur.rol_id
     WHERE ur.usuario_id = $1`,
    [authUser.usuarioId]
  ).then(result => {
    const userRoles = result.rows.map(r => r.nombre);
    const hasRole = allowedRoles.some(role => userRoles.includes(role));
    if (!hasRole) {
      return { error: "No autorizado", status: 403 };
    }
    return { authUser, userRoles };
  }).catch(err => {
    return { error: "Error al verificar roles", status: 500 };
  });
}

// Subir documento de examen (médico y admin)
router.post("/", upload.single("documento"), async (req, res) => {
  try {
    const authCheck = await requireRole(req, ["medico", "admin"]);
    if (authCheck.error) {
      return res.status(authCheck.status).json({
        error: authCheck.error,
        glosa: "No tiene permisos para realizar esta acción",
      });
    }
    const { authUser } = authCheck;

    const { examen_medico_id, paciente_id } = req.body;

    if (!examen_medico_id || !paciente_id) {
      return res.status(400).json({
        error: "Error de validación",
        glosa: "examen_medico_id y paciente_id son requeridos",
      });
    }

    if (!req.file) {
      return res.status(400).json({
        error: "Error de validación",
        glosa: "Debe subir un documento",
      });
    }

    const ext = require("path").extname(req.file.originalname || "").toLowerCase();
    if (!hasValidMagicBytes(req.file.buffer, ext)) {
      return res.status(400).json({
        error: "Error de validación",
        glosa: "El contenido del archivo no coincide con una firma válida para su extensión",
      });
    }
    const cleanName = sanitizeFilename(req.file.originalname);

    const result = await pool.query(
      `INSERT INTO documentos_examen (
        examen_medico_id, paciente_id, documento, nombre_archivo
      ) VALUES ($1, $2, $3, $4) RETURNING id, nombre_archivo, created_at`,
      [examen_medico_id, paciente_id, req.file.buffer, cleanName]
    );

    const documento = result.rows[0];

    await pool.query(
      "INSERT INTO auditoria (usuario_id, accion) VALUES ($1, $2)",
      [
        authUser?.usuarioId || null,
        `DOCUMENTOS_CREAR: subió documento "${documento.nombre_archivo}" para examen ID ${examen_medico_id}`,
      ]
    );

    res.status(201).json({ documento });
  } catch (err) {
    console.error(err);
    const status = err.statusCode || (err.name === "MulterError" ? 400 : 500);
    res.status(status).json({
      error: status === 400 ? "Error de validación" : "Error al subir documentos",
      glosa: err.message || err.toString(),
    });
  }
});

// Obtener documentos de un examen (médico, admin y paciente)
router.get("/examen/:examen_id", async (req, res) => {
  try {
    const authUser = getUserFromAuthHeader(req);
    
    if (!authUser) {
      return res.status(401).json({
        error: "No autorizado",
        glosa: "Token inválido",
      });
    }

    // Verificar roles
    const userRolesResult = await pool.query(
      `SELECT r.nombre 
       FROM usuario_roles ur
       JOIN roles r ON r.id = ur.rol_id
       WHERE ur.usuario_id = $1`,
      [authUser.usuarioId]
    );
    const userRoles = userRolesResult.rows.map(r => r.nombre);

    // Si es paciente, verificar que el examen sea suyo
    if (userRoles.includes("paciente")) {
      const examenResult = await pool.query(
        `SELECT em.paciente_id, p.usuario_id 
         FROM examen_medico em
         JOIN pacientes p ON p.id = em.paciente_id
         WHERE em.id = $1`,
        [req.params.examen_id]
      );
      if (examenResult.rows.length === 0 || 
          examenResult.rows[0].usuario_id !== authUser.usuarioId) {
        return res.status(403).json({
          error: "No autorizado",
          glosa: "Solo puede ver sus propios documentos",
        });
      }
    } else if (!userRoles.includes("medico") && !userRoles.includes("admin")) {
      return res.status(403).json({
        error: "No autorizado",
        glosa: "No tiene permisos para realizar esta acción",
      });
    }

    const result = await pool.query(
      `SELECT id, nombre_archivo, created_at
       FROM documentos_examen
       WHERE examen_medico_id = $1 AND deleted_at IS NULL
       ORDER BY created_at DESC`,
      [req.params.examen_id]
    );

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Error al obtener documentos",
      glosa: err.message || err.toString(),
    });
  }
});

// Descargar documento (médico, admin y paciente)
router.get("/:id", async (req, res) => {
  try {
    const authUser = getUserFromAuthHeader(req);
    
    if (!authUser) {
      return res.status(401).json({
        error: "No autorizado",
        glosa: "Token inválido",
      });
    }

    // Verificar roles
    const userRolesResult = await pool.query(
      `SELECT r.nombre 
       FROM usuario_roles ur
       JOIN roles r ON r.id = ur.rol_id
       WHERE ur.usuario_id = $1`,
      [authUser.usuarioId]
    );
    const userRoles = userRolesResult.rows.map(r => r.nombre);

    // Obtener documento
    const docResult = await pool.query(
      `SELECT de.*, em.paciente_id, p.usuario_id
       FROM documentos_examen de
       JOIN examen_medico em ON em.id = de.examen_medico_id
       JOIN pacientes p ON p.id = em.paciente_id
       WHERE de.id = $1 AND de.deleted_at IS NULL AND em.deleted_at IS NULL`,
      [req.params.id]
    );

    if (docResult.rows.length === 0) {
      return res.status(404).json({ error: "No encontrado" });
    }

    const documento = docResult.rows[0];

    // Si es paciente, verificar que el documento sea suyo
    if (userRoles.includes("paciente")) {
      if (documento.usuario_id !== authUser.usuarioId) {
        return res.status(403).json({
          error: "No autorizado",
          glosa: "Solo puede ver sus propios documentos",
        });
      }
    } else if (!userRoles.includes("medico") && !userRoles.includes("admin")) {
      return res.status(403).json({
        error: "No autorizado",
        glosa: "No tiene permisos para realizar esta acción",
      });
    }

    // Detectar el tipo MIME basado en la extensión del archivo
    const extension = documento.nombre_archivo.split('.').pop().toLowerCase();
    let contentType = "application/pdf";
    if (['jpg', 'jpeg'].includes(extension)) {
      contentType = "image/jpeg";
    } else if (extension === 'png') {
      contentType = "image/png";
    } else if (extension === 'pdf') {
      contentType = "application/pdf";
    }
    
    res.setHeader("Content-Type", contentType);
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${documento.nombre_archivo}"`
    );
    res.send(documento.documento);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Error al descargar documento",
      glosa: err.message || err.toString(),
    });
  }
});

// Eliminar documento (solo admin)
router.delete("/:id", async (req, res) => {
  try {
    const authCheck = await requireRole(req, ["admin"]);
    if (authCheck.error) {
      return res.status(authCheck.status).json({
        error: authCheck.error,
        glosa: "No tiene permisos para realizar esta acción",
      });
    }
    const { authUser } = authCheck;

    const result = await pool.query(
      "UPDATE documentos_examen SET deleted_at = NOW() WHERE id=$1 AND deleted_at IS NULL RETURNING *",
      [req.params.id]
    );

    if (result.rows.length === 0)
      return res.status(404).json({ error: "No encontrado" });

    await pool.query(
      "INSERT INTO auditoria (usuario_id, accion) VALUES ($1, $2)",
      [
        authUser?.usuarioId || null,
        `DOCUMENTOS_ELIMINAR: eliminó documento ID ${req.params.id}`,
      ]
    );

    res.json({ deleted: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Error al eliminar documento",
      glosa: err.message || err.toString(),
    });
  }
});

module.exports = router;


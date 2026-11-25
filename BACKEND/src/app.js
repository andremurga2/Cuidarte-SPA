const path = require("path");
const fs = require("fs");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const jwt = require("jsonwebtoken");
const morgan = require("morgan");
const swaggerUi = require("swagger-ui-express");

const { JWT_SECRET } = require("./config");
const { isRevoked } = require("./utils/revoked");
const { requireAuth, requireRoles } = require("./middleware/auth");
const { migratePasswords } = require("./migrate");

const authRoutes = require("./routes/auth");
const userRoutes = require("./routes/users");
const pacientesRoutes = require("./routes/pacientes");
const examenesRoutes = require("./routes/examenes");
const documentosRoutes = require("./routes/documentos");
const tipoExamenRoutes = require("./routes/tipo-examen");
const auditRoutes = require("./routes/audit");
const rolesRoutes = require("./routes/roles");

const app = express();
app.disable("x-powered-by");
app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_URL || "http://localhost:3333" }));
app.use(express.json({ limit: "1mb" }));
app.use(morgan("combined", { skip: (req, res) => res.statusCode < 400 }));

// Rechaza tokens cerrados con /autenticacion/logout
app.use((req, res, next) => {
  const h = req.headers.authorization || "";
  if (h.startsWith("Bearer ")) {
    try {
      const d = jwt.verify(h.slice(7), JWT_SECRET);
      if (d.jti && isRevoked(d.jti)) {
        return res.status(401).json({ error: "No autorizado", glosa: "Sesión cerrada" });
      }
    } catch { /* cada ruta valida el token por su cuenta */ }
  }
  next();
});

fs.mkdirSync(path.join(__dirname, "..", "uploads", "documentos"), { recursive: true });

// Control de acceso centralizado (antes de montar las rutas)
app.get("/roles", requireAuth);
app.post("/roles", requireRoles(["admin"]));
app.put("/roles/:id", requireRoles(["admin"]));
app.delete("/roles/:id", requireRoles(["admin"]));
app.post("/usuarios", requireRoles(["admin"]));
app.delete("/usuarios/:id", requireRoles(["admin"]));
app.get("/pacientes/buscar/rut/:rut", requireRoles(["medico", "admin"]));
app.use("/tipo-examen", requireAuth);

app.use("/autenticacion", authRoutes);
app.use("/usuarios", userRoutes);
app.use("/pacientes", pacientesRoutes);
app.use("/examenes", examenesRoutes);
app.use("/documentos", documentosRoutes);
app.use("/tipo-examen", tipoExamenRoutes);
app.use("/auditoria", auditRoutes);
app.use("/roles", rolesRoutes);

const openapi = require("./openapi.json");
app.use("/docs", swaggerUi.serve, swaggerUi.setup(openapi));
app.get("/openapi.json", (req, res) => res.json(openapi));

app.get("/", (req, res) => res.json({ name: "cuidarteplus", status: "ok" }));

module.exports = app;

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  migratePasswords()
    .then(() => app.listen(PORT, () => console.log(`cuidarteplus API escuchando en puerto ${PORT}`)))
    .catch((e) => { console.error("Fallo en el arranque:", e); process.exit(1); });
}

const { pool } = require("./db");
const { hashPassword } = require("./utils/password");
async function ensureSchema() {
  for (const t of ["pacientes", "examen_medico", "documentos_examen"]) {
    await pool.query(`ALTER TABLE ${t} ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_${t}_deleted_at ON ${t}(deleted_at)`);
  }
}
async function migratePasswords() {
  await ensureSchema();
  const { rows } = await pool.query(
    "SELECT id, contrasena FROM usuarios WHERE contrasena NOT LIKE '$2%'"
  );
  for (const u of rows) {
    await pool.query("UPDATE usuarios SET contrasena = $1 WHERE id = $2", [
      await hashPassword(u.contrasena),
      u.id,
    ]);
  }
  console.log(`Migración de contraseñas: ${rows.length} usuario(s) pasaron a bcrypt`);
}
async function migrateWithRetry(intentos = 15, esperaMs = 2000) {
  for (let i = 1; i <= intentos; i++) {
    try {
      return await migratePasswords();
    } catch (e) {
      if (i === intentos) throw e;
      console.log(`BD no disponible (intento ${i}/${intentos}), reintentando...`);
      await new Promise((r) => setTimeout(r, esperaMs));
    }
  }
}
module.exports = { migratePasswords: migrateWithRetry };

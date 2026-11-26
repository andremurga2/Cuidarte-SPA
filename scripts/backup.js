// Respaldo cifrado (AES-256-GCM) de PostgreSQL y prueba de restauracion.
// Uso:  node scripts/backup.js backup
//       node scripts/backup.js test [archivo.enc]
// Requiere la variable de entorno BACKUP_PASSPHRASE (minimo 16 caracteres).
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const DIR = path.join(ROOT, "backups");
const PG = "cuidarteplus-postgres-ev";
const DB = "cuidarteplus";
const DB_TEST = "cuidarteplus_restore";
const MAGIC = Buffer.from("CPBK1");
const TABLAS = ["usuarios", "pacientes", "examen_medico", "documentos_examen", "auditoria"];

function passphrase() {
  const p = process.env.BACKUP_PASSPHRASE;
  if (!p || p.length < 16) {
    console.error("Defina BACKUP_PASSPHRASE (minimo 16 caracteres) en el entorno.");
    process.exit(1);
  }
  return p;
}

function encrypt(buf, pass) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.scryptSync(pass, salt, 32);
  const c = crypto.createCipheriv("aes-256-gcm", key, iv);
  const data = Buffer.concat([c.update(buf), c.final()]);
  return Buffer.concat([MAGIC, salt, iv, data, c.getAuthTag()]);
}

function decrypt(file, pass) {
  if (file.length < 50 || !file.subarray(0, 5).equals(MAGIC)) throw new Error("Formato de respaldo invalido");
  const salt = file.subarray(5, 21);
  const iv = file.subarray(21, 33);
  const tag = file.subarray(file.length - 16);
  const data = file.subarray(33, file.length - 16);
  const key = crypto.scryptSync(pass, salt, 32);
  const d = crypto.createDecipheriv("aes-256-gcm", key, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(data), d.final()]);
}

function dc(args, input) {
  const r = spawnSync("docker", ["compose", "exec", "-T", PG, ...args], {
    cwd: ROOT, input, maxBuffer: 1 << 30,
  });
  if (r.error || r.status !== 0) {
    console.error("Fallo: docker compose exec " + args.join(" "));
    console.error(String((r.stderr && r.stderr.toString()) || (r.error && r.error.message) || ""));
    process.exit(1);
  }
  return r.stdout;
}

function conteos(db) {
  const out = {};
  for (const t of TABLAS) {
    out[t] = Number(dc(["psql", "-U", "postgres", "-d", db, "-At", "-c", `SELECT count(*) FROM ${t}`]).toString().trim());
  }
  return out;
}

function hacerBackup() {
  const pass = passphrase();
  fs.mkdirSync(DIR, { recursive: true });
  const dump = dc(["pg_dump", "-U", "postgres", "-Fc", DB]);
  if (dump.subarray(0, 5).toString() !== "PGDMP") { console.error("El volcado no parece valido"); process.exit(1); }
  const enc = encrypt(dump, pass);
  const ts = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14);
  const file = path.join(DIR, `cuidarteplus-${ts}.dump.enc`);
  fs.writeFileSync(file, enc);
  const sha = crypto.createHash("sha256").update(enc).digest("hex");
  console.log(`Respaldo creado: ${file}`);
  console.log(`Tamano: dump ${dump.length} bytes -> cifrado ${enc.length} bytes`);
  console.log(`SHA-256: ${sha}`);
  return file;
}

function probar(archivo) {
  const pass = passphrase();
  const file = archivo || hacerBackup();
  const enc = fs.readFileSync(file);
  console.log("\n[1] El archivo no es legible sin la clave");
  console.log("    Empieza con PGDMP (dump en claro)?: " + (enc.subarray(0, 5).toString() === "PGDMP" ? "SI (FALLA)" : "NO (correcto)"));
  console.log("\n[2] Una clave incorrecta es rechazada");
  try { decrypt(enc, pass + "x"); console.log("    FALLA: acepto una clave incorrecta"); process.exit(1); }
  catch { console.log("    Rechazada (correcto)"); }

  console.log("\n[3] Restauracion en una base temporal (" + DB_TEST + ")");
  const dump = decrypt(enc, pass);
  dc(["psql", "-U", "postgres", "-d", "postgres", "-c", `DROP DATABASE IF EXISTS ${DB_TEST}`]);
  dc(["psql", "-U", "postgres", "-d", "postgres", "-c", `CREATE DATABASE ${DB_TEST}`]);
  dc(["pg_restore", "-U", "postgres", "-d", DB_TEST, "--no-owner"], dump);

  console.log("\n[4] Comparacion de filas (original vs restaurada)");
  const a = conteos(DB);
  const b = conteos(DB_TEST);
  let ok = true;
  for (const t of TABLAS) {
    const igual = a[t] === b[t];
    if (!igual) ok = false;
    console.log(`    ${t.padEnd(18)} original=${String(a[t]).padStart(4)} restaurada=${String(b[t]).padStart(4)}  ${igual ? "OK" : "DIFERENTE"}`);
  }
  dc(["psql", "-U", "postgres", "-d", "postgres", "-c", `DROP DATABASE ${DB_TEST}`]);
  console.log("\nRESULTADO: " + (ok ? "RESTAURACION EXITOSA" : "RESTAURACION CON DIFERENCIAS"));
  process.exit(ok ? 0 : 1);
}

module.exports = { encrypt, decrypt };

if (require.main === module) {
  const cmd = process.argv[2];
  if (cmd === "backup") hacerBackup();
  else if (cmd === "test") probar(process.argv[3]);
  else console.log("Uso: node scripts/backup.js backup | test [archivo.enc]");
}
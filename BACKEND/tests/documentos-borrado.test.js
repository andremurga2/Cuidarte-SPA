const request = require("supertest");

const API = process.env.API_URL || "http://localhost:4444";
const api = () => request(API);
const bearer = (t) => ({ Authorization: `Bearer ${t}` });
const login = (u, p) => api().post("/autenticacion/login").send({ nombre_usuario: u, password: p });
const sufijo = Date.now();

function rutConDv(n) {
  let s = 1, m = 0, x = n;
  for (; x; x = Math.floor(x / 10)) s = (s + (x % 10) * (9 - (m++ % 6))) % 11;
  return `${n}-${s ? s - 1 : "K"}`;
}
const idDe = (b) => b.id ?? b.paciente?.id ?? b.examen?.id ?? b.examen_medico?.id ?? b.documento?.id;

let tAdmin, tMedico, pacienteId, tipoId, examenId, docId;
const PDF = Buffer.from("%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF");
const DOCX = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.from("word/document.xml")]);
const PPTX = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.from("ppt/slides/slide1.xml")]);
const subir = (t, buf, nombre, tipo) =>
  api().post("/documentos").set(bearer(t))
    .field("examen_medico_id", String(examenId)).field("paciente_id", String(pacienteId))
    .attach("documento", buf, { filename: nombre, contentType: tipo });

beforeAll(async () => {
  tAdmin = (await login("admin", "admin")).body.token;
  tMedico = (await login("medico", "medico")).body.token;
  const p = await api().post("/pacientes").set(bearer(tAdmin)).send({
    rut: rutConDv(10000000 + (sufijo % 80000000)), primer_nombre: "Prueba", apellido_paterno: "Borrado",
    fecha_nacimiento: "1990-01-01", sexo: "M", email: `del_${sufijo}@test.cl`,
  });
  pacienteId = idDe(p.body);
  tipoId = (await api().get("/tipo-examen").set(bearer(tMedico))).body[0]?.id;
  const e = await api().post("/examenes").set(bearer(tMedico)).send({ tipo_examen_medico_id: Number(tipoId), paciente_id: Number(pacienteId) });
  examenId = idDe(e.body);
});

describe("Datos de prueba creados por la API", () => {
  test("CP-DEL-00 existen paciente, tipo de examen y examen", () => {
    expect(pacienteId).toBeDefined();
    expect(tipoId).toBeDefined();
    expect(examenId).toBeDefined();
  });
});

describe("Subida de documentos (BUG-016)", () => {
  test("CP-DOC-01 PDF válido -> 201 y nombre saneado", async () => {
    const r = await subir(tMedico, PDF, "../informe valido 2026.pdf", "application/pdf");
    expect(r.status).toBe(201);
    docId = idDe(r.body);
    expect(JSON.stringify(r.body)).not.toMatch(/\.\.\//);
  });
  test("CP-DOC-02 DOCX válido -> 201", async () => {
    const r = await subir(tMedico, DOCX, "informe.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
    expect(r.status).toBe(201);
  });
  test("CP-DOC-03 PPTX válido -> 201", async () => {
    const r = await subir(tMedico, PPTX, "presentacion.pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation");
    expect(r.status).toBe(201);
  });
  test("CP-DOC-06 nombre con tildes se conserva sin tildes", async () => {
    const r = await subir(tMedico, PDF, "Ejecución crítica.pdf", "application/pdf");
    expect(r.status).toBe(201);
    expect(JSON.stringify(r.body)).toContain("Ejecucion_critica.pdf");
  });
  test("CP-DOC-04 ejecutable renombrado a .pdf -> 400", async () => {
    const r = await subir(tMedico, Buffer.from("MZ-falso-pdf"), "falso.pdf", "application/pdf");
    expect(r.status).toBe(400);
  });
  test("CP-DOC-05 extensión no permitida (.exe) -> 400", async () => {
    const r = await subir(tMedico, Buffer.from("MZ"), "malware.exe", "application/octet-stream");
    expect(r.status).toBe(400);
  });
});

describe("Borrado lógico (BUG-015)", () => {
  test("CP-DEL-01 admin elimina el documento y deja de aparecer", async () => {
    expect((await api().delete(`/documentos/${docId}`).set(bearer(tAdmin))).status).toBe(200);
    expect((await api().get(`/documentos/${docId}`).set(bearer(tAdmin))).status).toBe(404);
  });
  test("CP-DEL-02 médico elimina el examen (RF-3.3) y deja de aparecer", async () => {
    expect((await api().delete(`/examenes/${examenId}`).set(bearer(tMedico))).status).toBe(200);
    expect((await api().get(`/examenes/${examenId}`).set(bearer(tMedico))).status).toBe(404);
  });
  test("CP-DEL-03 admin elimina el paciente y no aparece por id", async () => {
    expect((await api().delete(`/pacientes/${pacienteId}`).set(bearer(tAdmin))).status).toBe(200);
    expect((await api().get(`/pacientes/${pacienteId}`).set(bearer(tAdmin))).status).toBe(404);
  });
});

describe("CORS con HTTPS", () => {
  test("CP-SEG-06 el origen HTTPS del frontend está permitido", async () => {
    const r = await api().options("/autenticacion/login")
      .set("Origin", "https://localhost:3443").set("Access-Control-Request-Method", "POST");
    expect(r.headers["access-control-allow-origin"]).toBe("https://localhost:3443");
  });
  test("CP-SEG-07 un origen ajeno no recibe cabecera CORS", async () => {
    const r = await api().options("/autenticacion/login")
      .set("Origin", "https://sitio-malo.example").set("Access-Control-Request-Method", "POST");
    expect(r.headers["access-control-allow-origin"]).toBeUndefined();
  });
});
const request = require("supertest");
const jwt = require("jsonwebtoken");

const API = process.env.API_URL || "http://localhost:4444";
const api = () => request(API);
const sufijo = Date.now();
const FUERTE = "Prueba#12345Xy";
const bearer = (t) => ({ Authorization: `Bearer ${t}` });
const login = (u, p) =>
  api().post("/autenticacion/login").send({ nombre_usuario: u, password: p });

let tAdmin, tMedico, tPaciente;
const qa = { nombre: `qa_${sufijo}`, correo: `qa_${sufijo}@test.cl`, id: null, token: null };

beforeAll(async () => {
  tAdmin = (await login("admin", "admin")).body.token;
  tMedico = (await login("medico", "medico")).body.token;
  tPaciente = (await login("paciente", "paciente")).body.token;
});

describe("Autenticación", () => {
  test("CP-AUT-01 login admin válido entrega token", async () => {
    const r = await login("admin", "admin");
    expect(r.status).toBe(200);
    expect(typeof r.body.token).toBe("string");
  });
  test("CP-AUT-02 clave incorrecta -> 401", async () => {
    expect((await login("admin", "incorrecta")).status).toBe(401);
  });
  test("CP-AUT-03 usuario inexistente -> 401", async () => {
    expect((await login("no_existe_xyz", "x")).status).toBe(401);
  });
  test("CP-AUT-04 login sin cuerpo -> 400", async () => {
    expect((await api().post("/autenticacion/login").send({})).status).toBe(400);
  });
  test("CP-AUT-05 registro con clave débil -> 400", async () => {
    const r = await api().post("/autenticacion/registro").send({
      nombre_usuario: `debil_${sufijo}`, password: "123456", correo: `d_${sufijo}@test.cl`,
    });
    expect(r.status).toBe(400);
  });
  test("CP-AUT-06 registro con clave fuerte -> 201", async () => {
    const r = await api().post("/autenticacion/registro").send({
      nombre_usuario: qa.nombre, password: FUERTE, correo: qa.correo,
    });
    expect(r.status).toBe(201);
    qa.id = r.body.usuario.id;
  });
  test("CP-AUT-07 el usuario registrado puede iniciar sesión (hash válido)", async () => {
    const r = await login(qa.nombre, FUERTE);
    expect(r.status).toBe(200);
    qa.token = r.body.token;
  });
  test("CP-AUT-08 logout invalida el token", async () => {
    const t = (await login("paciente", "paciente")).body.token;
    expect((await api().get("/tipo-examen").set(bearer(t))).status).toBe(200);
    expect((await api().post("/autenticacion/logout").set(bearer(t))).status).toBe(200);
    expect((await api().get("/pacientes/1").set(bearer(t))).status).toBe(401);
  });
  test("CP-AUT-09 token firmado con otro secreto -> 401", async () => {
    const falso = jwt.sign({ usuarioId: 1, rolNombre: "admin" }, "otro-secreto-cualquiera");
    expect((await api().get("/usuarios").set(bearer(falso))).status).toBe(401);
  });
  test("CP-AUT-10 petición sin token -> 401", async () => {
    expect((await api().get("/pacientes")).status).toBe(401);
  });
});

describe("Seguridad", () => {
  test("CP-SEG-01 inyección SQL en login no autentica", async () => {
    const r = await login("' OR '1'='1' --", "' OR '1'='1");
    expect([400, 401]).toContain(r.status);
  });
  test("CP-SEG-02 bloqueo tras 5 intentos fallidos -> 429", async () => {
    const u = `bloqueo_${sufijo}`;
    let ultimo;
    for (let i = 0; i < 6; i++) ultimo = await login(u, "x");
    expect(ultimo.status).toBe(429);
  });
  test("CP-SEG-03 la respuesta de login no expone la contraseña", async () => {
    const r = await login("admin", "admin");
    expect(JSON.stringify(r.body)).not.toMatch(/contrasena|\$2[aby]\$/);
  });
  test("CP-SEG-04 cabeceras de seguridad presentes", async () => {
    const r = await api().get("/");
    expect(r.headers["x-powered-by"]).toBeUndefined();
    expect(r.headers["x-content-type-options"]).toBe("nosniff");
  });
  test("CP-SEG-05 carpeta pública de documentos no existe", async () => {
    expect((await api().get("/files/documentos/cualquiera.pdf")).status).toBe(404);
  });
});

describe("Control de acceso por rol", () => {
  test("CP-ACC-01 paciente no lista pacientes -> 403", async () => {
    expect((await api().get("/pacientes").set(bearer(tPaciente))).status).toBe(403);
  });
  test("CP-ACC-02 paciente no accede a la ficha de un id ajeno", async () => {
    expect((await api().get("/pacientes/999999").set(bearer(tPaciente))).status).toBe(403);
  });
  test("CP-ACC-03 médico lista pacientes -> 200", async () => {
    expect((await api().get("/pacientes").set(bearer(tMedico))).status).toBe(200);
  });
  test("CP-ACC-04 médico no elimina pacientes -> 403", async () => {
    expect((await api().delete("/pacientes/999999").set(bearer(tMedico))).status).toBe(403);
  });
  test("CP-ACC-05 médico no lista usuarios -> 403", async () => {
    expect((await api().get("/usuarios").set(bearer(tMedico))).status).toBe(403);
  });
  test("CP-ACC-06 admin lista usuarios -> 200", async () => {
    expect((await api().get("/usuarios").set(bearer(tAdmin))).status).toBe(200);
  });
  test("CP-ACC-07 paciente no crea usuarios -> 403", async () => {
    const r = await api().post("/usuarios").set(bearer(tPaciente)).send({
      nombre_usuario: `intruso_${sufijo}`, contrasena_hash: FUERTE, correo: `i_${sufijo}@test.cl`, rol_id: 1,
    });
    expect(r.status).toBe(403);
  });
  test("CP-ACC-08 anónimo no elimina usuarios -> 401", async () => {
    expect((await api().delete("/usuarios/999999")).status).toBe(401);
  });
  test("CP-ACC-09 anónimo no crea roles -> 401", async () => {
    expect((await api().post("/roles").send({ nombre: `rol_${sufijo}` })).status).toBe(401);
  });
  test("CP-ACC-10 paciente no crea roles -> 403", async () => {
    expect((await api().post("/roles").set(bearer(tPaciente)).send({ nombre: `rol_${sufijo}` })).status).toBe(403);
  });
  test("CP-ACC-11 anónimo no busca pacientes por RUT -> 401", async () => {
    expect((await api().get("/pacientes/buscar/rut/11111111-1")).status).toBe(401);
  });
  test("CP-ACC-12 anónimo no lista tipos de examen -> 401", async () => {
    expect((await api().get("/tipo-examen")).status).toBe(401);
  });
  test("CP-ACC-13 un usuario no puede auto-asignarse el rol admin", async () => {
    const r = await api().put(`/usuarios/${qa.id}`).set(bearer(qa.token))
      .send({ correo: `qa2_${sufijo}@test.cl`, rol_id: 1 });
    expect(r.status).toBeGreaterThanOrEqual(400);
  });
});
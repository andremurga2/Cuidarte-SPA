import http from 'k6/http';
import { check } from 'k6';
export const options = {
  scenarios: { carga: { executor: 'constant-vus', vus: 200, duration: '30s' } },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    'http_req_duration{tipo:crud}': ['p(95)<300'],
  },
};
const API = __ENV.API;
export function setup() {
  const r = http.post(`${API}/autenticacion/login`, JSON.stringify({ nombre_usuario: 'medico', password: 'medico' }), { headers: { 'Content-Type': 'application/json' } });
  return { token: r.json('token') };
}
export default function (d) {
  const h = { headers: { Authorization: `Bearer ${d.token}` } };
  const a = http.get(`${API}/pacientes/1`, Object.assign({ tags: { tipo: 'crud' } }, h));
  check(a, { 'GET /pacientes/1 = 200': (r) => r.status === 200 });
  const b = http.get(`${API}/pacientes`, Object.assign({ tags: { tipo: 'listado' } }, h));
  check(b, { 'GET /pacientes = 200': (r) => r.status === 200 });
}

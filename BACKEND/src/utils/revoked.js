const revocados = new Map();
function revoke(jti, exp) {
  if (jti) revocados.set(jti, exp * 1000);
}
function isRevoked(jti) {
  const ahora = Date.now();
  for (const [k, v] of revocados) if (v < ahora) revocados.delete(k);
  return revocados.has(jti);
}
module.exports = { revoke, isRevoked };

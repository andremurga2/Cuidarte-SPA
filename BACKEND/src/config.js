require("dotenv").config();
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32 || JWT_SECRET === "inseguro") {
  console.error("FATAL: JWT_SECRET no definido o inseguro (mínimo 32 caracteres).");
  process.exit(1);
}
module.exports = { JWT_SECRET };

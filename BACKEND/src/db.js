const { Pool } = require("pg");
require("dotenv").config();

const connectionString =
  process.env.DATABASE_URL ||
  "postgres://postgres:alone15@localhost:5432/cuidarteplus";

const pool = new Pool({ connectionString, max: Number(process.env.DB_POOL_MAX || 20) });

module.exports = { pool };

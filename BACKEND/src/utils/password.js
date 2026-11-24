const bcrypt = require("bcryptjs");
const ROUNDS = 10;
const hashPassword = (plain) => bcrypt.hash(plain, ROUNDS);
const isHash = (s) => typeof s === "string" && /^\$2[aby]\$/.test(s);
const verifyPassword = (plain, stored) =>
  isHash(stored) ? bcrypt.compare(plain, stored) : Promise.resolve(false);
module.exports = { hashPassword, verifyPassword, isHash };

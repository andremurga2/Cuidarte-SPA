const security = require("eslint-plugin-security");

module.exports = [
  security.configs.recommended,
  {
    files: ["src/**/*.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "commonjs",
      globals: {
        require: "readonly", module: "writable", process: "readonly",
        console: "readonly", __dirname: "readonly", setTimeout: "readonly"
      }
    }
  }
];

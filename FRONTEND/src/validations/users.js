import * as yup from "yup";

export const updateUsuarioSchema = yup.object().shape({
  correo: yup
    .string()
    .required("El correo es requerido")
    .email("El correo debe tener un formato válido")
    .max(255, "El correo no puede exceder 255 caracteres"),
});

export const updatePasswordSchema = yup.object().shape({
  contrasena_hash: yup
    .string()
    .required("La contraseña es requerida")
    .min(12, "La contraseña debe tener al menos 12 caracteres").matches(/[a-z]/, "Debe incluir una minúscula").matches(/[A-Z]/, "Debe incluir una mayúscula").matches(/[0-9]/, "Debe incluir un número").matches(/[^A-Za-z0-9]/, "Debe incluir un símbolo"),
  confirmar_contrasena: yup
    .string()
    .required("Debe confirmar la contraseña")
    .oneOf([yup.ref("contrasena_hash")], "Las contraseñas no coinciden"),
});

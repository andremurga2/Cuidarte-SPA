FROM node:20-alpine
RUN apk upgrade --no-cache

WORKDIR /app

# Copiar archivos de dependencias
COPY package*.json ./

# Instalar dependencias
RUN npm ci --omit=dev

# Copiar código de la aplicación
COPY src/ ./src/
COPY sql/ ./sql/
# uploads se crea al construir (no se versiona)

# Crear directorio para uploads si no existe
RUN mkdir -p uploads/contracts uploads/documentos
# La API no usa npm en ejecucion: se elimina para quitar node-tar vulnerable de la imagen
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /root/.npm

# Exponer puerto
EXPOSE 4000

# Comando para iniciar la aplicación
CMD ["node", "src/app.js"]


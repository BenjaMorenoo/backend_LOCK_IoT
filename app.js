const express = require("express");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const http = require("http");
const { Server } = require("socket.io");

const cors = require("cors");

const app = express();
const server = http.createServer(app); // <- servidor HTTP
const io = new Server(server, {
  cors: {
    origin: "https://eduarduino.cl", // tu frontend
    methods: ["GET", "POST"],
  },
});

app.use(bodyParser.json());

// habilitar CORS para todas las rutas REST
app.use(cors({
  origin: "https://eduarduino.cl",
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

const SECRET_KEY = "supersecreto"; // ⚠️ cámbialo en producción
const db = new sqlite3.Database("./casilleros.db");

// Crear tablas si no existen
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS admin (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS profesores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    tarjeta_uid TEXT UNIQUE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS casilleros (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    numero TEXT NOT NULL UNIQUE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profesor_id INTEGER,
    casillero_id INTEGER,
    fecha_hora DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(profesor_id) REFERENCES profesores(id),
    FOREIGN KEY(casillero_id) REFERENCES casilleros(id)
  )`);
});

// Crear usuario admin por defecto si no existe
db.get("SELECT * FROM admin WHERE username = ?", ["admin"], async (err, row) => {
  if (!row) {
    const hash = await bcrypt.hash("123456", 10);
    db.run("INSERT INTO admin (username, password) VALUES (?, ?)", ["admin", hash]);
    console.log("Usuario admin creado (user: admin, pass: 123456)");
  }
});

// Middleware para validar token
function authMiddleware(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) return res.status(403).send("Token requerido");

  jwt.verify(token.split(" ")[1], SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).send("Token inválido");
    req.user = decoded;
    next();
  });
}

// 🔹 Endpoint que usará el ESP32 para enviar el UID leída
app.post("/lectura-tarjeta", (req, res) => {
  const { uid } = req.body;
  if (!uid) return res.status(400).send("UID requerido");

  // Enviar UID al frontend en tiempo real
  io.emit("nueva-tarjeta", uid);

  res.send("UID recibido y reenviado al frontend");
});

// Login
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM admin WHERE username = ?", [username], async (err, user) => {
    if (!user) return res.status(401).send("Credenciales inválidas");

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).send("Credenciales inválidas");

    const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: "8h" });
    res.json({ token });
  });
});

// Cambiar contraseña
app.post("/api/change-password", authMiddleware, async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  if (!oldPassword || !newPassword) {
    return res.status(400).send("Debes ingresar la contraseña actual y la nueva");
  }

  db.get("SELECT * FROM admin WHERE id = ?", [req.user.id], async (err, user) => {
    if (err) return res.status(500).send("Error en la base de datos");
    if (!user) return res.status(404).send("Usuario no encontrado");

    const valid = await bcrypt.compare(oldPassword, user.password);
    if (!valid) return res.status(401).send("La contraseña actual es incorrecta");

    const hash = await bcrypt.hash(newPassword, 10);

    db.run("UPDATE admin SET password = ? WHERE id = ?", [hash, user.id], function (err) {
      if (err) return res.status(500).send("Error actualizando la contraseña");
      res.send("Contraseña actualizada correctamente");
    });
  });
});

// Logs
app.get("/api/logs", authMiddleware, (req, res) => {
  const query = `
    SELECT logs.id, profesores.nombre AS profesor, casilleros.numero AS casillero, logs.fecha_hora
    FROM logs
    LEFT JOIN profesores ON logs.profesor_id = profesores.id
    LEFT JOIN casilleros ON logs.casillero_id = casilleros.id
    ORDER BY logs.fecha_hora DESC
  `;
  db.all(query, [], (err, rows) => {
    if (err) return res.status(500).send("Error obteniendo logs");
    res.json(rows);
  });
});

// Profesores
app.post("/api/profesores", authMiddleware, (req, res) => {
  const { nombre, tarjeta_uid } = req.body;
  db.run("INSERT INTO profesores (nombre, tarjeta_uid) VALUES (?, ?)", [nombre, tarjeta_uid], function (err) {
    if (err) return res.status(500).send("Error insertando profesor");
    res.send("Profesor agregado");
  });
});

app.get("/api/profesores", authMiddleware, (req, res) => {
  db.all("SELECT * FROM profesores", [], (err, rows) => {
    if (err) return res.status(500).send("Error obteniendo profesores");
    res.json(rows);
  });
});

// Casilleros
app.post("/api/casilleros", authMiddleware, (req, res) => {
  const { numero } = req.body;
  db.run("INSERT INTO casilleros (numero) VALUES (?)", [numero], function (err) {
    if (err) return res.status(500).send("Error insertando casillero");
    res.send("Casillero agregado");
  });
});

app.get("/api/casilleros", authMiddleware, (req, res) => {
  db.all("SELECT * FROM casilleros", [], (err, rows) => {
    if (err) return res.status(500).send("Error obteniendo casilleros");
    res.json(rows);
  });
});

// Endpoint público para ESP32 (abrir casillero)
app.post("/abrir", (req, res) => {
  const { tarjeta, casillero } = req.body;
  if (!tarjeta || !casillero) return res.status(400).send("Faltan datos");

  db.get("SELECT id FROM profesores WHERE tarjeta_uid = ?", [tarjeta], (err, profesor) => {
    if (!profesor) return res.status(404).send("Tarjeta no registrada");

    db.get("SELECT id FROM casilleros WHERE numero = ?", [casillero], (err, casilleroRow) => {
      if (!casilleroRow) return res.status(404).send("Casillero no registrado");

      db.run("INSERT INTO logs (profesor_id, casillero_id) VALUES (?, ?)", [profesor.id, casilleroRow.id], function (err) {
        if (err) return res.status(500).send("Error guardando log");
        res.send("Apertura registrada");
      });
    });
  });
});

app.get("/", (req, res) => {
  res.send("Api funcionando!");
});

// 🔹 Socket.io conexión
io.on("connection", (socket) => {
  console.log("Cliente conectado vía WebSocket");
  socket.on("disconnect", () => console.log("Cliente desconectado"));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));

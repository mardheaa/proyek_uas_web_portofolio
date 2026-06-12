/**
 * @file server.js - Backend API untuk Web Portofolio
 * @description Server Express.js dengan MySQL, bcrypt, dan multer
 * @version 2.0.0 - Fixed SonarCloud Issues
 */

require("dotenv").config();
const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const rateLimit = require("express-rate-limit");

const app = express();

// ==================== CONSTANTS ====================
const BCRYPT_ROUNDS = 10;
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
const KAMPUS_DOMAIN = /^[\w.-]+@upitra\.ac\.id$/i;
const PORT = process.env.PORT || 3000;

// ==================== CORS CONFIGURATION ====================
const corsOptions = {
  origin: [
    "http://localhost:3000",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
  ],
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true,
  optionsSuccessStatus: 200,
};
app.use(cors(corsOptions));
app.use(express.json());

// ==================== DATABASE CONNECTION ====================
const db = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "db_web_pelaporan_fasilitas",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// ==================== RATE LIMITING ====================
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 menit
  max: 100, // Max 100 request per IP
  message: { error: "Terlalu banyak request, coba lagi nanti" },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // Max 5 percobaan login/register
  message: { error: "Terlalu banyak percobaan, coba lagi setelah 15 menit" },
});

app.use("/api/", generalLimiter);

// ==================== HELPER FUNCTIONS ====================
/**
 * Sanitize filename untuk mencegah path traversal
 * @param {string} filename - Nama file asli
 * @returns {string} - Nama file yang sudah disanitasi
 */
const sanitizeFilename = (filename) => {
  if (!filename) return null;
  return path.basename(filename).replace(/[^a-z0-9.-]/gi, "_");
};

/**
 * Validate required fields
 * @param {Object} fields - Object berisi field yang harus divalidasi
 * @returns {string|null} - Error message atau null jika valid
 */
const validateRequiredFields = (fields) => {
  for (const [key, value] of Object.entries(fields)) {
    if (!value || value.toString().trim() === "") {
      return `Field ${key} wajib diisi`;
    }
  }
  return null;
};

// ==================== UPLOAD CONFIGURATION ====================
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const uniqueName =
      Date.now() +
      "-" +
      Math.round(Math.random() * 1e9) +
      path.extname(file.originalname);
    cb(null, uniqueName);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/")) {
      cb(null, true);
    } else {
      cb(new Error("Hanya file gambar (JPG, PNG, WEBP) yang diizinkan"), false);
    }
  },
});

// Serve static files
app.use("/uploads", express.static(uploadDir));

// ==================== ROUTES ====================

/**
 * @route POST /api/register
 * @desc Register user baru dengan validasi domain kampus
 */
app.post("/api/register", authLimiter, async (req, res) => {
  try {
    const { email, username, password } = req.body;

    // Validasi required fields
    const validationError = validateRequiredFields({
      email,
      username,
      password,
    });
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    // Validasi domain kampus
    if (!KAMPUS_DOMAIN.test(email)) {
      return res
        .status(400)
        .json({ error: "Hanya email @upitra.ac.id yang diizinkan" });
    }

    // Validasi password length
    if (password.length < 8) {
      return res.status(400).json({ error: "Password minimal 8 karakter" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);

    // Insert ke database
    await db.query(
      "INSERT INTO tbl_users (email, username, password) VALUES (?, ?, ?)",
      [
        email.toLowerCase().trim(),
        username.toLowerCase().trim(),
        hashedPassword,
      ],
    );

    return res.status(201).json({ message: "Registrasi berhasil" });
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") {
      if (err.sqlMessage && err.sqlMessage.includes("username")) {
        return res.status(400).json({ error: "Username sudah digunakan" });
      }
      return res.status(400).json({ error: "Email sudah terdaftar" });
    }
    return res.status(500).json({ error: "Server error" });
  }
});

/**
 * @route POST /api/login
 * @desc Login user dengan email/username dan password
 */
app.post("/api/login", authLimiter, async (req, res) => {
  try {
    const { loginInput, password } = req.body;

    // Validasi required fields
    const validationError = validateRequiredFields({ loginInput, password });
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    // Query database
    const [rows] = await db.query(
      "SELECT id, email, username, password FROM tbl_users WHERE email = ? OR username = ?",
      [loginInput.toLowerCase().trim(), loginInput.toLowerCase().trim()],
    );

    // Cek user exists
    if (rows.length === 0) {
      return res
        .status(401)
        .json({ error: "Email/username atau password salah" });
    }

    const user = rows[0];

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res
        .status(401)
        .json({ error: "Email/username atau password salah" });
    }

    return res.status(200).json({
      message: "Login berhasil",
      userId: user.id,
      username: user.username,
      email: user.email,
    });
  } catch (err) {
    return res.status(500).json({ error: "Server error" });
  }
});

/**
 * @route GET /api/activities
 * @desc Get semua data activities
 */
app.get("/api/activities", async (req, res) => {
  try {
    const [rows] = await db.query(
      "SELECT * FROM portfolio_activities ORDER BY created_at DESC",
    );
    return res.status(200).json(rows);
  } catch (err) {
    return res.status(500).json({ error: "Gagal mengambil data" });
  }
});

/**
 * @route POST /api/activities
 * @desc Create activity baru dengan upload foto
 */
app.post("/api/activities", upload.single("foto"), async (req, res) => {
  try {
    const { nama_kegiatan, jenis, instansi, tahun, deskripsi } = req.body;

    // Validasi required fields
    const validationError = validateRequiredFields({
      nama_kegiatan,
      jenis,
      instansi,
      tahun,
      deskripsi,
    });
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    // Validasi tahun
    const tahunNum = parseInt(tahun);
    if (
      isNaN(tahunNum) ||
      tahunNum < 1900 ||
      tahunNum > new Date().getFullYear() + 1
    ) {
      return res.status(400).json({ error: "Tahun tidak valid" });
    }

    const foto = req.file ? req.file.filename : null;

    await db.query(
      "INSERT INTO portfolio_activities (nama_kegiatan, jenis, instansi, tahun, deskripsi, foto) VALUES (?, ?, ?, ?, ?, ?)",
      [
        nama_kegiatan.trim(),
        jenis.trim(),
        instansi.trim(),
        tahunNum,
        deskripsi.trim(),
        foto,
      ],
    );

    return res.status(201).json({ message: "Data berhasil ditambahkan" });
  } catch (err) {
    return res.status(500).json({ error: "Gagal menyimpan data" });
  }
});

/**
 * @route PUT /api/activities/:id
 * @desc Update activity dan ganti foto (opsional)
 */
app.put("/api/activities/:id", upload.single("foto"), async (req, res) => {
  try {
    const { id } = req.params;
    const { nama_kegiatan, jenis, instansi, tahun, deskripsi, oldFoto } =
      req.body;

    // Validasi required fields
    const validationError = validateRequiredFields({
      nama_kegiatan,
      jenis,
      instansi,
      tahun,
      deskripsi,
    });
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    // Validasi tahun
    const tahunNum = parseInt(tahun);
    if (
      isNaN(tahunNum) ||
      tahunNum < 1900 ||
      tahunNum > new Date().getFullYear() + 1
    ) {
      return res.status(400).json({ error: "Tahun tidak valid" });
    }

    let foto = sanitizeFilename(oldFoto) || null;

    // Handle file upload
    if (req.file) {
      const safeOldFoto = sanitizeFilename(oldFoto);
      if (safeOldFoto && fs.existsSync(path.join(uploadDir, safeOldFoto))) {
        fs.unlinkSync(path.join(uploadDir, safeOldFoto));
      }
      foto = req.file.filename;
    }

    await db.query(
      "UPDATE portfolio_activities SET nama_kegiatan=?, jenis=?, instansi=?, tahun=?, deskripsi=?, foto=? WHERE id=?",
      [
        nama_kegiatan.trim(),
        jenis.trim(),
        instansi.trim(),
        tahunNum,
        deskripsi.trim(),
        foto,
        id,
      ],
    );

    return res.status(200).json({ message: "Data berhasil diupdate" });
  } catch (err) {
    return res.status(500).json({ error: "Gagal update data" });
  }
});

/**
 * @route DELETE /api/activities/:id
 * @desc Delete activity dan hapus file foto
 */
app.delete("/api/activities/:id", async (req, res) => {
  try {
    const { id } = req.params;

    // Get foto filename
    const [rows] = await db.query(
      "SELECT foto FROM portfolio_activities WHERE id=?",
      [id],
    );

    // Delete file if exists
    if (rows.length > 0 && rows[0].foto) {
      const safeFoto = sanitizeFilename(rows[0].foto);
      const fotoPath = path.join(uploadDir, safeFoto);
      if (fs.existsSync(fotoPath)) {
        fs.unlinkSync(fotoPath);
      }
    }

    // Delete from database
    await db.query("DELETE FROM portfolio_activities WHERE id=?", [id]);

    return res.status(200).json({ message: "Data berhasil dihapus" });
  } catch (err) {
    return res.status(500).json({ error: "Gagal menghapus data" });
  }
});

// ==================== ERROR HANDLING ====================
// Handle multer errors
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({ error: "File terlalu besar (max 5MB)" });
    }
    return res.status(400).json({ error: err.message });
  }
  if (err) {
    return res.status(400).json({ error: err.message });
  }
  next();
});

// Handle 404
app.use((req, res) => {
  return res.status(404).json({ error: "Endpoint tidak ditemukan" });
});

// ==================== SERVER LISTEN ====================
const server = app.listen(PORT, () => {
  // Server started successfully
});

server.on("error", (err) => {
  // Server error occurred
  process.exit(1);
});

// Graceful shutdown
process.on("SIGTERM", () => {
  server.close(() => {
    process.exit(0);
  });
});

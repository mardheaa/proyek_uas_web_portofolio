const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
app.use(cors());
app.use(express.json());

// ==================== 1. KONEKSI DATABASE ====================
const db = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "",
  database: "db_web_pelaporan_fasilitas",
});

// ==================== 2. REGEX DOMAIN KAMPUS ====================
const KAMPUS_DOMAIN = /^[\w.-]+@upitra\.ac\.id$/i;

// ==================== 3. REGISTER ====================
app.post("/api/register", async (req, res) => {
  try {
    const { email, username, password } = req.body;

    if (!email || !username || !password) {
      return res.status(400).json({ error: "Semua field wajib diisi" });
    }

    if (!KAMPUS_DOMAIN.test(email)) {
      return res
        .status(400)
        .json({ error: "Hanya email @upitra.ac.id yang diizinkan" });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: "Password minimal 8 karakter" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await db.query(
      "INSERT INTO tbl_users (email, username, password) VALUES (?, ?, ?)",
      [email.toLowerCase(), username.toLowerCase(), hashedPassword],
    );

    res.status(201).json({ message: "Registrasi berhasil" });
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") {
      if (err.sqlMessage && err.sqlMessage.includes("username")) {
        res.status(400).json({ error: "Username sudah digunakan" });
      } else {
        res.status(400).json({ error: "Email sudah terdaftar" });
      }
    } else {
      console.error("Register error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
});

// ==================== 4. LOGIN ====================
app.post("/api/login", async (req, res) => {
  try {
    const { loginInput, password } = req.body;

    if (!loginInput || !password) {
      return res
        .status(400)
        .json({ error: "Email/username dan password wajib diisi" });
    }

    const [rows] = await db.query(
      "SELECT id, email, username, password FROM tbl_users WHERE email = ? OR username = ?",
      [loginInput.toLowerCase(), loginInput.toLowerCase()],
    );

    if (rows.length === 0) {
      return res
        .status(401)
        .json({ error: "Email/username atau password salah" });
    }

    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res
        .status(401)
        .json({ error: "Email/username atau password salah" });
    }

    res.json({
      message: "Login berhasil",
      userId: user.id,
      username: user.username,
      email: user.email,
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ==================== 5. KONFIGURASI UPLOAD FOTO (Multer) ====================
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
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
  limits: { fileSize: 5 * 1024 * 1024 }, // Max 5MB
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/")) cb(null, true);
    else cb(new Error("Hanya file gambar (JPG, PNG, WEBP) yang diizinkan"));
  },
});

// Serve file statis dari folder uploads
app.use("/uploads", express.static(uploadDir));

// ==================== 6. CRUD ACTIVITIES ====================

// GET - Baca semua data
app.get("/api/activities", async (req, res) => {
  try {
    const [rows] = await db.query(
      "SELECT * FROM portfolio_activities ORDER BY created_at DESC",
    );
    res.json(rows);
  } catch (err) {
    console.error("Get activities error:", err);
    res.status(500).json({ error: "Gagal mengambil data" });
  }
});

// POST - Tambah data baru + upload foto
app.post("/api/activities", upload.single("foto"), async (req, res) => {
  try {
    const { nama_kegiatan, jenis, instansi, tahun, deskripsi } = req.body;
    const foto = req.file ? req.file.filename : null;

    await db.query(
      "INSERT INTO portfolio_activities (nama_kegiatan, jenis, instansi, tahun, deskripsi, foto) VALUES (?, ?, ?, ?, ?, ?)",
      [nama_kegiatan, jenis, instansi, tahun, deskripsi, foto],
    );
    res.status(201).json({ message: "Data berhasil ditambahkan" });
  } catch (err) {
    console.error("Create activity error:", err);
    res.status(500).json({ error: "Gagal menyimpan data" });
  }
});

// PUT - Update data + ganti foto (opsional)
app.put("/api/activities/:id", upload.single("foto"), async (req, res) => {
  try {
    const { id } = req.params;
    const { nama_kegiatan, jenis, instansi, tahun, deskripsi, oldFoto } =
      req.body;
    let foto = oldFoto || null;

    if (req.file) {
      if (oldFoto && fs.existsSync(path.join(uploadDir, oldFoto))) {
        fs.unlinkSync(path.join(uploadDir, oldFoto));
      }
      foto = req.file.filename;
    }

    await db.query(
      "UPDATE portfolio_activities SET nama_kegiatan=?, jenis=?, instansi=?, tahun=?, deskripsi=?, foto=? WHERE id=?",
      [nama_kegiatan, jenis, instansi, tahun, deskripsi, foto, id],
    );
    res.json({ message: "Data berhasil diupdate" });
  } catch (err) {
    console.error("Update activity error:", err);
    res.status(500).json({ error: "Gagal update data" });
  }
});

// DELETE - Hapus data + hapus file foto
app.delete("/api/activities/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const [rows] = await db.query(
      "SELECT foto FROM portfolio_activities WHERE id=?",
      [id],
    );
    if (rows.length > 0 && rows[0].foto) {
      const fotoPath = path.join(uploadDir, rows[0].foto);
      if (fs.existsSync(fotoPath)) {
        fs.unlinkSync(fotoPath);
      }
    }

    await db.query("DELETE FROM portfolio_activities WHERE id=?", [id]);
    res.json({ message: "Data berhasil dihapus" });
  } catch (err) {
    console.error("Delete activity error:", err);
    res.status(500).json({ error: "Gagal menghapus data" });
  }
});

// ==================== 7. SERVER LISTEN ====================
const PORT = process.env.PORT || 3000;
app
  .listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  })
  .on("error", (err) => {
    console.error("Server error:", err);
  });
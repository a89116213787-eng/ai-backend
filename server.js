import { Pool } from "pg";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import fs from "fs";
import path from "path";
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { GoogleGenerativeAI } from "@google/generative-ai";

dotenv.config();

// ==================
// DB CONNECTION  ✅ КРИТИЧНО ДОБАВЛЕНО
// ==================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// проверка подключения
pool.query("SELECT 1")
  .then(() => console.log("✅ DB connected"))
  .catch((e) => {
    console.error("❌ DB connection error:", e);
    process.exit(1);
  });

const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));

const PORT = process.env.PORT || 3000;

// --- Проверка наличия ключа ---
if (!process.env.GEMINI_API_KEY) {
  console.error("❌ GEMINI_API_KEY is not set");
  process.exit(1);
}

// --- Проверка наличия секрета для JWT ---
if (!process.env.JWT_SECRET) {
  console.error("❌ JWT_SECRET is not set");
  process.exit(1);
}

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// ==================
// JWT MIDDLEWARE
// ==================
function authMiddleware(req, res, next) {
  try {
    const header = req.headers.authorization;

    if (!header) {
      return res.status(401).json({ ok: false, error: "no token" });
    }

    const token = header.replace("Bearer ", "");
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ ok: false, error: "invalid token" });
  }
}

// ======================================================
// PROMO STORAGE
// ======================================================
const DATA_PATH = path.join(process.cwd(), "data", "promo-codes.json");

function readCodes() {
  const raw = fs.readFileSync(DATA_PATH, "utf-8");
  return JSON.parse(raw);
}

function writeCodes(data) {
  fs.writeFileSync(DATA_PATH, JSON.stringify(data, null, 2));
}

// ==================
// HEALTH CHECK
// ==================
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "ai-backend",
    time: new Date().toISOString()
  });
});

app.get("/", (req, res) => {
  res.json({ status: "ok", service: "ai-backend" });
});

// ======================================================
// AUTH SYSTEM
// ======================================================

// ---------- REGISTER ----------
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        ok: false,
        error: "email and password required",
      });
    }

    const exists = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    if (exists.rows.length > 0) {
      return res.status(400).json({
        ok: false,
        error: "user already exists",
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (email, password_hash)
       VALUES ($1, $2)
       RETURNING id, email`,
      [email, passwordHash]
    );

    const user = result.rows[0];

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.json({
      ok: true,
      user,
      token,
    });
  } catch (e) {
    console.error("REGISTER ERROR:", e);
    res.status(500).json({ ok: false, error: "register failed" });
  }
});

// ---------- LOGIN ----------
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        ok: false,
        error: "email and password required",
      });
    }

    const result = await pool.query(
      "SELECT id, email, password_hash FROM users WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        ok: false,
        error: "invalid credentials",
      });
    }

    const user = result.rows[0];

    const okPass = await bcrypt.compare(password, user.password_hash);
    if (!okPass) {
      return res.status(401).json({
        ok: false,
        error: "invalid credentials",
      });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.json({
      ok: true,
      user: { id: user.id, email: user.email },
      token,
    });
  } catch (e) {
    console.error("LOGIN ERROR:", e);
    res.status(500).json({ ok: false, error: "login failed" });
  }
});

// ======================================================
// PROMO SYSTEM
// ======================================================
app.post("/api/promo/validate", (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ ok: false });

    const store = readCodes();
    const clean = code.trim();

    if (store.master.includes(clean)) {
      return res.json({ ok: true, type: "master" });
    }

    const promo = store.promo.find((p) => p.code === clean);
    if (!promo) return res.json({ ok: false });

    if (promo.expiresAt && new Date(promo.expiresAt) < new Date()) {
      return res.json({ ok: false, reason: "expired" });
    }

    if (promo.used) {
      return res.json({ ok: false, reason: "used" });
    }

    return res.json({ ok: true, type: "promo" });
  } catch (e) {
    console.error("PROMO VALIDATE ERROR:", e);
    res.status(500).json({ ok: false });
  }
});

app.post("/api/promo/consume", (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ ok: false });

    const store = readCodes();
    const promo = store.promo.find((p) => p.code === code.trim());

    if (!promo) return res.json({ ok: false });

    promo.used = true;
    writeCodes(store);

    return res.json({ ok: true });
  } catch (e) {
    console.error("PROMO CONSUME ERROR:", e);
    res.status(500).json({ ok: false });
  }
});

// ==================
// GEMINI PROXY (JWT)
// ==================
app.post("/api/generate-image", authMiddleware, async (req, res) => {
  try {
    const { prompt } = req.body;

    if (!prompt || typeof prompt !== "string") {
      return res.status(400).json({ error: "prompt is required" });
    }

    const model = genAI.getGenerativeModel({
      model: "gemini-2.5-flash-image"
    });

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30_000);

    const result = await model.generateContent(prompt, {
      signal: controller.signal
    });

    clearTimeout(timeout);

    const response = await result.response;

    res.json({
      ok: true,
      data: response
    });
  } catch (err) {
    console.error("Gemini error:", err?.message || err);

    if (err.name === "AbortError") {
      return res.status(504).json({ error: "Gemini timeout" });
    }

    res.status(500).json({
      error: "generation failed",
      message: err?.message || "unknown error"
    });
  }
});

// ==================
// START SERVER
// ==================
app.listen(PORT, () => {
  console.log(`🚀 AI backend running on port ${PORT}`);
});
import crypto from "crypto";
import { Pool } from "pg";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import fs from "fs";
import path from "path";
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { GoogleGenerativeAI } from "@google/generative-ai";
import { sendMail } from "./services/mailService.js";

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
// BILLING WEBHOOK (SBP / PAYMENTS)
// ======================================================
app.post("/api/billing/webhook", async (req, res) => {
  try {
    const secret = req.headers["x-webhook-secret"];

    if (!secret || secret !== process.env.BILLING_WEBHOOK_SECRET) {
      return res.status(401).json({ ok: false, error: "invalid webhook secret" });
    }

    const { status, userId, tokens } = req.body;

    // ждём только успешную оплату
    if (status !== "paid") {
      return res.json({ ok: true, ignored: true });
    }

    if (!userId || !tokens || tokens <= 0) {
      return res.status(400).json({
        ok: false,
        error: "userId and tokens required",
      });
    }

    const result = await pool.query(
      "UPDATE users SET tokens = tokens + $1 WHERE id = $2 RETURNING id, email, tokens",
      [tokens, userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ ok: false, error: "user not found" });
    }

    console.log("💰 TOKENS ADDED:", result.rows[0]);

    return res.json({
      ok: true,
      user: result.rows[0],
    });
  } catch (e) {
    console.error("WEBHOOK ERROR:", e);
    res.status(500).json({ ok: false, error: "webhook failed" });
  }
});

// ======================================================
// SERVICE: ADD TOKENS (ADMIN ONLY)  🔥 ШАГ 3.1
// ======================================================
app.post("/api/admin/add-tokens", authMiddleware, async (req, res) => {
  try {
    const { userId, amount } = req.body;

    // 🔐 доступ только админу
    if (req.user.role !== "admin") {
      return res.status(403).json({ ok: false, error: "forbidden" });
    }

    if (!userId || !amount || amount <= 0) {
      return res.status(400).json({
        ok: false,
        error: "userId and positive amount required",
      });
    }

    const result = await pool.query(
      "UPDATE users SET tokens = tokens + $1 WHERE id = $2 RETURNING id, email, tokens",
      [amount, userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ ok: false, error: "user not found" });
    }

    return res.json({
      ok: true,
      user: result.rows[0],
    });
  } catch (e) {
    console.error("ADD TOKENS ERROR:", e);
    res.status(500).json({ ok: false, error: "add tokens failed" });
  }
});

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
      { id: user.id, email: user.email, role: "user" },
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
      "SELECT id, email, password_hash, role FROM users WHERE email = $1",
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
      { id: user.id, email: user.email, role: user.role },
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
// PASSWORD RESET — REQUEST
// ======================================================
app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ ok: false, error: "email required" });
    }

    const result = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    // даже если юзера нет — отвечаем одинаково (без утечки инфы)
    if (result.rows.length === 0) {
      return res.json({
        ok: true,
        message: "If user exists, reset instructions sent",
      });
    }

    const userId = result.rows[0].id;

    // генерируем токен
    const token = crypto.randomBytes(32).toString("hex");

    // срок жизни — 30 минут
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000);

    await pool.query(
      `INSERT INTO password_resets (user_id, token, expires_at)
       VALUES ($1, $2, $3)`,
      [userId, token, expiresAt]
    );

    // 🔔 ПОКА БЕЗ ПОЧТЫ — просто логируем
    console.log("🔐 PASSWORD RESET TOKEN:", token);

    return res.json({
      ok: true,
      message: "If user exists, reset instructions sent",
    });
  } catch (e) {
    console.error("FORGOT PASSWORD ERROR:", e);
    res.status(500).json({ ok: false, error: "forgot-password failed" });
  }
});

// ======================================================
// PASSWORD RESET — CONFIRM
// ======================================================
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({
        ok: false,
        error: "token and newPassword required",
      });
    }

    const result = await pool.query(
      `SELECT user_id, expires_at
       FROM password_resets
       WHERE token = $1`,
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ ok: false, error: "invalid token" });
    }

    const reset = result.rows[0];

    if (new Date(reset.expires_at) < new Date()) {
      return res.status(400).json({ ok: false, error: "token expired" });
    }

    const passwordHash = await bcrypt.hash(newPassword, 10);

    await pool.query(
      "UPDATE users SET password_hash = $1 WHERE id = $2",
      [passwordHash, reset.user_id]
    );

    // удаляем токен после использования
    await pool.query(
      "DELETE FROM password_resets WHERE token = $1",
      [token]
    );

    return res.json({
      ok: true,
      message: "password updated",
    });
  } catch (e) {
    console.error("RESET PASSWORD ERROR:", e);
    res.status(500).json({ ok: false, error: "reset-password failed" });
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
    let { requestId } = req.body;
    const { id, role } = req.user;

    // ======================================
    // 🔎 ВАЛИДАЦИЯ
    // ======================================
    if (!prompt || typeof prompt !== "string") {
      return res.status(400).json({ error: "prompt is required" });
    }

    // если фронт не прислал requestId — создаём сами
    if (!requestId) {
      requestId = `${id}-${Date.now()}`;
    }

    // ======================================
    // 🔁 ЗАЩИТА ОТ ДВОЙНЫХ ЗАПРОСОВ
    // ======================================
    try {
      await pool.query(
        "INSERT INTO request_logs (request_id, user_id) VALUES ($1, $2)",
        [requestId, id]
      );
    } catch (e) {
      if (e.code === "23505") {
        return res.json({
          ok: true,
          skipped: true,
          message: "request already processed",
        });
      }
      throw e;
    }

    // ======================================
    // 🔐 ПРОВЕРКА ПРАВ
    // ======================================
    if (role !== "admin") {
      const result = await pool.query(
        "SELECT tokens FROM users WHERE id = $1",
        [id]
      );

      if (result.rows.length === 0) {
        return res.status(401).json({ error: "user not found" });
      }

      const tokens = result.rows[0].tokens;

      if (tokens <= 0) {
        return res.status(403).json({
          error: "no tokens",
          message: "Токены закончились. Купите тариф.",
        });
      }

      // ⬇️ списываем 1 токен
      await pool.query(
        "UPDATE users SET tokens = tokens - 1 WHERE id = $1",
        [id]
      );

      // 📝 логируем
      await pool.query(
        `INSERT INTO token_logs (user_id, change, reason)
         VALUES ($1, $2, $3)`,
        [id, -1, "generation"]
      );
    } else {
      // лог для админа (не списываем)
      await pool.query(
        `INSERT INTO token_logs (user_id, change, reason)
         VALUES ($1, $2, $3)`,
        [id, 0, "admin_generation"]
      );
    }

    // ======================================
    // 🤖 ГЕНЕРАЦИЯ
    // ======================================
    const model = genAI.getGenerativeModel({
      model: "gemini-2.5-flash-image",
    });

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30_000);

    const result = await model.generateContent(prompt, {
      signal: controller.signal,
    });

    clearTimeout(timeout);

    const response = await result.response;

    res.json({
      ok: true,
      data: response,
    });
  } catch (err) {
    console.error("Gemini error:", err?.message || err);

    if (err.name === "AbortError") {
      return res.status(504).json({ error: "Gemini timeout" });
    }

    res.status(500).json({
      error: "generation failed",
      message: err?.message || "unknown error",
    });
  }
});

// ==================
// START SERVER
// ==================
app.listen(PORT, () => {
  console.log(`🚀 AI backend running on port ${PORT}`);
});

app.get("/test-mail", async (req, res) => {
  try {
    await sendMail({
      to: "ТВОЯ_ПОЧТА@gmail.com", // поставь свою реальную почту
      subject: "Тест почты",
      html: "<h2>Почта работает 🎉</h2><p>Если ты это читаешь — SMTP настроен правильно.</p>",
    });

    res.json({ ok: true, message: "Mail sent" });
  } catch (err) {
    console.error("MAIL ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});
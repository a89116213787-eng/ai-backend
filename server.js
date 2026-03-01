import { GoogleGenAI } from "@google/genai";
import crypto from "crypto";
import { Pool } from "pg";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import fs from "fs";
import path from "path";
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { sendMail } from "./src/services/mailClient.js";

dotenv.config();

// ===============================
// REQUEST SIGNATURE SECRET
// ===============================
// const REQUEST_SECRET = process.env.REQUEST_SECRET;

// if (!REQUEST_SECRET) {
 // console.error("❌ REQUEST_SECRET is missing in ENV");
 // process.exit(1);
//}

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
app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ limit: "25mb", extended: true }));

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

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY
});

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

import paymentsRouter from "./payments.js";
app.use("/api/payments", paymentsRouter(pool, authMiddleware));

// ===============================
// VERIFY SIGNATURE (anti-abuse)
// dev: отключено если нет REQUEST_SECRET
// ===============================
function verifyRequestSignature(req, res, next) {
  try {
    const secret = process.env.REQUEST_SECRET;
    const signature = req.headers["x-request-sign"];

    // если секрет не задан — пропускаем (dev режим)
    if (!secret) return next();

    // если секрет есть, но подписи нет — ошибка
    if (!signature) {
      return res.status(401).json({ error: "signature_missing" });
    }

    const expected = crypto
      .createHmac("sha256", secret)
      .update(JSON.stringify(req.body))
      .digest("hex");

    if (signature !== expected) {
      return res.status(401).json({ error: "bad_signature" });
    }

    next();
  } catch (e) {
    console.error("SIGNATURE ERROR:", e);
    res.status(500).json({ error: "signature_error" });
  }
}

// ==================
// 🔐 ADMIN ONLY MIDDLEWARE
// ==================
function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      ok: false,
      error: "admin access required",
    });
  }
  next();
}

// ==================
// 🔐 OWNER OR ADMIN
// пользователь может работать только со своими данными
// ==================
function requireSelfOrAdmin(getUserId) {
  return (req, res, next) => {
    const targetUserId = getUserId(req);

    if (req.user.role === "admin") {
      return next();
    }

    if (req.user.id !== targetUserId) {
      return res.status(403).json({
        ok: false,
        error: "forbidden",
      });
    }

    next();
  };
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

// ===============================
// 💳 МОИ ПЛАТЕЖИ
// ===============================
app.get("/api/payments/my", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;

    const result = await pool.query(
      `
      SELECT
        id,
        amount,
        tokens,
        status,
        provider,
        created_at
      FROM payments
      WHERE user_id = $1
      ORDER BY created_at DESC
      `,
      [userId]
    );

    res.json({
      ok: true,
      payments: result.rows,
    });
  } catch (e) {
    console.error("PAYMENTS MY ERROR:", e);
    res.status(500).json({
      ok: false,
      error: "Не удалось получить платежи",
    });
  }
});

// ======================================================
// SERVICE: ADD TOKENS (ADMIN ONLY)  🔥 ШАГ 3.1
// ======================================================
app.post("/api/admin/add-tokens", authMiddleware, requireAdmin, async (req, res) => {
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

    const role = email === "admin@local.dev" ? "admin" : "user";

    const result = await pool.query(
      `INSERT INTO users (email, password_hash, role)
       VALUES ($1, $2, $3)
       RETURNING id, email, role`,
      [email, passwordHash, role]
    );

    const user = result.rows[0];

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role,
      },
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
  user: {
    id: user.id,
    email: user.email,
    role: user.role,
  },
  role: user.role,
  token,
});

  } catch (e) {
    console.error("LOGIN ERROR:", e);
    res.status(500).json({ ok: false, error: "login failed" });
  }
});

app.get("/api/user/balance", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;

    const result = await pool.query(
      "SELECT tokens FROM users WHERE id = $1",
      [userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ ok: false });
    }

    res.json({
      ok: true,
      tokens: result.rows[0].tokens,
    });
  } catch (e) {
    console.error("BALANCE ERROR:", e);
    res.status(500).json({ ok: false });
  }
});

// ===============================
// 📅 SUBSCRIPTION STATUS
// ===============================
app.get("/api/user/subscription", authMiddleware, async (req, res) => {
  try {
    if (req.user.role === "admin") {
      return res.json({
        ok: true,
        active: true,
        admin: true,
        expires_at: null
      });
    }

    const sub = await pool.query(
      "SELECT expires_at FROM subscriptions WHERE user_id = $1",
      [req.user.id]
    );

    if (!sub.rows.length) {
      return res.json({ ok: true, active: false });
    }

    const expires = new Date(sub.rows[0].expires_at);
    const active = expires > new Date();

    res.json({
      ok: true,
      active,
      expires_at: expires
    });

  } catch (e) {
    console.error("SUB STATUS ERROR:", e);
    res.status(500).json({ ok: false });
  }
});

app.get("/api/user/me", authMiddleware, async (req, res) => {
  res.json({
    ok: true,
    email: req.user.email,
    id: req.user.id
  });
});

// ======================================================
// 🖼 USER GENERATIONS HISTORY
// ======================================================
app.get("/api/user/generations", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;

    const result = await pool.query(
      `
      SELECT id, prompt, image_url, created_at
      FROM generations
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 50
      `,
      [userId]
    );

    res.json({
      ok: true,
      items: result.rows,
    });

  } catch (e) {
    console.error("USER GENERATIONS ERROR:", e);
    res.status(500).json({
      ok: false,
      error: "failed to load generations",
    });
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

    // даже если юзера нет — отвечаем одинаково
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

    // 📧 отправляем письмо
    await sendMail({
      to: email,
      subject: "Восстановление пароля",
      html: `
        <h2>Сброс пароля</h2>
        <p>Перейдите по ссылке:</p>
        <p>
          <a href="https://dizain.pro/reset-password?token=${token}">
            Сбросить пароль
          </a>
        </p>
      `,
    });

    // ✅ ВАЖНО: ответ клиенту
    return res.json({
      ok: true,
      message: "If user exists, reset instructions sent",
    });
  } catch (e) {
    console.error("FORGOT PASSWORD ERROR:", e);
    return res.status(500).json({
      ok: false,
      error: "forgot-password failed",
    });
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

// ===============================
// RATE LIMIT (ANTI-SPAM GENERATION)
// ===============================
const generationCooldown = new Map(); // userId -> timestamp
const GENERATION_DELAY_MS = 8000; // 8 секунд между генерациями

// ===============================
// RATE LIMIT MIDDLEWARE
// ===============================
function rateLimitMiddleware(req, res, next) {
  try {
    const { id } = req.user;

    const now = Date.now();
    const last = generationCooldown.get(id);

    if (last && now - last < GENERATION_DELAY_MS) {
      const wait = Math.ceil((GENERATION_DELAY_MS - (now - last)) / 1000);

      return res.status(429).json({
        error: "too_many_requests",
        message: `Подождите ${wait} сек перед следующей генерацией`,
      });
    }

    generationCooldown.set(id, now);
    next();

  } catch (e) {
    console.error("RATE LIMIT ERROR:", e);
    next();
  }
}

// ==================
// GEMINI PROXY (JWT)
// ==================
app.post("/api/generate-image", authMiddleware, async (req, res) => {
  try {
    const {
  prompt,
  model: modelName,
  image,
  images,
  peopleImages,
  objectImages,
  mimeType,
  width,
  height,
  safety,
  mode,
  quality,
  aspectRatio,
  imageSize
} = req.body;
    let { requestId } = req.body;
    const { id, role } = req.user;

// ===============================
// 🔒 проверка подписки
// ===============================
if (role !== "admin") {

  const sub = await pool.query(
    "SELECT expires_at FROM subscriptions WHERE user_id = $1",
    [id]
  );

  if (!sub.rows.length || new Date(sub.rows[0].expires_at) < new Date()) {
    return res.status(403).json({
      ok: false,
      message: "Подписка закончилась. Купите тариф для продолжения."
    });
  }
}

    // ======================================
    // 🔎 ВАЛИДАЦИЯ
    // ======================================
    if (!prompt || typeof prompt !== "string") {
      return res.status(400).json({ error: "prompt is required" });
    }

// ===============================
// 🛡 IMAGE SIZE SAFETY LIMIT
// ===============================

const MAX_IMAGE_SIZE_MB = 5;
const MAX_IMAGES = 4;

function getBase64SizeMB(base64) {
  if (!base64 || typeof base64 !== "string") return 0;
  const clean = base64.replace(/^data:.*;base64,/, "");
  return (clean.length * 3 / 4) / (1024 * 1024);
}

let allIncomingImages = [];

// собираем все возможные входящие изображения
if (image) allIncomingImages.push(image);
if (Array.isArray(images)) allIncomingImages.push(...images);
if (Array.isArray(peopleImages)) allIncomingImages.push(...peopleImages);
if (Array.isArray(objectImages)) allIncomingImages.push(...objectImages);

// ограничение по количеству
if (allIncomingImages.length > MAX_IMAGES) {
  return res.status(400).json({
    error: `Maximum ${MAX_IMAGES} images allowed`
  });
}

// ограничение по размеру
for (const img of allIncomingImages) {
  const sizeMB = getBase64SizeMB(img);
  if (sizeMB > MAX_IMAGE_SIZE_MB) {
    return res.status(400).json({
      error: `Image too large. Max ${MAX_IMAGE_SIZE_MB}MB allowed`
    });
  }
}

// ===============================
// ✏ EDIT MODE VALIDATION (PRO SUPPORT)
// ===============================
if (
  mode === "edit" &&
  !image &&
  !images &&
  !peopleImages &&
  !objectImages
) {
  return res.status(400).json({
    error: "Edit mode requires image input"
  });
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
// ⏱ RATE LIMIT (ПОСЛЕ anti-duplicate)
// ======================================
const now = Date.now();
const last = generationCooldown.get(id);

if (last && now - last < GENERATION_DELAY_MS) {
  const wait = Math.ceil((GENERATION_DELAY_MS - (now - last)) / 1000);

  return res.status(429).json({
    error: "too_many_requests",
    message: `Подождите ${wait} сек перед следующей генерацией`,
  });
}

generationCooldown.set(id, now);

// ======================================
// 🔐 ПРОВЕРКА ПРАВ + АТОМАРНОЕ СПИСАНИЕ
// ======================================
if (role !== "admin") {

  // списываем 1 токен ТОЛЬКО если он есть
  const debit = await pool.query(
    `
    UPDATE users
    SET tokens = tokens - 1
    WHERE id = $1 AND tokens > 0
    RETURNING tokens
    `,
    [id]
  );

  // если токенов не было
  if (debit.rowCount === 0) {
    return res.status(403).json({
      error: "no_tokens",
      message: "Токены закончились. Купите тариф.",
    });
  }

  // лог
  await pool.query(
    `INSERT INTO token_logs (user_id, change, reason)
     VALUES ($1, $2, 'generation')`,
    [id, -1]
  );

} else {

  // админ не тратит токены
  await pool.query(
    `INSERT INTO token_logs (user_id, change, reason)
     VALUES ($1, 0, 'admin_generation')`,
    [id]
  );

}

// ===============================
// 🎨 QUALITY MODES
// ===============================

let finalModel = modelName || "gemini-2.5-flash-image";
let finalWidth = 1024;
let finalHeight = 1024;
let temperature = 0.9;
let outputMimeType = "image/png";

// 🔵 FLASH 2.5 — всегда максимум
if (finalModel === "gemini-2.5-flash-image") {

  finalWidth = 2048;
  finalHeight = 2048;
  temperature = 0.9;
  outputMimeType = "image/png";

}

// 🟣 GEMINI 3 PRO
if (finalModel === "gemini-3-pro-image-preview") {

  temperature = 1.0;
  outputMimeType = "image/png";

  if (imageSize === "1K") {
    finalWidth = 1024;
    finalHeight = 1024;
  }

  else if (imageSize === "2K") {
    finalWidth = 2048;
    finalHeight = 2048;
  }

  else if (imageSize === "4K") {
    finalWidth = 4096;
    finalHeight = 4096;
  }

  else {
    finalWidth = 2048;
    finalHeight = 2048;
  }
}

const isProModel = finalModel === "gemini-3-pro-image-preview";

// ===============================
// 📐 ASPECT RATIO SUPPORT (64 aligned)
// ===============================

if (aspectRatio && typeof aspectRatio === "string") {

  const [w, h] = aspectRatio.split(":").map(Number);

  if (w && h) {

    const base = 1024;

    let rawWidth, rawHeight;

    if (w >= h) {
      rawWidth = base;
      rawHeight = base * (h / w);
    } else {
      rawHeight = base;
      rawWidth = base * (w / h);
    }

    // делаем кратным 64
    finalWidth = Math.round(rawWidth / 64) * 64;
    finalHeight = Math.round(rawHeight / 64) * 64;

  }
}

// ===============================
// 🖼 IMAGE REFERENCES (PRO IDENTITY SUPPORT)
// ===============================

let parts = [];
let orderedImages = [];

// 🟣 PRO MODEL — structured identity
if (finalModel === "gemini-3-pro-image-preview") {

  // 👤 PEOPLE IMAGES (лица сохраняем)
  if (Array.isArray(peopleImages) && peopleImages.length > 0) {

    peopleImages.forEach((img) => {
      if (!img) return;

      const base64 = img.replace(/^data:.*;base64,/, "");

      parts.push({
        inlineData: {
          data: base64,
          mimeType: "image/png"
        }
      });
    });

    parts.push({
      text: "Preserve identity, facial structure, eyes, nose, mouth, proportions and skin tone of provided people images."
    });
  }

  // 🏞 OBJECT IMAGES (фон / одежда)
  if (Array.isArray(objectImages) && objectImages.length > 0) {

    objectImages.forEach((img) => {
      if (!img) return;

      const base64 = img.replace(/^data:.*;base64,/, "");

      parts.push({
        inlineData: {
          data: base64,
          mimeType: "image/png"
        }
      });
    });

    parts.push({
      text: "Use object images as editable environment or clothing reference."
    });
  }

}

// 🔵 Flash или fallback режим
else {

  if (Array.isArray(images) && images.length > 0) {
    orderedImages = images;
  }
  else if (image && typeof image === "string") {
    orderedImages = [image];
  }

  if (orderedImages.length > 14) {
    return res.status(400).json({
      error: "Maximum 14 reference images allowed"
    });
  }

  orderedImages.forEach((img) => {

    if (!img) return;

    const base64 = img.replace(/^data:.*;base64,/, "");

    parts.push({
      inlineData: {
        data: base64,
        mimeType: "image/png"
      }
    });

  });

}
// ===============================
// ✏ TEXT PROMPT (ПОСЛЕ ИЗОБРАЖЕНИЙ)
// ===============================

let numberedInstruction = "";

if (orderedImages.length > 0) {
  numberedInstruction =
    `You are editing provided images.\n` +
    `Image numbering follows order:\n` +
    orderedImages
      .map((_, i) => `Image ${i + 1}`)
      .join("\n") +
    `\n\n`;
}

let finalPrompt = "";

if (mode === "edit") {

  finalPrompt = `
You are performing controlled image editing.

Rules:
- Preserve facial identity if people images were provided.
- Do not alter identity unless explicitly instructed.
- Maintain realism and anatomical correctness.
- Apply only requested modifications.

User instruction:
${prompt}
`;

} else {

  finalPrompt = `
Generate a high quality, highly detailed image.
${prompt}
`;

}

parts.push({
  text: finalPrompt
});

// ======================================
// 🤖 ГЕНЕРАЦИЯ (FINAL CLEAN VERSION)
// ======================================

let response;
let imageBase64 = null;
let imageMime = "image/png";

// Для image моделей
if (finalModel.includes("image")) {

  response = await ai.models.generateContent({
  model: finalModel,
  contents: [
    {
      role: "user",
      parts
    }
  ],
  config: {
  responseModalities: ["IMAGE"],
  temperature,
  imageConfig: {
    width: finalWidth,
    height: finalHeight
  }
}
});

  const candidate = response?.candidates?.[0];
  const contentParts = candidate?.content?.parts || [];

  const imagePart = contentParts.find(p => p.inlineData?.data);

  if (!imagePart) {
    console.error("⚠ Gemini returned no IMAGE modality");
    console.error(JSON.stringify(response, null, 2));
    throw new Error("No image returned from model");
  }

  imageBase64 = imagePart.inlineData.data;
  imageMime = imagePart.inlineData.mimeType || "image/png";

} else {

  // Текстовая модель
  response = await ai.models.generateContent({
    model: finalModel,
    contents: prompt,
    config: {
      temperature
    }
  });

}

// ===============================
// 🧠 THINKING LOG (PRO)
// ===============================
if (isProModel) {
  const thoughtParts = response?.candidates?.[0]?.content?.parts
    ?.filter(p => p.thought);

  if (thoughtParts?.length) {
    console.log("🧠 Gemini thinking:", thoughtParts.length);
  }
}

    // ======================================
// 💾 СОХРАНЯЕМ В ИСТОРИЮ
// ======================================

if (imageBase64) {

  const imageUrl = `data:${imageMime};base64,${imageBase64}`;

  await pool.query(
    `INSERT INTO generations (user_id, prompt, image_url)
     VALUES ($1, $2, $3)`,
    [id, prompt, imageUrl]
  );

  return res.json({
    ok: true,
    image: imageUrl
  });
}

// текстовый ответ
return res.json({
  ok: true,
  data: response
});

    // ======================================
    // ОТВЕТ КЛИЕНТУ (ВСЕГДА!)
    // ======================================

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

// ===============================
// 🚀 STREAM GENERATION
// ===============================
app.post("/api/generate-image-stream", authMiddleware, async (req, res) => {
  try {
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");

    const stream = await ai.models.generateContentStream({
      model: "gemini-3-pro-image-preview",
      contents: [
        {
          role: "user",
          parts: [{ text: req.body.prompt }]
        }
      ]
    });

    for await (const chunk of stream) {
      res.write(`data: ${JSON.stringify(chunk)}\n\n`);
    }

    res.end();

  } catch (err) {
    console.error("STREAM ERROR:", err);
    res.status(500).end();
  }
});

// ==================
// START SERVER
// ==================
app.listen(PORT, () => {
  console.log(`🚀 AI backend running on port ${PORT}`);
});

app.get("/api/debug/users", authMiddleware, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, email, role, tokens FROM users ORDER BY id"
    );

    res.json({
      ok: true,
      users: result.rows,
    });
  } catch (e) {
    res.status(500).json({
      ok: false,
      error: e.message,
    });
  }
});

// ======================================================
// YOOKASSA WEBHOOK (БОЕВОЙ)
// ======================================================
app.post("/api/payments/webhook/yookassa", async (req, res) => {
  try {
    const event = req.body;

    // интересует только успешная оплата
    if (event.event !== "payment.succeeded") {
      return res.json({ ok: true });
    }

    const paymentObject = event.object;

    const paymentId = paymentObject.metadata?.payment_id;

    if (!paymentId) {
      return res.status(400).json({
        ok: false,
        error: "payment_id not found in metadata",
      });
    }

    // проверяем платёж
    const result = await pool.query(
      "SELECT * FROM payments WHERE id = $1",
      [paymentId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        ok: false,
        error: "payment not found",
      });
    }

    const payment = result.rows[0];
    const userId = payment.user_id;

    // защита от двойного вебхука
    if (payment.status === "paid") {
      return res.json({ ok: true, alreadyProcessed: true });
    }

    // отмечаем платёж
    await pool.query(
      "UPDATE payments SET status = 'paid', provider_payment_id = $1 WHERE id = $2",
      [paymentObject.id, paymentId]
    );

    // начисляем токены
    await pool.query(
      "UPDATE users SET tokens = tokens + $1 WHERE id = $2",
      [payment.tokens, payment.user_id]
    );

// =======================
// ПОДПИСКА
// =======================

// проверяем подписку
const sub = await pool.query(
  `SELECT expires_at FROM subscriptions WHERE user_id=$1`,
  [userId]
);

const now = new Date();

if (sub.rows.length === 0) {
  // подписки нет → создаём на 30 дней
  const expires = new Date(now);
  expires.setDate(expires.getDate() + 30);

  await pool.query(
    `INSERT INTO subscriptions (user_id, expires_at)
     VALUES ($1, $2)`,
    [userId, expires]
  );
} else {
  const expires = new Date(sub.rows[0].expires_at);

  if (expires < now) {
    // подписка закончилась → новая 30 дней
    const newExpire = new Date(now);
    newExpire.setDate(newExpire.getDate() + 30);

    await pool.query(
      `UPDATE subscriptions SET expires_at=$1 WHERE user_id=$2`,
      [newExpire, userId]
    );
  }
  // если активна — НЕ трогаем
}

    // лог
    await pool.query(
      `INSERT INTO token_logs (user_id, change, reason)
       VALUES ($1, $2, 'payment')`,
      [payment.user_id, payment.tokens]
    );

    return res.json({ ok: true });
  } catch (e) {
    console.error("YOOKASSA WEBHOOK ERROR:", e);
    res.status(500).json({ ok: false });
  }
});

// ======================================================
// 💰 MOCK PAYMENT CONFIRM (как webhook ЮKassa)
// ======================================================
app.post("/api/payments/mock-paid", authMiddleware, async (req, res) => {
  try {
    const { payment_id } = req.body;

    if (!payment_id) {
      return res.status(400).json({
        ok: false,
        error: "payment_id обязателен",
      });
    }

    // 1️⃣ получаем платёж
    const paymentRes = await pool.query(
      `SELECT * FROM payments WHERE id = $1`,
      [payment_id]
    );

    if (paymentRes.rows.length === 0) {
      return res.status(404).json({
        ok: false,
        error: "Платёж не найден",
      });
    }

    const payment = paymentRes.rows[0];

    if (payment.status === "paid") {
      return res.json({
        ok: true,
        message: "Платёж уже подтверждён",
      });
    }

    // 2️⃣ обновляем статус платежа
    await pool.query(
      `UPDATE payments SET status = 'paid' WHERE id = $1`,
      [payment_id]
    );

    // 3️⃣ начисляем токены пользователю
    await pool.query(
      `
      UPDATE users
      SET tokens = tokens + $1
      WHERE id = $2
      `,
      [payment.tokens, payment.user_id]
    );

    // =======================
// ПОДПИСКА (1 месяц доступа)
// =======================

const userId = payment.user_id;

const sub = await pool.query(
  `SELECT expires_at FROM subscriptions WHERE user_id=$1`,
  [userId]
);

const now = new Date();

if (sub.rows.length === 0) {
  // подписки нет → создаём на 30 дней
  const expires = new Date(now);
  expires.setDate(expires.getDate() + 30);

  await pool.query(
    `INSERT INTO subscriptions (user_id, expires_at)
     VALUES ($1, $2)`,
    [userId, expires]
  );

} else {
  const expires = new Date(sub.rows[0].expires_at);

  // если подписка истекла → даём новый месяц
  if (expires < now) {
    const newExpire = new Date(now);
    newExpire.setDate(newExpire.getDate() + 30);

    await pool.query(
      `UPDATE subscriptions SET expires_at=$1 WHERE user_id=$2`,
      [newExpire, userId]
    );
  }
  // если активна — НЕ продлеваем
}

    res.json({
      ok: true,
      message: "Платёж подтверждён, токены начислены",
    });
  } catch (e) {
    console.error("MOCK PAID ERROR:", e);

    res.status(500).json({
      ok: false,
      error: "Ошибка подтверждения платежа",
    });
  }
});

// ======================================================
// PAYMENTS — HISTORY (USER)
// ======================================================
app.get("/api/payments/history", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;

    const result = await pool.query(
      `SELECT 
         id,
         amount,
         tokens,
         status,
         provider,
         created_at
       FROM payments
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [userId]
    );

    return res.json({
      ok: true,
      payments: result.rows,
    });
  } catch (e) {
    console.error("PAYMENTS HISTORY ERROR:", e);
    res.status(500).json({ ok: false, error: "history failed" });
  }
});

// ======================================================
// 💳 ADMIN — ALL PAYMENTS
// ======================================================
app.get("/api/admin/payments", authMiddleware, async (req, res) => {
  try {
    // 🔐 только админ
    if (req.user.role !== "admin") {
      return res.status(403).json({ ok: false, error: "forbidden" });
    }

    const result = await pool.query(`
      SELECT
        p.id,
        p.amount,
        p.tokens,
        p.status,
        p.provider,
        p.created_at,
        u.email
      FROM payments p
      JOIN users u ON u.id = p.user_id
      ORDER BY p.created_at DESC
    `);

    return res.json({
      ok: true,
      payments: result.rows,
    });
  } catch (e) {
    console.error("ADMIN PAYMENTS ERROR:", e);
    res.status(500).json({
      ok: false,
      error: "failed to load payments",
    });
  }
});
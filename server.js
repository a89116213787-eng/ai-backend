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
import { verifyEmailTemplate } from "./src/templates/emails/verifyEmailTemplate.js";
import { uploadToR2 } from "./utils/uploadToR2.js";
import sharp from "sharp";
import Replicate from "replicate";
import { S3Client, GetObjectCommand, PutObjectCommand, DeleteObjectCommand, ListObjectsV2Command } from "@aws-sdk/client-s3";
import deleteImageRoute from "./delete-image.js";
import multer from "multer";

async function normalizeImageToBase64(img) {

  if (!img) return null;

  // если уже base64
  if (img.startsWith("data:")) {
    return img.replace(/^data:.*;base64,/, "");
  }

  // если URL (R2)
  if (img.startsWith("http")) {

    const response = await fetch(img);
    const buffer = await response.arrayBuffer();

    return Buffer.from(buffer).toString("base64");
  }

  return null;
}

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

// увеличиваем timeout для долгих генераций (4K / PRO)
app.use((req, res, next) => {
  res.setTimeout(120000); // 120 секунд
  next();
});

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

// ===============================
// KLING / REPLICATE CLIENT
// ===============================
const replicate = new Replicate({
  auth: process.env.REPLICATE_API_TOKEN
});

// ===============================
// VIDEO CACHE
// ===============================
const videoCache = new Map();

// ===============================
// KLING MODELS
// ===============================
const KLING_MODELS = {

  flash: "kwaivgi/kling-v2.1",

  pro: "kwaivgi/kling-v2.6",

  ultra: "kwaivgi/kling-v3-omni-video",

  motion: "kwaivgi/kling-v3-motion-control"

};

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
app.use("/api", deleteImageRoute);

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
// ФУНКЦИЯ УДАЛЕНИЯ АККАУНТОВ
// ======================================================
async function deleteUserWithCleanup(userId) {

  const user = await pool.query(
    `SELECT avatar_url FROM users WHERE id = $1`,
    [userId]
  );

  if (!user.rows.length) {
    throw new Error("user_not_found");
  }

  const avatar = user.rows[0]?.avatar_url;

  const s3 = new S3Client({
    region: "auto",
    endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
    credentials: {
      accessKeyId: process.env.R2_ACCESS_KEY,
      secretAccessKey: process.env.R2_SECRET_KEY,
    },
  });

  const files = await pool.query(
    `SELECT image_url, video_url FROM generations WHERE user_id = $1`,
    [userId]
  );

  for (const row of files.rows) {

    const urls = [row.image_url, row.video_url].filter(Boolean);

    for (const url of urls) {

      if (!url) continue;

      try {

        let key;

      if (url.includes("/api/download-video/")) {
        key = "videos/" + url.split("/api/download-video/")[1];
      } else {
        const parsed = new URL(url);
        key = parsed.pathname.slice(1);
      }

        await s3.send(new DeleteObjectCommand({
          Bucket: process.env.R2_BUCKET,
          Key: key
        }));

      } catch (e) {
        console.error("R2 delete error:", e);
      }

    }
  }

  if (avatar) {
    try {

      const key = new URL(avatar).pathname.slice(1);

      await s3.send(new DeleteObjectCommand({
        Bucket: process.env.R2_BUCKET,
        Key: key
      }));

    } catch (e) {
      console.error("avatar delete error:", e);
    }
  }

  const client = await pool.connect();

try {

  await client.query("BEGIN");

  await client.query(`DELETE FROM generations WHERE user_id = $1`, [userId]);
  await client.query(`DELETE FROM assistant_messages WHERE user_id = $1`, [userId]);
  await client.query(`DELETE FROM subscriptions WHERE user_id = $1`, [userId]);
  await client.query(`DELETE FROM token_logs WHERE user_id = $1`, [userId]);
  await client.query(`DELETE FROM payments WHERE user_id = $1`, [userId]);
  await client.query(`DELETE FROM workspaces WHERE user_id = $1`, [userId]);
  await client.query(`DELETE FROM password_resets WHERE user_id = $1`, [userId]);

  await client.query(`DELETE FROM users WHERE id = $1`, [userId]);

  await client.query("COMMIT");

} catch (e) {

  await client.query("ROLLBACK");
  throw e;

} finally {

  client.release();

}

}

// ======================================================
// ADMIN — DELETE USER (SAFE)
// ======================================================

app.post("/api/admin/delete-user", authMiddleware, requireAdmin, async (req, res) => {
  try {

    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({ ok:false });
    }

    // получаем пользователя
    const user = await pool.query(
      `SELECT id, role, avatar_url FROM users WHERE id = $1`,
      [userId]
    );

    if (!user.rows.length) {
      return res.status(404).json({ ok:false });
    }

    const target = user.rows[0];

    // ❌ нельзя удалить админа
    if (target.role === "admin") {
      return res.status(403).json({
        ok:false,
        error:"cannot_delete_admin"
      });
    }

    // ❌ нельзя удалить себя
    if (req.user.id === userId) {
      return res.status(403).json({
        ok:false,
        error:"cannot_delete_self"
      });
    }

    await deleteUserWithCleanup(userId);

      console.log(`🧹 user ${userId} deleted with cleanup`);

      res.json({ ok:true });

    } catch(e) {

      console.error("DELETE USER ERROR:",e);

      res.status(500).json({
        ok:false
      });

    }
  });

// ======================================================
// USER — DELETE SELF ACCOUNT
// ======================================================

app.post("/api/user/delete-account", authMiddleware, async (req, res) => {
  try {

    const userId = req.user.id;

    await deleteUserWithCleanup(userId);

    console.log(`🧹 self user ${userId} deleted`);

    res.json({ ok:true });

  } catch(e) {

    console.error("SELF DELETE ERROR:", e);

    res.status(500).json({ ok:false });
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
  const client = await pool.connect(); // 🔥 ВАЖНО

  try {
    const { email, password, captcha } = req.body;

    // ===============================
    // 🧹 NORMALIZE EMAIL
    // ===============================
    const emailNormalized = email?.trim().toLowerCase();

    // ===============================
    // CLOUDFLARE TURNSTILE CHECK
    // ===============================
    const verify = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          secret: process.env.TURNSTILE_SECRET,
          response: captcha
        })
      }
    );

    const captchaResult = await verify.json();

    if (!captchaResult.success) {
      return res.status(400).json({
        ok: false,
        error: "captcha_failed"
      });
    }

    if (!emailNormalized || !password) {
      return res.status(400).json({
        ok: false,
        error: "email and password required",
      });
    }

    // ===============================
    // 🚀 НАЧИНАЕМ ТРАНЗАКЦИЮ
    // ===============================
    await client.query("BEGIN");

    const exists = await client.query(
      "SELECT id FROM users WHERE email = $1",
      [emailNormalized]
    );

    if (exists.rows.length > 0) {
      await client.query("ROLLBACK");
      return res.status(400).json({
        ok: false,
        error: "user already exists",
      });
    }

    // ===============================
    // 🧠 ПРОВЕРКА TRIAL
    // ===============================
    const trialInsert = await client.query(
      `
      INSERT INTO used_trials (email)
      VALUES ($1)
      ON CONFLICT (email) DO NOTHING
      RETURNING email
      `,
      [emailNormalized]
    );

    const hasUsedTrial = trialInsert.rowCount === 0;

    const passwordHash = await bcrypt.hash(password, 10);

    const role = emailNormalized === "admin@local.dev" ? "admin" : "user";

    const tokens = hasUsedTrial ? 0 : 50;
    const trialUsed = hasUsedTrial;

    // ===============================
    // EMAIL VERIFY TOKEN
    // ===============================
    const verifyToken = crypto.randomBytes(32).toString("hex");

    const verifyExpires = new Date(
      Date.now() + 24 * 60 * 60 * 1000 // 24 часа
    );

    const result = await client.query(
      `
      INSERT INTO users (
        email,
        password_hash,
        role,
        tokens,
        trial_used,
        email_verified,
        email_verify_token,
        email_verify_expires
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      RETURNING id, email, role
      `,
      [
        emailNormalized,
        passwordHash,
        role,
        tokens,
        trialUsed,
        false,
        verifyToken,
        verifyExpires
      ]
    );

    const user = result.rows[0];

    // ===============================
    // 🎁 TRIAL (если не использовал)
    // ===============================
    if (!hasUsedTrial) {

      const now = new Date();
      const expires = new Date(now);
      expires.setDate(expires.getDate() + 5);

      await client.query(
        `INSERT INTO subscriptions (user_id, expires_at)
         VALUES ($1, $2)`,
        [user.id, expires]
      );
    }

    // ===============================
    // ✅ КОММИТ
    // ===============================
    await client.query("COMMIT");

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role,
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    // ===============================
    // 📧 SEND VERIFY EMAIL
    // ===============================
      await sendMail({
          to: emailNormalized,
          subject: "Подтверждение почты — ДизАiн",
          html: verifyEmailTemplate(
            `https://dizain.pro/api/auth/verify-email?token=${verifyToken}`,
            emailNormalized
          )
        });


    return res.json({
      ok: true,
      user,
      token,
    });

  } catch (e) {

    // ===============================
    // ❌ ROLLBACK ПРИ ЛЮБОЙ ОШИБКЕ
    // ===============================
    await client.query("ROLLBACK");

    console.error("REGISTER ERROR:", e);

    res.status(500).json({ ok: false, error: "register failed" });

  } finally {

    // ===============================
    // 🔌 ОСВОБОЖДАЕМ СОЕДИНЕНИЕ
    // ===============================
    client.release();

  }
});

    // ======================================================
    // EMAIL VERIFY
    // ======================================================
    app.get("/api/auth/verify-email", async (req, res) => {
      try {

        const { token } = req.query;

        if (!token) {
          return res.status(400).send("Invalid token");
        }

        const result = await pool.query(
          `
          SELECT id, email_verify_expires
          FROM users
          WHERE email_verify_token = $1
          `,
          [token]
        );

         if (!result.rows.length) {
           return res.status(400).send(`
             <html>
               <head>
                 <style>
                   @font-face {
                     font-family: "Gothic";
                     src: url("https://dizain.pro/fonts/GOTHIC.TTF") format("truetype");
                   }

                   body {
                     font-family: "Gothic", sans-serif;
                     -webkit-font-smoothing: antialiased;
                   }
                 </style>
               </head>
                <body style="
                 min-height:100vh;
                 background:#000;
                 display:flex;
                 align-items:center;
                 justify-content:center;
                 padding:2rem;
                 color:white;
                 font-family:Gothic,sans-serif;
                 margin:0;
               ">
                 <div style="
                   width:100%;
                   max-width:420px;
                   box-sizing:border-box;
                   text-align:center;
                   background:rgba(255,255,255,0.04);
                   border:1px solid rgba(255,255,255,0.05);
                   border-radius:24px;
                   padding:3rem 2rem;
                   backdrop-filter:blur(25px);
                   box-shadow:0 10px 40px rgba(0,0,0,0.6);
                  ">
                   <h2 style="
                     font-size:1.45rem;
                     font-weight:500;
                     margin-bottom:0.4rem;
                   ">
                     Ссылка недействительна
                   </h2>
                   <p style="
                     font-size:0.95rem;
                     color:#aaa;
                     line-height:1.5;
                     margin-bottom:2rem;
                   ">
                     Срок подтверждения истёк<br/>
                     Зарегистрируйтесь снова
                   </p>

                   <a
                     href="https://dizain.pro/auth/register"
                      style="
                        display:inline-block;
                        width:100%;
                        padding:0.95rem 1rem;
                        border-radius:9999px;
                        background:white;
                        border:none;
                        color:black;
                        font-weight:400;
                        text-decoration:none;
                        box-sizing:border-box;
                        text-align:center;
                      "
                     >
                     Регистрация
                   </a>
                 </div>
               </body>
             </html>
           `);
         }

        const user = result.rows[0];

        if (
          !user.email_verify_expires ||
          new Date(user.email_verify_expires) < new Date()
        ) {
           return res.status(400).send(`
              <html>
               <head>
                 <style>
                   @font-face {
                     font-family: "Gothic";
                     src: url("https://dizain.pro/fonts/GOTHIC.TTF") format("truetype");
                   }

                   body {
                     font-family: "Gothic", sans-serif;
                     -webkit-font-smoothing: antialiased;
                   }
                 </style>
               </head>
                <body style="
                 min-height:100vh;
                 background:#000;
                 display:flex;
                 align-items:center;
                 justify-content:center;
                 padding:2rem;
                 color:white;
                 font-family:Gothic,sans-serif;
                 margin:0;
               ">
                 <div style="
                   width:100%;
                   max-width:420px;
                   box-sizing:border-box;
                   text-align:center;
                   background:rgba(255,255,255,0.04);
                   border:1px solid rgba(255,255,255,0.05);
                   border-radius:24px;
                   padding:3rem 2rem;
                   backdrop-filter:blur(25px);
                   box-shadow:0 10px 40px rgba(0,0,0,0.6);
                  ">
                   <h2 style="
                     font-size:1.45rem;
                     font-weight:500;
                     margin-bottom:0.4rem;
                   ">
                     Ссылка недействительна
                   </h2>
                   <p style="
                     font-size:0.95rem;
                     color:#aaa;
                     line-height:1.5;
                     margin-bottom:2rem;
                   ">
                     Срок подтверждения истёк<br/>
                     Зарегистрируйтесь снова
                   </p>

                   <a
                     href="https://dizain.pro/auth/register"
                      style="
                        display:inline-block;
                        width:100%;
                        padding:0.95rem 1rem;
                        border-radius:9999px;
                        background:white;
                        border:none;
                        color:black;
                        font-weight:400;
                        text-decoration:none;
                        box-sizing:border-box;
                        text-align:center;
                      "
                     >
                     Регистрация
                   </a>
                 </div>
               </body>
             </html>
           `);
         }

        await pool.query(
          `
          UPDATE users
          SET
            email_verified = true,
            email_verify_token = NULL,
            email_verify_expires = NULL,
            verification_reminders_sent = 0
          WHERE id = $1
          `,
          [user.id]
        );

       return res.redirect("https://dizain.pro/auth/login?verified=1");

      } catch (e) {

        console.error("VERIFY EMAIL ERROR:", e);

        return res.status(500).send("Verification failed");

      }
    });

    // ======================================================
    // RESEND VERIFY EMAIL
    // ======================================================
    app.post("/api/auth/resend-verification", async (req, res) => {
      try {

        const { email } = req.body;

        const emailNormalized = email?.trim().toLowerCase();

        if (!emailNormalized) {
          return res.status(400).json({
            ok: false,
            error: "email required"
          });
        }

        const result = await pool.query(
          `
          SELECT
          id,
          email_verified,
          email_verify_expires
          FROM users
          WHERE email = $1
          `,
          [emailNormalized]
        );

        // всегда одинаковый ответ
        if (!result.rows.length) {
          return res.json({
            ok: true
          });
        }

        const user = result.rows[0];

        // уже подтвержден
        if (user.email_verified) {
          return res.json({
            ok: true
          });
        }

    // ===============================
    // RESEND LIMIT (2 HOURS)
    // ===============================
    const nextAllowedResend =
      new Date(user.email_verify_expires).getTime()
      - (22 * 60 * 60 * 1000);

    if (Date.now() < nextAllowedResend) {

      const minutes = Math.ceil(
        (nextAllowedResend - Date.now()) / 60000
      );

      return res.status(429).json({
        ok: false,
        error: "resend_cooldown",
        minutes
      });

    }

        // новый токен
        const verifyToken = crypto.randomBytes(32).toString("hex");

        const verifyExpires = new Date(
          Date.now() + 24 * 60 * 60 * 1000
        );

        await pool.query(
          `
          UPDATE users
          SET
            email_verify_token = $1,
            email_verify_expires = $2,
            verification_reminders_sent = 0
          WHERE id = $3
          `,
          [
            verifyToken,
            verifyExpires,
            user.id
          ]
        );

        // отправка письма
        await sendMail({
          to: emailNormalized,
          subject: "Подтверждение почты — ДизАiн",
          html: verifyEmailTemplate(
            `https://dizain.pro/api/auth/verify-email?token=${verifyToken}`,
            emailNormalized
          )
        });

        return res.json({
          ok: true
        });

      } catch (e) {

        console.error("RESEND VERIFY ERROR:", e);

        return res.status(500).json({
          ok: false
        });

      }
    });

  // ---------- LOGIN ----------
  app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const emailNormalized = email.trim().toLowerCase();

    if (!email || !password) {
      return res.status(400).json({
        ok: false,
        error: "email and password required",
      });
    }

    const result = await pool.query(
      `
      SELECT
        id,
        email,
        password_hash,
        role,
        email_verified
      FROM users
      WHERE email = $1
      `,
      [emailNormalized]
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

    // ===============================
    // EMAIL NOT VERIFIED
    // ===============================
    if (!user.email_verified) {
      return res.status(403).json({
        ok: false,
        error: "email_not_verified"
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

    const user = await pool.query(
  "SELECT admin_subscription FROM users WHERE id = $1",
  [req.user.id]
);

if (req.user.role === "admin" || user.rows[0]?.admin_subscription) {
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
  try {
    const result = await pool.query(
      "SELECT id, email, avatar_url, first_name, last_name FROM users WHERE id = $1",
      [req.user.id]
    );

    const user = result.rows[0];

    res.json({
      ok: true,
      id: user.id,
      email: user.email,
      avatar_url: user.avatar_url,
      first_name: user.first_name,
      last_name: user.last_name
    });

  } catch (e) {
    console.error("ME ERROR:", e);
    res.status(500).json({ ok: false });
  }
});

// ======================================================
// 💬 SUPPORT SYSTEM
// ======================================================

// история пользователя
app.get(
"/api/support/history",
authMiddleware,
async(req,res)=>{

try{

const result=await pool.query(
`
SELECT
id,
message,
sender,
is_read,
created_at
FROM support_messages
WHERE user_id=$1
AND is_closed=false
ORDER BY created_at ASC
`,
[req.user.id]
);

res.json({
ok:true,
messages:result.rows
});

}catch(e){

console.error(
"SUPPORT HISTORY ERROR:",
e
);

res.status(500).json({
ok:false
});

}

});

// пользователь отправляет
app.post(
"/api/support/send",
authMiddleware,
async(req,res)=>{

try{

const {message}=req.body;

if(!message){

return res.status(400).json({
ok:false
});

}

await pool.query(
`
INSERT INTO support_messages
(
user_id,
message,
sender
)
VALUES
($1,$2,'user')
`,
[
req.user.id,
message
]
);

res.json({
ok:true
});

}catch(e){

console.error(
"SUPPORT SEND ERROR:",
e
);

res.status(500).json({
ok:false
});

}

});

// оператор отвечает
app.post(
"/api/support/reply",
authMiddleware,
requireAdmin,
async(req,res)=>{

try{

const {
userId,
message
}=req.body;

if(
!userId||
!message
){

return res.status(400).json({
ok:false
});

}

await pool.query(
`
INSERT INTO support_messages
(
user_id,
message,
sender
)
VALUES
($1,$2,'operator')
`,
[
userId,
message
]
);

res.json({
ok:true
});

}catch(e){

console.error(
"SUPPORT REPLY ERROR:",
e
);

res.status(500).json({
ok:false
});

}

});

// ======================================================
// 🤖 AI ASSISTANT
// ======================================================

    const upload = multer({
      storage: multer.memoryStorage()
    });

    const GENERATOR_CAPABILITIES = {
  models: [
    "gemini-2.5-flash-image",
    "gemini-3-pro-image-preview"
  ],

  aspectRatios: [
    "1:1",
    "3:4",
    "4:3",
    "9:16",
    "16:9"
  ],

  imageSizes: [
    "1024",
    "1536",
    "2048"
  ],

  maxImages: 4,

  features: [
    "text_to_image",
    "image_to_image",
    "image_editing",
    "multiple_images",
    "style_transfer",
    "character_consistency",
    "multimodal_prompts"
  ]
};

    const SYSTEM_PROMPT = `
You are an AI assistant inside the dizAIn image and video generation platform.

ASSISTANT ROLE

Your name is dizAIn AI.

You help users:

— create high quality prompts for real AI models used in the platform
— improve prompts
— explain styles
— analyze images
— suggest prompt improvements
— help understand generation tools
— communicate like a friendly human assistant

You generate prompts optimized for the platform models.

LANGUAGE RULES

Primary language: Russian
Secondary language: English

If user writes in Russian — answer in Russian.
If user writes in English — answer in English.

ASSISTANT BEHAVIOR

Answer briefly and clearly.

Do not write long explanations unless the user asks.

If user asks for a prompt — immediately provide a ready prompt.

Do not introduce yourself in every message.

Do not greet in every message.

Write like a normal human, friendly tone, emojis allowed.

PROMPT FORMAT

If user asks for a prompt respond exactly like this:

Prompt:
<generated prompt>

MODEL DISCLOSURE RULE

If user asks what models are used respond:

"Собственные генеративные модели ИИ"

RESTRICTIONS

Do not invent platform features.

Do not invent settings.

If unsure say you are not sure.

Do not repeat your role every message.

Do not write unnecessary text.

Stay professional and polite.

PLATFORM CONTEXT

The dizAIn platform allows users to:

— generate images
— generate video
— edit images
— use prompt cards
— create custom generations

IMAGE GENERATION CAPABILITIES

Text → Image

Image → Image editing

Image Editing:
object editing
background change
style change
inpainting

Multiple image references

Style transfer

Character consistency

Aspect ratio:
1:1
3:4
4:3
9:16
16:9

Image sizes:
1024
1536
2048

Multimodal prompts (text + images)

Scene understanding:
lighting
composition
camera
depth
style

IMAGE ANALYSIS

You can:

describe images
detect style
detect composition
detect objects
detect atmosphere
convert image → prompt
improve prompts
generate prompt variations
generate image ideas

VIDEO GENERATION CAPABILITIES

Text → Video

Image → Video

Frame animation

Camera motion:
pan
zoom
tilt
orbit
dolly
tracking shot

Character motion

Physics simulation

Character consistency

Style control:
cinematic
anime
realistic
3D
cartoon
fantasy
sci-fi

Lighting control

Scene composition

Object interaction

Environment animation:
water
wind
clouds
fire

Facial animation

Cinematic shots:
wide shot
close-up
medium shot
drone shot

Depth understanding

Motion consistency

Loop video

HD video generation

Weather effects:
rain
snow
fog
wind

Cinematic effects:
depth of field
motion blur
lens flare
film grain

Animation styles:
Pixar style
anime
3D animation
cartoon

Complex scenes
dynamic scenes
creative scenes
`;

// история сообщений
app.get("/api/assistant/history", authMiddleware, async (req, res) => {

  try {

    const userId = req.user.id;

    const result = await pool.query(
      `
      SELECT role, content, created_at
      FROM assistant_messages
      WHERE user_id = $1
      ORDER BY created_at ASC
      LIMIT 30
      `,
      [userId]
    );

    res.json({
      ok: true,
      messages: result.rows
    });

  } catch (e) {

    console.error("ASSISTANT HISTORY ERROR:", e);

    res.status(500).json({
      ok: false
    });

  }

});


// отправка сообщения ассистенту
app.post("/api/assistant", authMiddleware, upload.array("images",3), async (req, res) => {

  try {

    const { message } = req.body;
    const userId = req.user.id;

    const parts = [];

parts.push({
  text: message
});

if(req.files){

  req.files.forEach(file => {

    parts.push({
      inlineData:{
        mimeType:file.mimetype,
        data:file.buffer.toString("base64")
      }
    });

  });

}

    if (!message) {
      return res.status(400).json({
        ok: false,
        error: "message required"
      });
    }

    const user = await pool.query(
  "SELECT admin_subscription FROM users WHERE id = $1",
  [userId]
);

const isAdmin = req.user.role === "admin" || user.rows[0]?.admin_subscription;

    // ===============================
    // 🔒 ПРОВЕРКА ПОДПИСКИ
    // ===============================
    if (!isAdmin) {

      const sub = await pool.query(
        "SELECT expires_at FROM subscriptions WHERE user_id = $1",
        [userId]
      );

      if (!sub.rows.length || new Date(sub.rows[0].expires_at) < new Date()) {
        return res.status(403).json({
          ok: false,
          error: "subscription_required"
        });
      }

    }

    // сохраняем сообщение пользователя
    await pool.query(
      `
      INSERT INTO assistant_messages (user_id, role, content)
      VALUES ($1, 'user', $2)
      `,
      [userId, message]
    );

    // ===============================
// 🤖 ЗАПРОС В GEMINI
// ===============================

// ===============================
// 🧠 ЗАГРУЖАЕМ КОНТЕКСТ ДИАЛОГА
// ===============================
const historyResult = await pool.query(
`
SELECT role, content
FROM assistant_messages
WHERE user_id = $1
ORDER BY created_at DESC
LIMIT 9
`,
[userId]
);

const historyMessages = historyResult.rows.reverse();

res.setHeader("Content-Type", "text/event-stream");
res.setHeader("Cache-Control", "no-cache");
res.setHeader("Connection", "keep-alive");

res.flushHeaders();

let reply = "";

const stream = await ai.models.generateContentStream({
  model: "gemini-2.5-flash",

  config: {
    systemInstruction: `
${SYSTEM_PROMPT}

REAL GENERATOR SETTINGS

The platform uses these real generator settings:

Models:
${GENERATOR_CAPABILITIES.models.join(", ")}

Aspect Ratios:
${GENERATOR_CAPABILITIES.aspectRatios.join(", ")}

Image Sizes:
${GENERATOR_CAPABILITIES.imageSizes.join(", ")}

Maximum images per request:
${GENERATOR_CAPABILITIES.maxImages}
`,
    temperature: 0.7,
    maxOutputTokens: 1000
  },

  contents: [

    ...historyMessages.map(m => ({
      role: m.role === "assistant" ? "model" : "user",
      parts: [{ text: m.content }]
    })),

    {
      role: "user",
      parts: [
        { text: message },
        ...parts.slice(1)
      ]
    }

  ]
});

for await (const chunk of stream) {

  const text =
    chunk?.candidates?.[0]?.content?.parts?.[0]?.text || "";

  if (text) {

    reply += text;

    res.write(`data: ${JSON.stringify({ token: text })}\n\n`);

  }

}

res.write(`data: [DONE]\n\n`);

// ===============================
// 💾 СОХРАНЯЕМ ОТВЕТ АССИСТЕНТА
// ===============================
await pool.query(
`
INSERT INTO assistant_messages (user_id, role, content)
VALUES ($1, 'assistant', $2)
`,
[userId, reply]
);

// ===============================
// 🧹 ОЧИСТКА СТАРЫХ СООБЩЕНИЙ (оставляем 30)
// ===============================
await pool.query(
`
DELETE FROM assistant_messages
WHERE id IN (
  SELECT id FROM assistant_messages
  WHERE user_id = $1
  ORDER BY created_at DESC
  OFFSET 30
)
`,
[userId]
);

res.end();

} catch (e) {

console.error("ASSISTANT ERROR:", e);

if (!res.headersSent) {
  res.status(500).json({
    ok: false
  });
}

}
});

// ======================================================
// IMAGE UPLOAD (PROMPT CARD)
// ======================================================

app.post("/api/upload-image", authMiddleware, async (req, res) => {
  try {

    const { image } = req.body;

    if (!image) {
      return res.status(400).json({
        ok: false,
        error: "image required"
      });
    }

    // убираем data:image/...;base64
    const base64 = image.replace(/^data:.*;base64,/, "");

    const buffer = Buffer.from(base64, "base64");

    // 🔥 конвертируем в WEBP
    const webpBuffer = await sharp(buffer)
      .webp({ quality: 85 })
      .toBuffer();

    // 🔥 загружаем в R2
    const imageUrl = await uploadToR2(webpBuffer);

    return res.json({
      ok: true,
      url: imageUrl
    });

  } catch (e) {

    console.error("UPLOAD IMAGE ERROR:", e);

    res.status(500).json({
      ok: false,
      error: "upload failed"
    });

  }
});

// =========================
// 🖼 ЗАГРУЗКА АВАТАРА R2
// =========================
app.post("/api/user/upload-avatar", authMiddleware, upload.single("file"), async (req, res) => {
  try {
    const file = req.file;

    const userRes = await pool.query(
      "SELECT avatar_url FROM users WHERE id = $1",
      [req.user.id]
    );

    const oldAvatar = userRes.rows[0]?.avatar_url;

    if (!file) {
      return res.status(400).json({ ok: false, error: "no file" });
    }

    // 🔥 конвертация + адаптивное сжатие
    const webp = await sharp(file.buffer)
      .resize({
        width: 1024,
        height: 1024,
        fit: "inside",              // сохраняет пропорции
        withoutEnlargement: true    // не увеличивает маленькие
      })
      .webp({ quality: 85 })
      .toBuffer();

    // 🔥 удаляем старый аватар
    if (oldAvatar) {
      try {

        const key = new URL(oldAvatar).pathname.slice(1);

        const s3 = new S3Client({
          region: "auto",
          endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
          credentials: {
            accessKeyId: process.env.R2_ACCESS_KEY,
            secretAccessKey: process.env.R2_SECRET_KEY,
          },
        });

        await s3.send(
          new DeleteObjectCommand({
            Bucket: process.env.R2_BUCKET,
            Key: key,
          })
        );

        console.log("OLD AVATAR DELETED:", key);

      } catch (err) {
        console.error("DELETE OLD AVATAR ERROR:", err);
      }
    }

    // 🔥 загрузка в R2
    const url = await uploadToR2(webp, "avatars");

    // 🔥 сохраняем в БД
    await pool.query(
      "UPDATE users SET avatar_url = $1 WHERE id = $2",
      [url, req.user.id]
    );

    return res.json({
      ok: true,
      url,
    });

  } catch (e) {
    console.error("UPLOAD AVATAR ERROR:", e);
    res.status(500).json({ ok: false });
  }
});

app.post("/api/user/update-profile", authMiddleware, async (req, res) => {
  try {
    const { firstName, lastName } = req.body;

    await pool.query(
      `UPDATE users 
       SET first_name = $1, last_name = $2 
       WHERE id = $3`,
      [firstName || "", lastName || "", req.user.id]
    );

    res.json({ ok: true });

  } catch (e) {
    console.error("UPDATE PROFILE ERROR:", e);
    res.status(500).json({ ok: false });
  }
});

// ======================================================
// WORKSPACE SAVE
// ======================================================

app.post("/api/workspace/save", authMiddleware, async (req, res) => {
  try {

    const userId = req.user.id;
    const { data } = req.body;

    await pool.query(
      `
      INSERT INTO workspaces (user_id, data)
      VALUES ($1, $2)
      ON CONFLICT (user_id)
      DO UPDATE SET
        data = EXCLUDED.data,
        updated_at = NOW()
      `,
      [userId, data]
    );

    res.json({ ok: true });

  } catch (e) {

    console.error("WORKSPACE SAVE ERROR:", e);

    res.status(500).json({ ok: false });

  }
});

// ======================================================
// WORKSPACE LOAD
// ======================================================
app.get("/api/workspace/load", authMiddleware, async (req, res) => {
  try {

    const userId = req.user.id;

    const result = await pool.query(
      `SELECT data FROM workspaces WHERE user_id = $1`,
      [userId]
    );

    res.json({
      ok: true,
      data: result.rows[0]?.data || null
    });

  } catch (e) {
    console.error("WORKSPACE LOAD ERROR:", e);
    res.status(500).json({ ok: false });
  }
});

// ======================================================
// 🖼 USER GENERATIONS HISTORY
// ======================================================
app.get("/api/user/generations", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;

    const result = await pool.query(
      `
      SELECT *
      FROM (
        (
          SELECT id, prompt, image_url, video_url, created_at
          FROM generations
          WHERE user_id = $1
          AND image_url IS NOT NULL
          ORDER BY created_at DESC
          LIMIT 150
       )

        UNION ALL

       (
          SELECT id, prompt, image_url, video_url, created_at
          FROM generations
          WHERE user_id = $1
          AND video_url IS NOT NULL
          ORDER BY created_at DESC
          LIMIT 50
        )
      ) t
      ORDER BY created_at DESC
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

// ===============================
// ❤️ LIKE GENERATION
// ===============================
app.post("/api/generation/like", authMiddleware, async (req, res) => {
  try {

    const { id } = req.body;

    if (!id) {
      return res.status(400).json({
        ok: false,
        error: "generation id required"
      });
    }

    await pool.query(
      `
      UPDATE generations
      SET liked = true
      WHERE id = $1 AND user_id = $2
      `,
      [id, req.user.id]
    );

    res.json({ ok: true });

  } catch (e) {

    console.error("LIKE ERROR:", e);

    res.status(500).json({
      ok: false,
      error: "like failed"
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

let spentCost = 0;

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
    const { id, role } = req.user;

    const user = await pool.query(
  "SELECT admin_subscription FROM users WHERE id = $1",
  [id]
);

const isAdmin = role === "admin" || user.rows[0]?.admin_subscription;

// ===============================
// 🔒 проверка подписки
// ===============================
if (!isAdmin) {

  const sub = await pool.query(
    "SELECT expires_at FROM subscriptions WHERE user_id = $1",
    [id]
  );

  if (!sub.rows.length || new Date(sub.rows[0].expires_at) < new Date()) {
    return res.status(403).json({
      ok: false,
      message: "Подписка закончилась"
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

// ===============================
// 💰 TOKEN COST CALCULATION
// ===============================

let cost = 4.5; // Flash

if (modelName === "gemini-3-pro-image-preview") {

  if (imageSize === "1K") cost = 6;
  if (imageSize === "2K") cost = 6.5;
  if (imageSize === "4K") cost = 7;

}

// ======================================
// 🔐 ПРОВЕРКА ПРАВ + АТОМАРНОЕ СПИСАНИЕ
// ======================================
if (!isAdmin) {

  const debit = await pool.query(
`
UPDATE users
SET tokens = tokens - $2
WHERE id = $1 AND tokens >= $2
RETURNING tokens
`,
[id, cost]
);

  if (debit.rowCount === 0) {
    return res.status(403).json({
      error: "no_tokens",
      message: "Токены закончились"
    });
  }

  // запоминаем сколько списали
  spentCost = cost;

  // лог списания
  await pool.query(
    `INSERT INTO token_logs (user_id, change, reason)
     VALUES ($1, $2, 'generation')`,
    [id, -cost]
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

// 🔵 FLASH 2.5 — simpler sizing
if (finalModel === "gemini-2.5-flash-image") {

  temperature = 0.9;
  outputMimeType = "image/png";

  // базовый размер меньше для стабильности
  finalWidth = 1024;
  finalHeight = 1024;

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

    for (const img of peopleImages) {

  const base64 = await normalizeImageToBase64(img);
  if (!base64) continue;

  parts.push({
    inlineData: {
      data: base64,
      mimeType: "image/png"
    }
  });

}

    parts.push({
      text: "Preserve identity, facial structure, eyes, nose, mouth, proportions and skin tone of provided people images."
    });

 // ===============================
 // 🔒 CHARACTER CONSISTENCY LOCK
 // ===============================

  parts.push({
    text: `
CRITICAL IDENTITY LOCK:

The provided people images define a specific person.

You must preserve:
- face structure
- identity
- eyes
- nose
- lips
- skin tone
- proportions

The person must remain the SAME across all generated scenes.

Do not invent a new person.
`
  });

}

  // 🏞 OBJECT IMAGES (фон / одежда)
  if (Array.isArray(objectImages) && objectImages.length > 0) {

    for (const img of objectImages) {

  const base64 = await normalizeImageToBase64(img);
  if (!base64) continue;

  parts.push({
    inlineData: {
      data: base64,
      mimeType: "image/png"
    }
  });

}

    parts.push({
      text: "Use object images as editable environment or clothing reference."
    });
  }

  // 🟣 FALLBACK — если нет people/object, но есть обычные images
if (
  (!peopleImages || peopleImages.length === 0) &&
  (!objectImages || objectImages.length === 0)
) {

  let fallbackImages = [];

  if (Array.isArray(images) && images.length > 0) {
    fallbackImages = images;
  } else if (image && typeof image === "string") {
    fallbackImages = [image];
  }

  for (const img of fallbackImages) {

  const base64 = await normalizeImageToBase64(img);
  if (!base64) continue;

  parts.push({
    inlineData: {
      data: base64,
      mimeType: "image/png"
    }
  });

}

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

  for (const img of orderedImages) {

  const base64 = await normalizeImageToBase64(img);
  if (!base64) continue;

  parts.push({
    inlineData: {
      data: base64,
      mimeType: "image/png"
    }
  });

  }

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

IMPORTANT:
- Change aspect ratio if necessary.
- Expand or crop image naturally to match new canvas size.
- Preserve identity if faces are provided.
- Apply only requested modifications.

User instruction:
${prompt}

Enhance facial realism, skin texture, natural eyes, micro skin detail and photographic lighting.
`;

} else {

  finalPrompt = `
Generate an ultra realistic professional photograph.

Use natural lighting, cinematic composition, realistic shadows and depth.

Camera simulation:
full-frame camera, 50mm lens, f/1.8 aperture, HDR, global illumination.

${prompt}
`;

}

// ===============================
// 🧠 MULTI IMAGE COMPOSITION HINT
// ===============================

if (peopleImages?.length && objectImages?.length) {

  parts.push({
    text: `
You are composing a scene using multiple visual references.

Rules:
- People images define the identity and must remain unchanged.
- Object images define environment, clothing or items.
- Combine them naturally into one coherent scene.
- Maintain realism, lighting consistency and proportions.
`
  });

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

  // ===============================
// 🖼 OFFICIAL IMAGE CONFIG (PRO ONLY)
// ===============================

let imageConfigBlock = {};

if (finalModel === "gemini-3-pro-image-preview") {

  imageConfigBlock = {
    aspectRatio: aspectRatio || "1:1",
    imageSize: imageSize || "1K"
  };

} else {

  // Flash остаётся через aspectRatio
  imageConfigBlock = {
    aspectRatio: aspectRatio || "1:1"
  };

}

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
    imageConfig: imageConfigBlock
  },
  timeout: 120000 // увеличенный timeout для PRO/4K
});

  const candidate = response?.candidates?.[0];
  const contentParts = candidate?.content?.parts || [];

  const imagePart = contentParts.find(p => p.inlineData?.data);

  if (!imagePart) {
  console.error("⚠ Gemini returned no IMAGE modality");
  console.error(JSON.stringify(response, null, 2));

  return res.status(502).json({
    error: "model_no_image",
    message: "Модель на обновлении. Попробуйте позже"
  });
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

  const buffer = Buffer.from(imageBase64, "base64");

  const webpBuffer = await sharp(buffer)
    .webp({ quality: 85 })
    .toBuffer();

  const imageUrl = await uploadToR2(webpBuffer);

  const result = await pool.query(
  `INSERT INTO generations (user_id, prompt, image_url)
   VALUES ($1, $2, $3)
   RETURNING id`,
  [id, prompt, imageUrl]
);

  return res.json({
    ok: true,
    image: imageUrl,
    id: result.rows[0].id
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

    // ===============================
    // 🔄 TOKEN REFUND
    // ===============================
  if (spentCost > 0 && !isAdmin) {

    try {

      await pool.query(
        `UPDATE users SET tokens = tokens + $1 WHERE id = $2`,
        [spentCost, req.user.id]
      );

      await pool.query(
        `INSERT INTO token_logs (user_id, change, reason)
         VALUES ($1, $2, 'generation_refund')`,
        [req.user.id, spentCost]
      );

      console.log("🔄 tokens refunded:", spentCost);

    } catch (refundErr) {

      console.error("TOKEN REFUND ERROR:", refundErr);

    }

  }

  if (err.name === "AbortError") {
    return res.status(504).json({ error: "Gemini timeout" });
  }

  res.status(500).json({
  error: "generation_failed",
  message: "Модель на обновлении. Попробуйте позже"
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

app.get("/api/download/:id", authMiddleware, async (req, res) => {
  try {

    const { id } = req.params;

    const result = await pool.query(
      `SELECT image_url FROM generations WHERE id = $1`,
      [id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "image not found" });
    }

    const imageUrl = result.rows[0].image_url;

    const key = imageUrl.split(".r2.dev/")[1];

    const s3 = new S3Client({
      region: "auto",
      endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
      credentials: {
        accessKeyId: process.env.R2_ACCESS_KEY,
        secretAccessKey: process.env.R2_SECRET_KEY,
      },
    });

    const object = await s3.send(
      new GetObjectCommand({
        Bucket: process.env.R2_BUCKET,
        Key: key
      })
    );

    const chunks = [];
    for await (const chunk of object.Body) {
      chunks.push(chunk);
    }

    const buffer = Buffer.concat(chunks);

    const png = await sharp(buffer)
      .png()
      .toBuffer();

    res.setHeader("Content-Type", "image/png");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="dizain.png"`
    );

    res.send(png);

  } catch (e) {
    console.error("DOWNLOAD ERROR", e);
    res.status(500).json({ error: "download failed" });
  }
});

// ======================================================
// 🎬 VIDEO GENERATION (KLING)
// ======================================================

app.post("/api/generate-video", authMiddleware, async (req, res) => {

  let spentCost = 0;

  try {

    const { prompt, image, model, duration } = req.body;

    const { id, role } = req.user;

    const user = await pool.query(
  "SELECT admin_subscription FROM users WHERE id = $1",
  [id]
);

const isAdmin = role === "admin" || user.rows[0]?.admin_subscription;

    // ===============================
    // 🔒 SUBSCRIPTION CHECK
    // ===============================
    if (!isAdmin) {

      const sub = await pool.query(
        "SELECT expires_at FROM subscriptions WHERE user_id = $1",
        [id]
      );

      if (!sub.rows.length || new Date(sub.rows[0].expires_at) < new Date()) {
        return res.status(403).json({
          ok: false,
          message: "Подписка закончилась"
        });
      }

    }

    // ===============================
    // 💰 TOKEN COST (VIDEO)
    // ===============================

    let cost = 60; // Flash 2.1

    if (model === "kwaivgi/kling-v2.6") cost = 90;
    if (model === "kwaivgi/kling-v3-omni-video") cost = 120;
    if (model === "kwaivgi/kling-v3-motion-control") cost = 120;

    if (!isAdmin) {

      const debit = await pool.query(
        `
        UPDATE users
        SET tokens = tokens - $2
        WHERE id = $1 AND tokens >= $2
        RETURNING tokens
        `,
        [id, cost]
      );

      if (debit.rowCount === 0) {

        return res.status(403).json({
          error: "no_tokens",
          message: "Токены закончились"
        });

      }

      spentCost = cost;

    }

    // ===============================
    // NORMALIZE IMAGE
    // ===============================

    let startImage = null;

    if (image) {

      if (typeof image === "string" && image.startsWith("data:")) {

        const base64 = image.replace(/^data:.*;base64,/, "");
        const buffer = Buffer.from(base64, "base64");

        const url = await uploadToR2(buffer);

        startImage = url;

      }

      else if (typeof image === "string" && image.startsWith("http")) {

        startImage = image;

      }

    }

    // ===============================
    // MODEL SELECT
    // ===============================

    const klingModel = model || KLING_MODELS.flash;

    const input = {
     prompt,
     duration: duration || 5
    };
  
    if (startImage) {
      input.start_image = startImage;
    }

    // ===============================
    // GENERATION
    // ===============================

    const prediction = await replicate.predictions.create({
  model: klingModel,
  input
});

return res.json({
  ok: true,
  prediction_id: prediction.id
});

  }

  catch (err) {

    console.error("KLING ERROR:", err);

    if (spentCost > 0 && req.user?.role !== "admin") {

      await pool.query(
        `UPDATE users SET tokens = tokens + $1 WHERE id = $2`,
        [spentCost, req.user.id]
      );

    }

    res.status(500).json({
     ok: false,
     error: "generation_failed",
     message: "Модель на обновлении. Попробуйте позже"
   });

  }

});

// ======================================================
// 🎬 VIDEO STATUS CHECK
// ======================================================

app.get("/api/video-status/:id", authMiddleware, async (req, res) => {

  try {

    const id = req.params.id;

    // если уже загружали видео — отдаём сразу
    if (videoCache.has(id)) {
      return res.json({
        ok: true,
        status: "done",
        video: videoCache.get(id)
      });
    }

    const prediction = await replicate.predictions.get(id);

    if (prediction.status === "succeeded") {

      let videoUrl = prediction.output;

if (Array.isArray(videoUrl)) {
  videoUrl = videoUrl[0];
}

if (typeof videoUrl === "object" && videoUrl?.video) {
  videoUrl = videoUrl.video;
}

      // скачиваем видео
      const response = await fetch(videoUrl);

if (!response.ok) {
  throw new Error("Video download failed from replicate");
}

const arrayBuffer = await response.arrayBuffer();

if (!arrayBuffer || arrayBuffer.byteLength < 1000) {
  throw new Error("Video file is empty");
}

const buffer = Buffer.from(arrayBuffer);

      // создаём R2 клиент
const s3 = new S3Client({
  region: "auto",
  endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: process.env.R2_ACCESS_KEY,
    secretAccessKey: process.env.R2_SECRET_KEY
  }
});

// загружаем в R2 как mp4
const key = `videos/${crypto.randomUUID()}.mp4`;

await s3.send(
  new PutObjectCommand({
    Bucket: process.env.R2_BUCKET,
    Key: key,
    Body: buffer,
    ContentType: "video/mp4"
  })
);

// получаем имя файла
const videoKey = key.split("videos/")[1];

// 🔥 получаем userId
const userId = req.user.id;

// 🔥 ВАЖНО: prompt надо передать
const prompt = req.body.prompt || "video generation";

// 🔥 сохраняем в БД
await pool.query(
  `
  INSERT INTO generations (user_id, prompt, video_url)
  VALUES ($1, $2, $3)
  `,
  [
    userId,
    prompt,
    `https://ai-backend-bd2h.onrender.com/api/download-video/${videoKey}`
  ]
);

// кэш
videoCache.set(id, videoKey);

return res.json({
  ok: true,
  status: "done",
  video: `https://ai-backend-bd2h.onrender.com/api/download-video/${videoKey}`
});

    }

    return res.json({
      ok: true,
      status: prediction.status
    });

  } catch (e) {

    console.error("VIDEO STATUS ERROR:", e);

    res.status(500).json({
      ok: false
    });

  }

});

// ======================================================
// 🎬 VIDEO DOWNLOAD (R2 → USER)
// ======================================================

app.get("/api/download-video/:key", async (req, res) => {

  try {

    const { key } = req.params;

    const s3 = new S3Client({
      region: "auto",
      endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
      credentials: {
        accessKeyId: process.env.R2_ACCESS_KEY,
        secretAccessKey: process.env.R2_SECRET_KEY
      }
    });

    const object = await s3.send(
      new GetObjectCommand({
        Bucket: process.env.R2_BUCKET,
        Key: `videos/${key}`
      })
    );

    const chunks = [];

    for await (const chunk of object.Body) {
      chunks.push(chunk);
    }

    const buffer = Buffer.concat(chunks);

    res.setHeader("Content-Type", "video/mp4");
    res.setHeader(
      "Content-Disposition",
      'attachment; filename="video.mp4"'
    );

    res.send(buffer);

  } catch (e) {

    console.error("VIDEO DOWNLOAD ERROR:", e);

    res.status(500).json({
      ok: false
    });

  }

});

// ======================================
// AUTO CLEANUP OLD GENERATIONS (30 days)
// ======================================

async function cleanupOldGenerations() {
  try {

    const result = await pool.query(`
      DELETE FROM generations
      WHERE liked = false
      AND created_at < NOW() - interval '30 days'
      RETURNING image_url, video_url
    `);

    if (!result.rows.length) {
      console.log("🧹 cleanup: nothing to delete");
      return;
    }

    const s3 = new S3Client({
      region: "auto",
      endpoint: process.env.R2_ENDPOINT,
      credentials: {
        accessKeyId: process.env.R2_ACCESS_KEY,
        secretAccessKey: process.env.R2_SECRET_KEY,
      },
    });

    for (const row of result.rows) {

  const urls = [row.image_url, row.video_url].filter(Boolean);

  for (const url of urls) {

    let key;

    if (url.includes("/api/download-video/")) {
      key = "videos/" + url.split("/api/download-video/")[1];
    } else {
      const parts = url.split(".r2.dev/");
      if (parts.length < 2) continue;
      key = parts[1];
    }

    await s3.send(
      new DeleteObjectCommand({
        Bucket: process.env.R2_BUCKET,
        Key: key
      })
    );

  }

}

console.log("🧹 deleted generations:", result.rows.length);

  } catch (err) {
    console.error("CLEANUP ERROR:", err);
  }
}

setInterval(cleanupOldGenerations, 24 * 60 * 60 * 1000);

// ======================================
// AUTO VERIFY EMAIL REMINDERS
// ======================================

async function sendVerificationReminders() {

  try {

    const result = await pool.query(`
      SELECT
        id,
        email,
        email_verify_token,
        verification_reminders_sent,
        created_at
      FROM users
      WHERE email_verified = false
    `);

    for (const user of result.rows) {

      const createdAt = new Date(user.created_at).getTime();

      const hoursPassed =
        (Date.now() - createdAt) / (1000 * 60 * 60);

      // ===============================
      // reminder #1 after 6h
      // ===============================
      if (
        user.verification_reminders_sent === 0 &&
        hoursPassed >= 6
      ) {

        await sendMail({
          to: user.email,
         subject: "Подтверждение почты — ДизАiн",
          html: verifyEmailTemplate(
          `https://dizain.pro/api/auth/verify-email?token=${user.email_verify_token}`,
          user.email
        )
        });

        await pool.query(
          `
          UPDATE users
          SET verification_reminders_sent = 1
          WHERE id = $1
          `,
          [user.id]
        );

        console.log("📧 reminder #1:", user.email);

      }

      // ===============================
      // reminder #2 after 18h
      // ===============================
      else if (
        user.verification_reminders_sent === 1 &&
        hoursPassed >= 18
      ) {

        await sendMail({
          to: user.email,
          subject: "Подтверждение почты — ДизАiн",
          html: verifyEmailTemplate(
          `https://dizain.pro/api/auth/verify-email?token=${user.email_verify_token}`,
          user.email
        )
        });

        await pool.query(
          `
          UPDATE users
          SET verification_reminders_sent = 2
          WHERE id = $1
          `,
          [user.id]
        );

        console.log("📧 reminder #2:", user.email);

      }

    }

  } catch (e) {

    console.error("VERIFY REMINDER ERROR:", e);

  }

}

// ======================================
// AUTO DELETE UNVERIFIED USERS (24h)
// ======================================

async function cleanupUnverifiedUsers() {

  try {

    const result = await pool.query(`
      SELECT id
      FROM users
      WHERE
        email_verified = false
        AND created_at < NOW() - interval '24 hours'
    `);

    if (!result.rows.length) {
      console.log("🧹 no unverified users to delete");
      return;
    }

    for (const row of result.rows) {

      try {

        await deleteUserWithCleanup(row.id);

        console.log("🧹 deleted unverified user:", row.id);

      } catch (e) {

        console.error("DELETE UNVERIFIED USER ERROR:", e);

      }

    }

  } catch (e) {

    console.error("UNVERIFIED CLEANUP ERROR:", e);

  }

}

setInterval(
  cleanupUnverifiedUsers,
  60 * 60 * 1000 // раз в час
);

setInterval(
  sendVerificationReminders,
  60 * 60 * 1000
);

// ==================
// START SERVER
// ==================
app.listen(PORT, () => {
  console.log(`🚀 AI backend running on port ${PORT}`);
});

app.get("/api/debug/users", authMiddleware, requireAdmin, async (req, res) => {
  try {

    const result = await pool.query(`
      SELECT
        u.id,
        u.email,
        u.role,
        u.tokens,
        u.email_verified,
        u.created_at,

        (
          SELECT COUNT(*)
          FROM generations g
          WHERE g.user_id = u.id
        ) AS generations_count

      FROM users u
      ORDER BY u.created_at DESC
    `);

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

// ======================================================
// ADMIN — ACTIVATE MONTH SUBSCRIPTION
// ======================================================

app.post("/api/admin/activate-month-subscription", authMiddleware, requireAdmin, async (req, res) => {
  try {

    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({ ok:false });
    }

    const expirationDate = new Date();
    expirationDate.setMonth(expirationDate.getMonth() + 1);

    await pool.query(
      `
      INSERT INTO subscriptions (user_id, expires_at)
      VALUES ($1,$2)
      ON CONFLICT (user_id)
      DO UPDATE SET expires_at = $2
      `,
      [userId, expirationDate]
    );

    res.json({ ok:true });

  } catch(e) {

    console.error("ADMIN SUB ERROR:",e);
    res.status(500).json({ ok:false });

  }
});

// ======================================================
// ADMIN — ADMIN SUBSCRIPTION (NO TOKEN LIMIT)
// ======================================================

app.post("/api/admin/set-admin-subscription", authMiddleware, requireAdmin, async (req, res) => {
  try {

    const { userId } = req.body;

    await pool.query(
      `
      UPDATE users
      SET admin_subscription = true
      WHERE id = $1
      `,
      [userId]
    );

    res.json({ ok: true });

  } catch (e) {

    console.error("ADMIN SUB ERROR:", e);

    res.status(500).json({ ok: false });

  }
});
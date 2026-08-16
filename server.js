import { GoogleGenAI } from "@google/genai";
import crypto from "crypto";
import { Pool } from "pg";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import fs from "fs";
import path from "path";
import express from "express";
import cors from "cors";
import axios from "axios";
import dotenv from "dotenv";
import { sendMail } from "./src/services/mailClient.js";
import { verifyEmailTemplate } from "./src/templates/emails/verifyEmailTemplate.js";
import { uploadToR2, uploadToR2WithKey, uploadPromptImageToR2, uploadPromptImagePreviewToR2, uploadVideoToR2WithKey, deleteFromR2ByKey, getObjectFromR2ByKey } from "./utils/uploadToR2.js";
import sharp from "sharp";
import Replicate from "replicate";
import deleteImageRoute from "./delete-image.js";
import multer from "multer";
import TelegramBot from "node-telegram-bot-api";

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
// TELEGRAM SUPPORT
// ===============================

const tgBot = new TelegramBot(
process.env.TELEGRAM_BOT_TOKEN,
{
polling:{
params:{
timeout:10
}
}
}
);

tgBot.on(
"polling_error",
(e)=>{

if(
e.message?.includes(
"409 Conflict"
)
){

console.log(
"TG: another active polling instance is using this bot token"
);

return;

}

console.error(
"TG POLLING:",
e.message
);

}
);

console.log(
"🤖 Telegram bot ready"
);

const TELEGRAM_ADMIN_ID=
process.env.TELEGRAM_ADMIN_ID;

let replyState={};

// ===============================
// TELEGRAM CALLBACKS
// ===============================

tgBot.on(
"callback_query",
async(query)=>{

try{

const data=
query.data||"";

const chatId=
query.message?.chat?.id;

if(!chatId)return;

if(
String(chatId)!==
String(
TELEGRAM_ADMIN_ID
)
){

await tgBot.answerCallbackQuery(
query.id,
{
text:"Нет доступа",
show_alert:true
}
);

return;

}

if(
data.startsWith(
"reply_"
)
){

const userId=
data.replace(
"reply_",
""
);

replyState[
chatId
]=userId;

await tgBot.sendMessage(
chatId,
"✍ Напишите ответ пользователю"
);

}

if(
data.startsWith(
"close_"
)
){

const userId=
data.replace(
"close_",
""
);

await pool.query(
`
UPDATE support_messages
SET is_closed=true
WHERE user_id=$1
`,
[
userId
]
);

await tgBot.sendMessage(
chatId,
"✅ Диалог закрыт"
);

}

await tgBot.answerCallbackQuery(
query.id
);

}catch(e){

console.error(
"TG CALLBACK ERROR:",
e
);

}

});

// ===============================
// TELEGRAM TEXT REPLY
// ===============================

tgBot.on(
"message",
async(msg)=>{

try{

const chatId=
msg.chat.id;

if(
String(chatId)!==
String(
TELEGRAM_ADMIN_ID
)
){
return;
}

const text=
msg.text||"";

if(!text)return;

if(
!replyState[
chatId
]
)
return;

const userId=
replyState[
chatId
];

await pool.query(
`
INSERT INTO support_messages
(
user_id,
message,
sender,
is_read
)
VALUES
(
$1,
$2,
'operator',
false
)
`,
[
userId,
text
]
);

await pool.query(
`
UPDATE support_messages
SET is_read=true
WHERE user_id=$1
AND sender='user'
AND is_closed=false
`,
[
userId
]
);

delete replyState[
chatId
];

await tgBot.sendMessage(
chatId,
"✅ Ответ отправлен"
);

}catch(e){

console.error(
"TG REPLY ERROR:",
e
);

}

});

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
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
  keepAlive: true,
  keepAliveInitialDelayMillis: 10000,
});

// проверка подключения
pool.on("error", (e) => {
  console.error("DB POOL IDLE CLIENT ERROR:", {
    message: e?.message,
    code: e?.code,
    errno: e?.errno,
    syscall: e?.syscall,
    stack: e?.stack,
  });
});

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

  const client = await pool.connect();
  const cleanupKeys = new Map();

try {

  await client.query("BEGIN");

  const user = await client.query(
    `SELECT avatar_url FROM users WHERE id = $1`,
    [userId]
  );

  if (!user.rows.length) {
    throw new Error("user_not_found");
  }

  const files = await client.query(
    `SELECT image_url, image_key, video_url, video_key FROM generations WHERE user_id = $1`,
    [userId]
  );

  for (const row of files.rows) {
    const imageKey = getGeneratedImageKey(row);

    if (row.image_url && !imageKey) {
      throw new Error("invalid_generated_image_key");
    }

    if (imageKey) {
      cleanupKeys.set(imageKey, "generated_image");
    }

    const videoKey = getGeneratedVideoKey(row.video_key) || getGeneratedVideoKey(row.video_url);

    if (row.video_url && !videoKey) {
      throw new Error("invalid_generated_video_key");
    }

    if (videoKey) {
      cleanupKeys.set(videoKey, "generated_video");
    }
  }

  const workspace = await client.query(
    `SELECT data FROM workspaces WHERE user_id = $1`,
    [userId]
  );

  for (const row of workspace.rows) {
    collectPromptCardCleanupKeys(row.data, userId, cleanupKeys);
  }

  const avatarKey = getAvatarKey(user.rows[0]?.avatar_url);

  if (user.rows[0]?.avatar_url && !avatarKey) {
    throw new Error("invalid_avatar_key");
  }

  if (avatarKey) {
    cleanupKeys.set(avatarKey, "avatar");
  }

  await enqueueR2CleanupKeys(client, cleanupKeys);

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

  if (cleanupKeys.size > 0) {
    void cleanupQueuedR2Objects([...cleanupKeys.keys()]).catch((e) => {
      console.error("R2 CLEANUP QUEUE IMMEDIATE ERROR:", e);
    });
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
      expires.setDate(expires.getDate() + 30);

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
  `
  SELECT
    id,
    email,
    avatar_url,
    first_name,
    last_name,
    onboarding_done
  FROM users
  WHERE id = $1
  `,
  [req.user.id]
);

    const user = result.rows[0];

    res.json({
      ok: true,
      id: user.id,
      email: user.email,
      avatar_url: user.avatar_url,
      first_name: user.first_name,
      last_name: user.last_name,
      onboarding_done: user.onboarding_done
    });

  } catch (e) {
    console.error("ME ERROR:", e);
    res.status(500).json({ ok: false });
  }
});

app.post("/api/user/onboarding-complete", authMiddleware, async (req, res) => {
  try {

    await pool.query(
      `
      UPDATE users
      SET onboarding_done = true
      WHERE id = $1
      `,
      [req.user.id]
    );

    res.json({
      ok: true
    });

  } catch (e) {

    console.error(
      "ONBOARDING COMPLETE ERROR:",
      e
    );

    res.status(500).json({
      ok: false
    });

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

let status="active";

if(result.rows.length===0){

const statusResult=await pool.query(
`
SELECT EXISTS (
  SELECT 1
  FROM support_messages
  WHERE user_id=$1
) AS has_any
`,
[req.user.id]
);

status=
statusResult.rows[0]?.has_any
?
"closed"
:
"new";

}

res.json({
ok:true,
status,
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

// статус непрочитанных ответов поддержки
app.get(
"/api/support/unread",
authMiddleware,
async(req,res)=>{

try{

const result=await pool.query(
`
SELECT EXISTS (
  SELECT 1
  FROM support_messages
  WHERE user_id = $1
  AND sender = 'operator'
  AND is_read = false
  AND is_closed = false
) AS unread
`,
[req.user.id]
);

res.json({
ok:true,
unread:result.rows[0]?.unread === true
});

}catch(e){

console.error(
"SUPPORT UNREAD ERROR:",
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

if(
!message?.trim()
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
($1,$2,'user')
`,
[
req.user.id,
message
]
);

const user=await pool.query(
`
SELECT email
FROM users
WHERE id=$1
`,
[
req.user.id
]
);

const email=
user.rows[0]?.email
||
"unknown";

try{

await tgBot.sendMessage(
TELEGRAM_ADMIN_ID,

`👤 ${email}

${message}`,

{
reply_markup:{
inline_keyboard:[
[
{
text:"✉ Ответить",
callback_data:
`reply_${req.user.id}`
},
{
text:"✅ Закрыть",
callback_data:
`close_${req.user.id}`
}
]
]
}
}
);

}catch(e){

console.error(
"TG SEND ERROR:",
e
);

}

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

// список статусов поддержки для админки
app.get(
"/api/admin/support-status",
authMiddleware,
requireAdmin,
async(req,res)=>{

try{

const result=
await pool.query(
`

SELECT

user_id,

COUNT(*)
FILTER(
WHERE
sender='user'
AND is_read=false
AND is_closed=false
) as unread,

CASE

WHEN COUNT(*)
FILTER(
WHERE
sender='user'
AND is_read=false
AND is_closed=false
)>0

THEN 'new'

WHEN COUNT(*)
FILTER(
WHERE
sender='operator'
AND is_closed=false
)>0

THEN 'answered'

ELSE 'closed'

END as status

FROM support_messages

GROUP BY user_id

`
);

res.json({

ok:true,

items:result.rows

});

}catch(e){

console.error(
"SUPPORT STATUS ERROR:",
e
);

res.status(500).json({
ok:false
});

}

});

// пользователь открыл поддержку → пометить ответы прочитанными
app.post(
"/api/support/read",
authMiddleware,
async(req,res)=>{

try{

await pool.query(
`
UPDATE support_messages
SET is_read=true
WHERE user_id=$1
AND sender='operator'
AND is_closed=false
`,
[
req.user.id
]
);

res.json({
ok:true
});

}catch(e){

console.error(
"SUPPORT READ ERROR:",
e
);

res.status(500).json({
ok:false
});

}

});

// ========================================
// 🧹 AUTO CLEAN SUPPORT
// ========================================

setInterval(
async()=>{

try{

await pool.query(
`

DELETE
FROM support_messages

WHERE
is_closed=true

AND created_at
<
NOW()
-
INTERVAL '30 days'

`
);

console.log(
"🧹 support cleaned"
);

}catch(e){

console.error(
"SUPPORT CLEAN ERROR:",
e
);

}

},
1000
*
60
*
60
*
24
);

// история конкретного пользователя для админа
app.get(
"/api/admin/support-history/:id",
authMiddleware,
requireAdmin,
async(req,res)=>{

try{

const result=
await pool.query(
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
[
req.params.id
]
);

res.json({
ok:true,
messages:
result.rows
});

}catch(e){

console.error(
"ADMIN SUPPORT HISTORY ERROR:",
e
);

res.status(500).json({
ok:false
});

}

});

// ответ оператора
app.post(
"/api/admin/support-reply",
authMiddleware,
requireAdmin,
async(req,res)=>{

try{

const{
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
sender,
is_read
)
VALUES
(
$1,
$2,
'operator',
false
)
`,
[
userId,
message
]
);

await pool.query(
`
UPDATE support_messages
SET is_read=true
WHERE user_id=$1
AND sender='user'
AND is_closed=false
`,
[userId]
);

res.json({
ok:true
});

}catch(e){

console.error(
"ADMIN REPLY ERROR:",
e
);

res.status(500).json({
ok:false
});

}

});

// закрытие диалога
app.post(
"/api/admin/support-close",
authMiddleware,
requireAdmin,
async(req,res)=>{

try{

const{
userId
}=req.body;

await pool.query(
`
UPDATE support_messages
SET is_closed=true
WHERE user_id=$1
`,
[
userId
]
);

res.json({
ok:true
});

}catch(e){

console.error(
"CLOSE CHAT ERROR:",
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

    const promptImageUpload = multer({
      storage: multer.memoryStorage(),
      limits: {
        fileSize: 2 * 1024 * 1024
      }
    });

    function uploadPromptImageFile(req, res, next) {
      promptImageUpload.single("file")(req, res, (err) => {
        if (!err) {
          next();
          return;
        }

        if (err.code === "LIMIT_FILE_SIZE") {
          res.status(413).json({
            ok: false,
            error: "file_too_large"
          });
          return;
        }

        res.status(400).json({
          ok: false,
          error: "upload parse failed"
        });
      });
    }

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

DIALOGUE CONTEXT AND CONTINUATION RULES:

Treat the conversation history supplied with the current request as the active dialogue context. Interpret short or incomplete user messages in relation to the preceding conversation instead of treating them as isolated requests.

If the user says “continue”, “go on”, “yes”, “next”, “keep going”, or uses an equivalent short confirmation, continue the previous task from the first unfinished scene, section, step, prompt, code block, list item, or numbered item.

Do not restart the task, repeat completed material, or change the established characters, style, format, terminology, constraints, numbering, or creative direction unless the user explicitly asks for a change.

When continuing a long structured result, preserve all relevant details from the previous parts, including character identity, appearance, environment, visual style, chronology, formatting, numbering, and previously established requirements.

If the requested answer is too large to fit safely in one response, split it into coherent parts. Do not begin a new scene, section, step, prompt, code block, list, or numbered item unless you can complete it. Finish the current item completely, stop at a natural boundary, and briefly ask whether to continue from the next item.

Never intentionally end in the middle of a sentence, paragraph, scene, prompt, code block, list item, or numbered item.

Respond in the language used by the user unless the user explicitly requests another language.

ПРАВИЛА КОНТЕКСТА ДИАЛОГА И ПРОДОЛЖЕНИЯ:

Считай переданную историю сообщений активным контекстом текущего диалога. Короткие и неполные сообщения пользователя понимай в связи с предыдущей перепиской, а не как отдельные запросы без контекста.

Если пользователь пишет «продолжай», «дальше», «да», «следующее», «продолжи» или использует аналогичное короткое подтверждение, продолжай предыдущую задачу с первой незавершённой сцены, раздела, шага, промта, блока кода, элемента списка или нумерованного пункта.

Не начинай задачу заново, не повторяй уже завершённый материал и не меняй установленные персонажи, стиль, формат, терминологию, ограничения, нумерацию или творческое направление, если пользователь явно не попросил об изменении.

При продолжении длинного структурированного ответа сохраняй все важные детали предыдущих частей: личность и внешность персонажей, окружение, визуальный стиль, хронологию, форматирование, нумерацию и ранее заданные требования.

Если запрошенный объём слишком велик для одного ответа, разбивай результат на логические части. Не начинай новую сцену, раздел, шаг, промт, блок кода, список или нумерованный пункт, если не можешь завершить его целиком. Закончи текущий пункт полностью, остановись на естественной границе и кратко предложи продолжить со следующего пункта.

Не обрывай намеренно ответ посреди предложения, абзаца, сцены, промта, блока кода, элемента списка или нумерованного пункта.

Отвечай на языке пользователя, если он явно не попросил использовать другой язык.

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

try {

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
    thinkingConfig: {
      thinkingBudget: 512
    },
    maxOutputTokens: 4000
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

  const finishReason = chunk?.candidates?.[0]?.finishReason;

  if (finishReason) {
    console.log("ASSISTANT FINISH_REASON:", finishReason);
  }

  const usageMetadata = chunk?.usageMetadata;
  const usageLog = {};

  if (typeof usageMetadata?.promptTokenCount === "number") {
    usageLog.promptTokenCount = usageMetadata.promptTokenCount;
  }

  if (typeof usageMetadata?.candidatesTokenCount === "number") {
    usageLog.candidatesTokenCount = usageMetadata.candidatesTokenCount;
  }

  if (typeof usageMetadata?.totalTokenCount === "number") {
    usageLog.totalTokenCount = usageMetadata.totalTokenCount;
  }

  if (Object.keys(usageLog).length > 0) {
    console.log("ASSISTANT USAGE_METADATA:", usageLog);
  }

  const text =
    chunk?.candidates?.[0]?.content?.parts
      ?.map(part => typeof part?.text === "string" ? part.text : "")
      .join("") || "";

  if (text) {

    reply += text;

    res.write(`data: ${JSON.stringify({ token: text })}\n\n`);

  }

}

res.write(`data: [DONE]\n\n`);

} catch (e) {

console.error("ASSISTANT STREAM ERROR:", e?.message || e);

if (!res.writableEnded) {
  res.end();
}

return;

}

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

app.post("/api/upload-image", authMiddleware, uploadPromptImageFile, async (req, res) => {
  try {

    const file = req.file;
    const { uploadId } = req.body;

    if (!file) {
      return res.status(400).json({
        ok: false,
        error: "file required"
      });
    }

    if (typeof uploadId !== "string" || !isUuid(uploadId)) {
      return res.status(400).json({
        ok: false,
        error: "invalid_upload_id"
      });
    }

    const allowedMimeTypes = new Set([
      "image/jpeg",
      "image/png",
      "image/webp"
    ]);

    if (!allowedMimeTypes.has(file.mimetype)) {
      return res.status(400).json({
        ok: false,
        error: "unsupported image type"
      });
    }

    const metadata = await sharp(file.buffer).metadata();
    const allowedFormats = new Set(["jpeg", "png", "webp"]);

    if (!metadata.format || !allowedFormats.has(metadata.format)) {
      return res.status(400).json({
        ok: false,
        error: "unsupported image format"
      });
    }

    if (metadata.pages && metadata.pages > 1) {
      return res.status(400).json({
        ok: false,
        error: "animated images are not supported"
      });
    }

    // 🔥 конвертируем в WEBP
    const webpBuffer = await sharp(file.buffer)
      .rotate()
      .resize({
        width: 1600,
        height: 1600,
        fit: "inside",
        withoutEnlargement: true
      })
      .webp({ quality: 85 })
      .toBuffer();

    // 🔥 загружаем в R2
    const previewBuffer = await sharp(file.buffer)
      .rotate()
      .resize({
        width: 320,
        height: 320,
        fit: "inside",
        withoutEnlargement: true
      })
      .webp({ quality: 60 })
      .toBuffer();

    const { url, key } = await uploadPromptImageToR2(webpBuffer, req.user.id, uploadId);
    const { url: previewUrl, key: previewKey } =
      await uploadPromptImagePreviewToR2(previewBuffer, req.user.id, uploadId);

    return res.json({
      ok: true,
      url,
      key,
      previewUrl,
      previewKey
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
  let newAvatarKey = null;

  try {
    const file = req.file;

    const userRes = await pool.query(
      "SELECT avatar_url FROM users WHERE id = $1",
      [req.user.id]
    );

    const oldAvatar = userRes.rows[0]?.avatar_url;
    const oldAvatarKey = oldAvatar ? getAvatarKey(oldAvatar) : null;

    if (!file) {
      return res.status(400).json({ ok: false, error: "no file" });
    }

    if (oldAvatar && !oldAvatarKey) {
      return res.status(500).json({ ok: false, error: "invalid_avatar_key" });
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

    // 🔥 загрузка в R2
    const uploadedAvatar = await uploadToR2WithKey(webp, "avatars");
    const url = uploadedAvatar.url;
    newAvatarKey = uploadedAvatar.key;

    // 🔥 сохраняем в БД
    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      await client.query(
        "UPDATE users SET avatar_url = $1 WHERE id = $2",
        [url, req.user.id]
      );

      if (oldAvatarKey) {
        await enqueueR2CleanupKeys(client, new Map([[oldAvatarKey, "avatar"]]));
      }

      await client.query("COMMIT");
    } catch (e) {
      await client.query("ROLLBACK");

      await enqueueR2CleanupKeys(pool, new Map([[newAvatarKey, "avatar"]]));

      void cleanupQueuedR2Objects([newAvatarKey]).catch((cleanupError) => {
        console.error("NEW AVATAR CLEANUP ERROR:", cleanupError);
      });

      throw e;
    } finally {
      client.release();
    }

    if (oldAvatarKey) {
      void cleanupQueuedR2Objects([oldAvatarKey]).catch((cleanupError) => {
        console.error("OLD AVATAR CLEANUP ERROR:", cleanupError);
      });
    }

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
  const client = await pool.connect();
  let armedPromptCleanupKeys = [];

  try {
    const userId = req.user.id;
    const { data, armPromptCleanupKeys } = req.body;

    if (armPromptCleanupKeys !== undefined && !Array.isArray(armPromptCleanupKeys)) {
      return res.status(400).json({ ok: false, error: "invalid_cleanup_keys" });
    }

    const rawArmPromptCleanupKeys = armPromptCleanupKeys || [];
    const validArmPromptCleanupKeys = rawArmPromptCleanupKeys.filter((key) => {
      const keyParts = typeof key === "string" ? getPromptImageKeyParts(key) : null;
      return keyParts && keyParts.owner === String(userId);
    });

    if (rawArmPromptCleanupKeys.length !== validArmPromptCleanupKeys.length) {
      return res.status(400).json({ ok: false, error: "invalid_cleanup_keys" });
    }

    armedPromptCleanupKeys = Array.from(new Set(validArmPromptCleanupKeys));
    const expectedPromptCleanupTypes = new Map(
      armedPromptCleanupKeys.map((key) => {
        const keyParts = getPromptImageKeyParts(key);
        return [
          key,
          keyParts?.variant === "preview" ? "prompt_preview" : "prompt_image"
        ];
      })
    );

    await client.query("BEGIN");

    const currentWorkspaceResult = await client.query(
      `SELECT data FROM workspaces WHERE user_id = $1`,
      [userId]
    );
    const currentWorkspaceData = currentWorkspaceResult.rows[0]?.data || null;

    await client.query(
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

    if (armedPromptCleanupKeys.length > 0) {
      await client.query(
        `
        UPDATE r2_cleanup_queue
        SET object_type = CASE
          WHEN object_type = 'prompt_image_pending' THEN 'prompt_image'
          WHEN object_type = 'prompt_preview_pending' THEN 'prompt_preview'
          ELSE object_type
        END
        WHERE object_key = ANY($1::text[])
          AND object_type IN ('prompt_image_pending', 'prompt_preview_pending')
        `,
        [armedPromptCleanupKeys]
      );

      const verifyResult = await client.query(
        `
        SELECT object_key, object_type
        FROM r2_cleanup_queue
        WHERE object_key = ANY($1::text[])
        `,
        [armedPromptCleanupKeys]
      );
      const actualPromptCleanupTypes = new Map(
        verifyResult.rows.map((row) => [row.object_key, row.object_type])
      );
      const allKeysArmed = armedPromptCleanupKeys.every((key) => {
        const actualType = actualPromptCleanupTypes.get(key);

        if (actualType === expectedPromptCleanupTypes.get(key)) {
          return true;
        }

        if (actualType) {
          return false;
        }

        return (
          !workspaceReferencesPromptKey(currentWorkspaceData, key) &&
          !workspaceReferencesPromptKey(data, key)
        );
      });

      if (!allKeysArmed) {
        await client.query("ROLLBACK");
        return res.status(409).json({
          ok: false,
          error: "cleanup_not_armed"
        });
      }
    }

    await client.query("COMMIT");

    if (armedPromptCleanupKeys.length > 0) {
      void cleanupQueuedR2Objects(armedPromptCleanupKeys).catch((error) => {
        console.error("PROMPT IMAGE ARMED CLEANUP ERROR:", error);
      });
    }

    res.json({ ok: true });

  } catch (e) {
    try {
      await client.query("ROLLBACK");
    } catch {}

    console.error("WORKSPACE SAVE ERROR:", e);

    res.status(500).json({ ok: false });

  } finally {
    client.release();
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
// PROMPT CARD IMAGE DELETE
function isUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
}

function isPromptImageKey(key) {
  return getPromptImageKeyParts(key) !== null;
}

function getPromptImageKeyParts(key) {
  const uuid = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
  const match = key.match(new RegExp(`^i/prompt-(${uuid})-(${uuid})(-preview)?\\.webp$`, "i"));

  if (!match) return null;

  return {
    owner: match[1],
    uploadId: match[2],
    variant: match[3] ? "preview" : "original"
  };
}

function workspaceReferencesPromptKey(data, key) {
  const cards = Array.isArray(data?.cards) ? data.cards : [];

  return cards.some((card) =>
    card?.type === "prompt" &&
    (card?.imageKey === key || card?.previewImageKey === key)
  );
}

function isGeneratedImageKey(key) {
  if (typeof key !== "string") return false;

  const match = key.match(/^i\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.webp$/i);
  return Boolean(match);
}

function getGeneratedImageKey(row) {
  if (isGeneratedImageKey(row?.image_key)) {
    return row.image_key;
  }

  if (typeof row?.image_url !== "string") {
    return null;
  }

  try {
    const parsed = new URL(row.image_url);
    const key = parsed.pathname.replace(/^\/+/, "");

    if (isGeneratedImageKey(key)) {
      return key;
    }
  } catch {
    return null;
  }

  return null;
}

async function deleteGeneratedImageObject(row) {
  const key = getGeneratedImageKey(row);

  if (!key) {
    throw new Error("invalid_generated_image_key");
  }

  await deleteFromR2ByKey(key);
}

function isGeneratedVideoKey(key) {
  if (typeof key !== "string") return false;

  return /^videos\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.mp4$/i.test(key);
}

function getGeneratedVideoKey(videoUrl) {
  if (typeof videoUrl !== "string") {
    return null;
  }

  if (isGeneratedVideoKey(videoUrl)) {
    return videoUrl;
  }

  try {
    const parsed = new URL(videoUrl);
    const marker = "/api/download-video/";
    const markerIndex = parsed.pathname.indexOf(marker);

    if (markerIndex === -1) {
      return null;
    }

    const fileName = parsed.pathname.slice(markerIndex + marker.length);
    const key = `videos/${fileName}`;

    if (isGeneratedVideoKey(key)) {
      return key;
    }
  } catch {
    return null;
  }

  return null;
}

function getVideoSigningSecret() {
  const secret = process.env.VIDEO_URL_SECRET;

  if (!secret) {
    console.error("VIDEO URL SIGNING CONFIG ERROR: VIDEO_URL_SECRET is not set");
    return null;
  }

  return secret;
}

function getVideoAccessKey(value) {
  if (typeof value !== "string") {
    return null;
  }

  if (isGeneratedVideoKey(value)) {
    return value;
  }

  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.mp4$/i.test(value)) {
    return `videos/${value}`;
  }

  return getGeneratedVideoKey(value);
}

function signVideoAccessUrl(objectKey, exp) {
  const secret = getVideoSigningSecret();

  if (!secret) {
    return null;
  }

  return crypto
    .createHmac("sha256", secret)
    .update(`${objectKey}:${exp}`)
    .digest("hex");
}

function getVideoFileNameFromKey(objectKey) {
  if (!isGeneratedVideoKey(objectKey)) {
    return null;
  }

  return objectKey.slice("videos/".length);
}

function timingSafeEqualString(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  const left = Buffer.from(a);
  const right = Buffer.from(b);

  if (left.length !== right.length) {
    return false;
  }

  return crypto.timingSafeEqual(left, right);
}

function getAvatarKey(avatarUrl) {
  if (typeof avatarUrl !== "string") {
    return null;
  }

  try {
    const parsed = new URL(avatarUrl);
    const key = parsed.pathname.replace(/^\/+/, "");

    if (/^avatars\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.webp$/i.test(key)) {
      return key;
    }
  } catch {
    return null;
  }

  return null;
}

function collectPromptCardCleanupKeys(data, userId, cleanupKeys) {
  const cards = Array.isArray(data?.cards) ? data.cards : [];

  for (const card of cards) {
    if (card?.type !== "prompt") continue;

    for (const [field, objectType] of [
      ["imageKey", "prompt_image"],
      ["previewImageKey", "prompt_preview"]
    ]) {
      const key = card?.[field];
      const keyParts = typeof key === "string" ? getPromptImageKeyParts(key) : null;

      if (keyParts && keyParts.owner === String(userId)) {
        cleanupKeys.set(key, objectType);
      }
    }
  }
}

async function enqueueR2CleanupKeys(client, cleanupKeys) {
  for (const [objectKey, objectType] of cleanupKeys) {
    await client.query(
      `
      INSERT INTO r2_cleanup_queue (object_key, object_type)
      VALUES ($1, $2)
      ON CONFLICT (object_key) DO NOTHING
      `,
      [objectKey, objectType]
    );
  }
}

async function cleanupQueuedR2Objects(objectKeys = null) {
  try {
    const armedObjectTypes = [
      "generated_image",
      "generated_video",
      "prompt_image",
      "prompt_preview",
      "avatar",
      "legacy_prompt_image",
      "legacy_workspace_video"
    ];

    const result = Array.isArray(objectKeys) && objectKeys.length
      ? await pool.query(
        `
        SELECT id, object_key
        FROM r2_cleanup_queue
        WHERE object_key = ANY($1::text[])
          AND object_type = ANY($2::text[])
        ORDER BY created_at ASC
        `,
        [objectKeys, armedObjectTypes]
      )
      : await pool.query(
        `
        SELECT id, object_key
        FROM r2_cleanup_queue
        WHERE object_type = ANY($1::text[])
        ORDER BY created_at ASC
        `,
        [armedObjectTypes]
      );

    for (const row of result.rows) {
      try {
        await deleteFromR2ByKey(row.object_key);

        await pool.query(
          `DELETE FROM r2_cleanup_queue WHERE id = $1`,
          [row.id]
        );
      } catch (e) {
        await pool.query(
          `
          UPDATE r2_cleanup_queue
          SET
            attempts = attempts + 1,
            last_attempt_at = NOW(),
            last_error = $2
          WHERE id = $1
          `,
          [row.id, String(e?.message || e).slice(0, 500)]
        );
      }
    }
  } catch (e) {
    console.error("R2 CLEANUP QUEUE ERROR:", e);
  }
}

app.post("/api/prompt-card/delete-image", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { key } = req.body;

    if (typeof key !== "string" || !isPromptImageKey(key)) {
      return res.status(400).json({
        ok: false,
        error: "invalid_key"
      });
    }

    const keyParts = getPromptImageKeyParts(key);

    if (!keyParts || keyParts.owner !== String(userId)) {
      return res.status(403).json({
        ok: false,
        error: "not_owned"
      });
    }

    const objectType = keyParts.variant === "preview"
      ? "prompt_preview_pending"
      : "prompt_image_pending";

    await pool.query(
      `
      INSERT INTO r2_cleanup_queue (object_key, object_type)
      VALUES ($1, $2)
      ON CONFLICT (object_key) DO NOTHING
      `,
      [key, objectType]
    );

    res.json({ ok: true });

  } catch (e) {
    console.error("PROMPT IMAGE DELETE ERROR:", e);
    res.status(500).json({
      ok: false,
      error: "delete_failed"
    });
  }
});

app.post("/api/prompt-card/cleanup-abandoned-upload", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { key } = req.body;

    if (typeof key !== "string" || !isPromptImageKey(key)) {
      return res.status(400).json({
        ok: false,
        error: "invalid_key"
      });
    }

    const keyParts = getPromptImageKeyParts(key);

    if (!keyParts || keyParts.owner !== String(userId)) {
      return res.status(403).json({
        ok: false,
        error: "not_owned"
      });
    }

    const workspaceResult = await pool.query(
      `SELECT data FROM workspaces WHERE user_id = $1`,
      [userId]
    );
    const workspaceCards = Array.isArray(workspaceResult.rows[0]?.data?.cards)
      ? workspaceResult.rows[0].data.cards
      : [];
    const hasWorkspaceReference = workspaceCards.some((card) =>
      card?.type === "prompt" &&
      (card?.imageKey === key || card?.previewImageKey === key)
    );

    if (hasWorkspaceReference) {
      return res.status(409).json({
        ok: false,
        error: "workspace_reference_exists"
      });
    }

    const objectType = keyParts.variant === "preview"
      ? "prompt_preview"
      : "prompt_image";

    await pool.query(
      `
      INSERT INTO r2_cleanup_queue (object_key, object_type)
      VALUES ($1, $2)
      ON CONFLICT (object_key) DO NOTHING
      `,
      [key, objectType]
    );

    void cleanupQueuedR2Objects([key]).catch((error) => {
      console.error("PROMPT ABANDONED UPLOAD CLEANUP ERROR:", error);
    });

    res.json({ ok: true });

  } catch (e) {
    console.error("PROMPT ABANDONED UPLOAD CLEANUP ERROR:", e);
    res.status(500).json({
      ok: false,
      error: "cleanup_failed"
    });
  }
});

// USER GENERATIONS HISTORY
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

  const { url: imageUrl, key: imageKey } = await uploadToR2WithKey(webpBuffer);

  const result = await pool.query(
  `INSERT INTO generations (user_id, prompt, image_url, image_key)
   VALUES ($1, $2, $3, $4)
   RETURNING id`,
  [id, prompt, imageUrl, imageKey]
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
      `
      SELECT image_url, image_key
      FROM generations
      WHERE id = $1
      AND user_id = $2
      `,
      [id, req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "image not found" });
    }

    const key = getGeneratedImageKey(result.rows[0]);

    if (!key) {
      return res.status(404).json({ error: "image not found" });
    }

    const object = await getObjectFromR2ByKey(key);

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
      const videoKey = videoCache.get(id);

      return res.json({
        ok: true,
        status: "done",
        video: `https://api.dizain.pro/api/download-video/${videoKey}`
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

const uploadedVideo = await uploadVideoToR2WithKey(buffer);
const videoKey = uploadedVideo.videoKey;

// 🔥 получаем userId
const userId = req.user.id;

// 🔥 ВАЖНО: prompt надо передать
const prompt = req.body.prompt || "video generation";

// 🔥 сохраняем в БД
try {
  await pool.query(
    `
    INSERT INTO generations (user_id, prompt, video_url, video_key)
    VALUES ($1, $2, $3, $4)
    `,
    [
      userId,
      prompt,
      uploadedVideo.url,
      uploadedVideo.key
    ]
  );
} catch (e) {
  try {
    await pool.query(
      `
      INSERT INTO r2_cleanup_queue (object_key, object_type, last_error)
      VALUES ($1, $2, $3)
      ON CONFLICT (object_key) DO NOTHING
      `,
      [
        uploadedVideo.key,
        "generated_video",
        "video_generation_db_insert_failed"
      ]
    );
  } catch (queueError) {
    console.error("VIDEO CLEANUP QUEUE INSERT ERROR:", queueError?.message || queueError);

    try {
      await deleteFromR2ByKey(uploadedVideo.key);
    } catch (deleteError) {
      console.error("VIDEO IMMEDIATE CLEANUP ERROR:", deleteError?.message || deleteError);
    }
  }

  throw e;
}

// кэш
videoCache.set(id, videoKey);

return res.json({
  ok: true,
  status: "done",
  video: `https://api.dizain.pro/api/download-video/${videoKey}`
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

app.post("/api/video/access", authMiddleware, async (req, res) => {
  try {
    const objectKey = getVideoAccessKey(req.body?.key);

    if (!objectKey) {
      return res.status(400).json({
        ok: false,
        error: "invalid_video_key"
      });
    }

    const fileName = getVideoFileNameFromKey(objectKey);

    if (!fileName) {
      return res.status(400).json({
        ok: false,
        error: "invalid_video_key"
      });
    }

    const legacyUrl = `https://api.dizain.pro/api/download-video/${fileName}`;
    const owner = await pool.query(
      `
      SELECT id
      FROM generations
      WHERE user_id = $1
      AND (
        video_key = $2
        OR (
          video_key IS NULL
          AND video_url = $3
        )
      )
      LIMIT 1
      `,
      [req.user.id, objectKey, legacyUrl]
    );

    if (!owner.rows.length) {
      return res.status(403).json({
        ok: false,
        error: "not_owned"
      });
    }

    const exp = Math.floor(Date.now() / 1000) + 5 * 60;
    const sig = signVideoAccessUrl(objectKey, exp);

    if (!sig) {
      return res.status(500).json({
        ok: false,
        error: "video_signing_not_configured"
      });
    }

    return res.json({
      ok: true,
      url: `https://api.dizain.pro/api/download-video/${fileName}?exp=${exp}&sig=${sig}`,
      expiresAt: exp
    });
  } catch (e) {
    console.error("VIDEO ACCESS ERROR:", e);

    return res.status(500).json({
      ok: false,
      error: "video_access_failed"
    });
  }
});

// ======================================================
// 🎬 VIDEO DOWNLOAD (R2 → USER)
// ======================================================

app.get("/api/download-video/:key", async (req, res) => {

  try {

    const { key } = req.params;
    const objectKey = `videos/${key}`;
    const exp = Number(req.query.exp);
    const sig = typeof req.query.sig === "string" ? req.query.sig : null;

    if (!isGeneratedVideoKey(objectKey) || !Number.isFinite(exp) || !sig) {
      return res.status(403).json({
        ok: false,
        error: "invalid_video_signature"
      });
    }

    if (exp < Math.floor(Date.now() / 1000)) {
      return res.status(403).json({
        ok: false,
        error: "video_signature_expired"
      });
    }

    const expectedSig = signVideoAccessUrl(objectKey, exp);

    if (!expectedSig || !timingSafeEqualString(sig, expectedSig)) {
      return res.status(403).json({
        ok: false,
        error: "invalid_video_signature"
      });
    }

    const object = await getObjectFromR2ByKey(objectKey);

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
// AUTO CLEANUP OLD GENERATIONS (17 days)
// ======================================

async function cleanupOldGenerations() {
  try {

    const result = await pool.query(`
      SELECT id, image_url, image_key, video_url, video_key
      FROM generations
      WHERE liked = false
      AND created_at < NOW() - interval '17 days'
    `);

    if (!result.rows.length) {
      console.log("cleanup: nothing to delete");
      return;
    }

    let deletedCount = 0;

    for (const row of result.rows) {
      try {
        const keys = [];

        if (row.image_url) {
          const imageKey = getGeneratedImageKey(row);

          if (!imageKey) {
            throw new Error("invalid_generated_image_key");
          }

          keys.push(imageKey);
        }

        if (row.video_url) {
          const videoKey = getGeneratedVideoKey(row.video_key) || getGeneratedVideoKey(row.video_url);

          if (!videoKey) {
            throw new Error("invalid_generated_video_key");
          }

          keys.push(videoKey);
        }

        for (const key of keys) {
          await deleteFromR2ByKey(key);
        }

        await pool.query(
          `DELETE FROM generations WHERE id = $1`,
          [row.id]
        );

        deletedCount += 1;

      } catch (e) {
        console.error("CLEANUP GENERATION DELETE ERROR:", {
          id: row.id,
          error: e?.message || e
        });
      }
    }

    console.log("deleted generations:", deletedCount);

  } catch (err) {
    console.error("CLEANUP ERROR:", err);
  }
}
setInterval(cleanupOldGenerations, 24 * 60 * 60 * 1000);
setInterval(cleanupQueuedR2Objects, 24 * 60 * 60 * 1000);

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
const httpServer = app.listen(PORT, () => {
  console.log(`🚀 AI backend running on port ${PORT}`);
});

let isShuttingDown = false;

async function gracefulShutdown(signal) {
  if (isShuttingDown) {
    console.log(`Shutdown already in progress (${signal})`);
    return;
  }

  isShuttingDown = true;
  console.log(`Shutdown started (${signal})`);

  const shutdownTimeout = setTimeout(() => {
    console.error("Shutdown timeout, forcing exit");
    process.exit(1);
  }, 15000);
  shutdownTimeout.unref?.();

  try {
    await tgBot.stopPolling();
    console.log("Telegram polling stopped");
  } catch (e) {
    console.error("TG STOP POLLING ERROR:", e?.message || e);
  }

  try {
    await new Promise((resolve, reject) => {
      httpServer.close((err) => {
        if (err) {
          reject(err);
          return;
        }

        resolve();
      });
    });
    console.log("HTTP server closed");
  } catch (e) {
    console.error("HTTP SERVER CLOSE ERROR:", e?.message || e);
  }

  try {
    await pool.end();
    console.log("DB pool closed");
  } catch (e) {
    console.error("DB POOL CLOSE ERROR:", e?.message || e);
  }

  clearTimeout(shutdownTimeout);
  console.log("Shutdown complete");
  process.exit(0);
}

process.on("SIGTERM", () => {
  void gracefulShutdown("SIGTERM");
});

process.on("SIGINT", () => {
  void gracefulShutdown("SIGINT");
});

app.get("/api/debug/users", authMiddleware, requireAdmin, async (req, res) => {
  try {
    const rawLimit = Number(req.query.limit);
    const rawOffset = Number(req.query.offset);
    const limit = Math.min(
      100,
      Math.max(1, Number.isFinite(rawLimit) ? Math.trunc(rawLimit) : 20)
    );
    const offset = Math.max(
      0,
      Number.isFinite(rawOffset) ? Math.trunc(rawOffset) : 0
    );

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
      LIMIT $1 OFFSET $2
    `, [limit, offset]);

    const totalResult = await pool.query(`
      SELECT COUNT(*)::int AS total
      FROM users
    `);
    const total = totalResult.rows[0]?.total ?? 0;
    const hasMore = offset + result.rows.length < total;

    res.json({
      ok: true,
      users: result.rows,
      total,
      hasMore,
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
const YOOKASSA_PAYMENT_GET_TIMEOUT_MS = 7000;

function logYooKassaWebhookDiagnostic(reason, details = {}) {
  console.warn("YOOKASSA WEBHOOK DIAGNOSTIC:", {
    reason,
    ...details
  });
}

function nonEmptyString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function parseRubToKopecks(value) {
  const normalized = String(value ?? "").trim().replace(",", ".");
  const match = normalized.match(/^(\d+)(?:\.(\d{1,2}))?$/);

  if (!match) return null;

  const rubles = BigInt(match[1]);
  const kopecks = BigInt((match[2] || "").padEnd(2, "0"));

  return rubles * 100n + kopecks;
}

app.post("/api/payments/yookassa-webhook", async (req, res) => {
  try {
    const event = req.body;

    // интересует только успешная оплата
    if (event.event !== "payment.succeeded") {
      return res.json({ ok: true });
    }

    const webhookPaymentId = nonEmptyString(event.object?.id);

    if (!webhookPaymentId) {
      logYooKassaWebhookDiagnostic("missing_webhook_payment_id");
      return res.json({ ok: true, ignored: true });
    }

    let yookassaResponse;

    try {
      yookassaResponse = await axios.get(
        `https://api.yookassa.ru/v3/payments/${encodeURIComponent(webhookPaymentId)}`,
        {
          auth: {
            username: process.env.YOOKASSA_SHOP_ID,
            password: process.env.YOOKASSA_SECRET_KEY
          },
          timeout: YOOKASSA_PAYMENT_GET_TIMEOUT_MS,
          validateStatus: () => true
        }
      );
    } catch (lookupError) {
      logYooKassaWebhookDiagnostic("yookassa_payment_lookup_unavailable", {
        code: lookupError.code || "unknown"
      });
      return res.status(503).json({ ok: false });
    }

    if (yookassaResponse.status === 401 || yookassaResponse.status === 403) {
      logYooKassaWebhookDiagnostic("yookassa_auth_failed", {
        status: yookassaResponse.status
      });
      return res.status(500).json({ ok: false });
    }

    if (yookassaResponse.status === 404 || yookassaResponse.status >= 500) {
      logYooKassaWebhookDiagnostic("yookassa_payment_lookup_temporary_failure", {
        status: yookassaResponse.status
      });
      return res.status(503).json({ ok: false });
    }

    if (yookassaResponse.status !== 200) {
      logYooKassaWebhookDiagnostic("yookassa_payment_lookup_failed", {
        status: yookassaResponse.status
      });
      return res.status(502).json({ ok: false });
    }

    const paymentObject = yookassaResponse.data;
    const verifiedPaymentId = nonEmptyString(paymentObject?.id);
    const metadataPaymentId = nonEmptyString(paymentObject?.metadata?.payment_id);
    const metadataUserId = nonEmptyString(paymentObject?.metadata?.user_id);
    const verifiedAmountKopecks = parseRubToKopecks(paymentObject?.amount?.value);

    if (
      verifiedPaymentId !== webhookPaymentId ||
      paymentObject?.status !== "succeeded" ||
      paymentObject?.paid !== true ||
      paymentObject?.amount?.currency !== "RUB" ||
      !metadataPaymentId ||
      !metadataUserId ||
      verifiedAmountKopecks === null
    ) {
      logYooKassaWebhookDiagnostic("verified_payment_validation_failed");
      return res.json({ ok: true, ignored: true });
    }

    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(metadataPaymentId)) {
      logYooKassaWebhookDiagnostic("invalid_metadata_payment_id");
      return res.json({ ok: true, ignored: true });
    }

    let paymentId = metadataPaymentId;

    // проверяем платёж
    let result = await pool.query(
      "SELECT * FROM payments WHERE id = $1",
      [paymentId]
    );

    if (result.rows.length === 0) {
      result = await pool.query(
        "SELECT * FROM payments WHERE external_id = $1",
        [verifiedPaymentId]
      );

      if (result.rows.length === 0) {
        logYooKassaWebhookDiagnostic("payment_not_found");
        return res.json({ ok: true, ignored: true });
      }
    }

    const payment = result.rows[0];
    paymentId = payment.id;
    const userId = payment.user_id;
    const dbAmountKopecks = parseRubToKopecks(payment.amount);

    if (
      String(payment.id) !== metadataPaymentId ||
      String(payment.user_id) !== metadataUserId ||
      payment.external_id !== verifiedPaymentId ||
      dbAmountKopecks === null ||
      dbAmountKopecks !== verifiedAmountKopecks
    ) {
      logYooKassaWebhookDiagnostic("payment_database_validation_failed");
      return res.json({ ok: true, ignored: true });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const lockedPaymentResult = await client.query(
        "SELECT * FROM payments WHERE id = $1 FOR UPDATE",
        [paymentId]
      );

      if (lockedPaymentResult.rows.length === 0) {
        await client.query("ROLLBACK");
        logYooKassaWebhookDiagnostic("locked_payment_not_found");
        return res.json({ ok: true, ignored: true });
      }

      const lockedPayment = lockedPaymentResult.rows[0];
      const lockedDbAmountKopecks = parseRubToKopecks(lockedPayment.amount);

      if (
        String(lockedPayment.id) !== metadataPaymentId ||
        String(lockedPayment.user_id) !== metadataUserId ||
        lockedPayment.external_id !== verifiedPaymentId ||
        lockedPayment.provider !== "yookassa" ||
        lockedDbAmountKopecks === null ||
        lockedDbAmountKopecks !== verifiedAmountKopecks
      ) {
        await client.query("ROLLBACK");
        logYooKassaWebhookDiagnostic("locked_payment_validation_failed");
        return res.json({ ok: true, ignored: true });
      }

      // защита от двойного вебхука
      if (lockedPayment.status === "paid") {
        await client.query("COMMIT");
        return res.json({ ok: true, alreadyProcessed: true });
      }

      // отмечаем платёж
      const paymentUpdate = await client.query(
        "UPDATE payments SET status = 'paid', provider_payment_id = $1 WHERE id = $2",
        [paymentObject.id, paymentId]
      );

      if (paymentUpdate.rowCount !== 1) {
        throw new Error("payment_update_failed");
      }

      // начисляем токены
      const userUpdate = await client.query(
        "UPDATE users SET tokens = tokens + $1 WHERE id = $2",
        [lockedPayment.tokens, lockedPayment.user_id]
      );

      if (userUpdate.rowCount !== 1) {
        throw new Error("user_tokens_update_failed");
      }

// =======================
// ПОДПИСКА
// =======================

// проверяем подписку
const sub = await client.query(
  `SELECT expires_at FROM subscriptions WHERE user_id=$1`,
  [userId]
);

const now = new Date();

if (sub.rows.length === 0) {
  // подписки нет → создаём на 30 дней
  const expires = new Date(now);
  expires.setDate(expires.getDate() + 30);

  await client.query(
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

    await client.query(
      `UPDATE subscriptions SET expires_at=$1 WHERE user_id=$2`,
      [newExpire, userId]
    );
  }
  // если активна — НЕ трогаем
}

      // лог
      await client.query(
        `INSERT INTO token_logs (user_id, change, reason)
         VALUES ($1, $2, 'payment')`,
        [lockedPayment.user_id, lockedPayment.tokens]
      );

      await client.query("COMMIT");
      return res.json({ ok: true });
    } catch (transactionError) {
      await client.query("ROLLBACK");
      throw transactionError;
    } finally {
      client.release();
    }
  } catch (e) {
    console.error("YOOKASSA WEBHOOK ERROR:", e);
    res.status(500).json({ ok: false });
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
    // 🔐 Только админ
    if (req.user.role !== "admin") {
      return res.status(403).json({ ok: false, error: "forbidden" });
    }

    const rawLimit = Number(req.query.limit);
    const rawOffset = Number(req.query.offset);
    const limit = Math.min(
      100,
      Math.max(1, Number.isFinite(rawLimit) ? Math.trunc(rawLimit) : 20)
    );
    const offset = Math.max(
      0,
      Number.isFinite(rawOffset) ? Math.trunc(rawOffset) : 0
    );

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
      LIMIT $1 OFFSET $2
    `, [limit, offset]);

    const totalResult = await pool.query(`
      SELECT COUNT(*)::int AS total
      FROM payments p
      JOIN users u ON u.id = p.user_id
    `);
    const total = totalResult.rows[0]?.total ?? 0;
    const hasMore = offset + result.rows.length < total;

    return res.json({
      ok: true,
      payments: result.rows,
      total,
      hasMore,
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

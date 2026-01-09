import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { GoogleGenerativeAI } from "@google/generative-ai";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));

const PORT = process.env.PORT || 3000;

// --- Проверка наличия ключа ---
if (!process.env.GEMINI_API_KEY) {
  console.error("❌ GEMINI_API_KEY is not set");
  process.exit(1);
}

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

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

// Корень тоже оставим, чтобы не путаться
app.get("/", (req, res) => {
  res.json({ status: "ok", service: "ai-backend" });
});

// ==================
// GEMINI PROXY
// ==================
app.post("/api/generate-image", async (req, res) => {
  try {
    const { prompt } = req.body;

    if (!prompt || typeof prompt !== "string") {
      return res.status(400).json({ error: "prompt is required" });
    }

    const model = genAI.getGenerativeModel({
      model: "gemini-2.5-flash-image"
    });

    // защита от зависаний
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

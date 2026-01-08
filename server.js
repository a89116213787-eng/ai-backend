import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { GoogleGenerativeAI } from "@google/generative-ai";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// health check
app.get("/", (req, res) => {
  res.json({ status: "ok", service: "ai-backend" });
});

// proxy endpoint
app.post("/api/generate-image", async (req, res) => {
  try {
    const { prompt } = req.body;

    if (!prompt) {
      return res.status(400).json({ error: "prompt is required" });
    }

    const model = genAI.getGenerativeModel({
      model: "gemini-2.5-flash-image"
    });

    const result = await model.generateContent(prompt);
    const response = await result.response;

    res.json(response);
  } catch (err) {
    console.error("Gemini error:", err);
    res.status(500).json({ error: "generation failed" });
  }
});

app.listen(PORT, () => {
  console.log(`AI backend running on port ${PORT}`);
});

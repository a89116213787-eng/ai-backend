# AI Backend — Gemini Proxy

Это прокси-сервер для работы с Google Gemini API.
Используется как безопасный backend, чтобы:
- не светить API-ключи на фронте
- обходить региональные ограничения
- иметь стабильную точку доступа для сайтов и приложений

---

## 🔗 Текущие адреса

Backend (Render):
https://ai-backend-bd2h.onrender.com

Health-check:
GET /health

Основной API:
POST /api/generate-image

---

## 🧠 Архитектура

[ Frontend ] ---> [ AI Backend (Render) ] ---> [ Google Gemini API ]
|
└── хранит GEMINI_API_KEY

---

## 🚀 Быстрое восстановление с нуля

### 1. Клонировать репозиторий
```bash
git clone https://github.com/a89116213787-eng/ai-backend.git
cd ai-backend

2. Установить зависимости
npm install

3. Создать .env
GEMINI_API_KEY=your_real_key_here
PORT=3000

4. Запуск локально
node server.js


Проверка:

http://localhost:3000/health

☁️ Восстановление на Render

Зайти: https://dashboard.render.com

New → Web Service

Подключить репозиторий ai-backend

Настройки:

Language: Node

Build Command: yarn install или npm install

Start Command: node server.js

В Environment Variables добавить:

GEMINI_API_KEY = ваш ключ


Deploy

🧪 Тест API из PowerShell
Invoke-WebRequest `
  -Uri https://ai-backend-bd2h.onrender.com/api/generate-image `
  -Method POST `
  -Headers @{ "Content-Type" = "application/json" } `
  -Body '{"prompt":"A futuristic robot in cyberpunk city"}'

🌐 Использование на фронтенде
Пример (чистый JS)
<!DOCTYPE html>
<html>
<body>
  <button id="gen">Generate</button>
  <div id="out"></div>

  <script>
    document.getElementById("gen").onclick = async () => {
      const res = await fetch("https://ai-backend-bd2h.onrender.com/api/generate-image", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          prompt: "A futuristic robot in cyberpunk city"
        })
      });

      const data = await res.json();

      const parts = data.data.candidates[0].content.parts;
      const imgPart = parts.find(p => p.inlineData);

      if (imgPart) {
        const img = document.createElement("img");
        img.src = "data:image/png;base64," + imgPart.inlineData.data;
        document.getElementById("out").appendChild(img);
      }
    };
  </script>
</body>
</html>

Пример (Next.js / React)
export async function generateImage(prompt: string) {
  const res = await fetch("https://ai-backend-bd2h.onrender.com/api/generate-image", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ prompt })
  });

  const data = await res.json();

  const parts = data.data.candidates[0].content.parts;
  const img = parts.find((p: any) => p.inlineData);

  return img
    ? "data:image/png;base64," + img.inlineData.data
    : null;
}
import express from "express";
import axios from "axios";
import { v4 as uuidv4 } from "uuid";

export default function paymentsRouter(pool, authMiddleware) {
  const router = express.Router();

/*
POST /api/payments/create
Создать платеж
*/
router.post("/create", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const userEmail = req.user.email;
    const amount = Number(req.body.amount);
    const tokens = Number(req.body.tokens);

    if (!amount || !tokens) {
      return res.status(400).json({
        ok: false,
        error: "invalid_data"
      });
    }

    // создаём запись в БД
    const result = await pool.query(
      `INSERT INTO payments (user_id, amount, tokens, status, provider)
       VALUES ($1, $2, $3, 'pending', 'yookassa')
       RETURNING id`,
      [userId, amount, tokens]
    );

    const paymentId = result.rows[0].id;

    // ============================
    // 💳 СОЗДАЕМ ПЛАТЕЖ В ЮKASSA
    // ============================

    const yooResponse = await axios.post(
      "https://api.yookassa.ru/v3/payments",
      {
        amount: {
          value: amount.toFixed(2),
          currency: "RUB"
        },

        confirmation: {
          type: "redirect",
          return_url: "https://dizain.pro/account/billing"
        },

        capture: true,
        description: `Покупка ${tokens} токенов`,

        // 🔥 ВОТ ЭТО ОБЯЗАТЕЛЬНО!
        receipt: {
  customer: {
    email: userEmail
  },
  items: [
    {
      description: `Токены (${tokens})`,
      quantity: "1.00",
      amount: {
        value: amount.toFixed(2),
        currency: "RUB"
      },
      vat_code: 1,
      payment_subject: "service",
      payment_mode: "full_prepayment"
    }
  ]
}

      },
      {
        auth: {
          username: process.env.YOOKASSA_SHOP_ID,
          password: process.env.YOOKASSA_SECRET_KEY
        },
        headers: {
          "Idempotence-Key": uuidv4()
        }
      }
    );

    const confirmationUrl = yooResponse.data.confirmation.confirmation_url;

    // сохраняем id юкассы
    await pool.query(
      `UPDATE payments
       SET external_id = $1
       WHERE id = $2`,
      [yooResponse.data.id, paymentId]
    );

    return res.json({
      ok: true,
      confirmationUrl
    });

  } catch (e) {
    console.error("CREATE PAYMENT ERROR:", e.response?.data || e);
    return res.status(500).json({
      ok: false,
      error: "payment_creation_failed"
    });
  }
});

return router;
}
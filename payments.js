import express from "express";
import axios from "axios";

const PAYMENT_TARIFFS = [
  { name: "basic", amount: 999, tokens: 260 },
  { name: "pro", amount: 1999, tokens: 680 },
  { name: "vip", amount: 3999, tokens: 1700 }
];

const PAYMENT_REQUEST_ID_MAX_LENGTH = 64;
const PAYMENT_REQUEST_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isValidPaymentRequestId(value) {
  return (
    typeof value === "string" &&
    value.length <= PAYMENT_REQUEST_ID_MAX_LENGTH &&
    PAYMENT_REQUEST_ID_RE.test(value)
  );
}

function getYooKassaConfirmationUrl(payment) {
  const confirmationUrl = payment?.confirmation?.confirmation_url;
  return typeof confirmationUrl === "string" && confirmationUrl
    ? confirmationUrl
    : null;
}

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
    const requestedAmount = Number(req.body.amount);
    const requestedTokens = Number(req.body.tokens);
    const requestId = req.body.requestId;

    const tariff = PAYMENT_TARIFFS.find(
      (item) => item.amount === requestedAmount && item.tokens === requestedTokens
    );

    if (!tariff) {
      return res.status(400).json({
        ok: false,
        error: "invalid_tariff"
      });
    }

    const { amount, tokens } = tariff;

    if (!isValidPaymentRequestId(requestId)) {
      return res.status(400).json({
        ok: false,
        error: "invalid_request_id"
      });
    }

    // создаём запись в БД
    let payment;

    try {
      const result = await pool.query(
        `INSERT INTO payments (user_id, amount, tokens, status, provider, idempotency_key)
         VALUES ($1, $2, $3, 'pending', 'yookassa', $4)
         RETURNING id, user_id, amount, tokens, status, provider, external_id`,
        [userId, amount, tokens, requestId]
      );

      payment = result.rows[0];
    } catch (insertError) {
      if (insertError.code !== "23505") {
        throw insertError;
      }

      const existing = await pool.query(
        `SELECT id, user_id, amount, tokens, status, provider, external_id
         FROM payments
         WHERE user_id = $1 AND idempotency_key = $2`,
        [userId, requestId]
      );

      if (existing.rows.length === 0) {
        throw insertError;
      }

      payment = existing.rows[0];
    }

    if (
      String(payment.user_id) !== String(userId) ||
      Number(payment.amount) !== amount ||
      Number(payment.tokens) !== tokens ||
      payment.provider !== "yookassa"
    ) {
      return res.status(400).json({
        ok: false,
        error: "invalid_request_id"
      });
    }

    const paymentId = payment.id;
    const idempotenceKey = `dizain-payment-${requestId}`;

    if (payment.external_id) {
      const existingYooResponse = await axios.get(
        `https://api.yookassa.ru/v3/payments/${encodeURIComponent(payment.external_id)}`,
        {
          auth: {
            username: process.env.YOOKASSA_SHOP_ID,
            password: process.env.YOOKASSA_SECRET_KEY
          },
          validateStatus: () => true
        }
      );

      if (existingYooResponse.status === 200) {
        const existingConfirmationUrl = getYooKassaConfirmationUrl(existingYooResponse.data);

        if (existingConfirmationUrl) {
          return res.json({
            ok: true,
            confirmationUrl: existingConfirmationUrl
          });
        }
      }
    }

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
        metadata: {
          payment_id: String(paymentId),
          user_id: String(userId)
        },

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
          "Idempotence-Key": idempotenceKey
        }
      }
    );

    const confirmationUrl = getYooKassaConfirmationUrl(yooResponse.data);

    if (!confirmationUrl) {
      throw new Error("missing_confirmation_url");
    }

    // сохраняем id юкассы
    const externalIdUpdate = await pool.query(
      `UPDATE payments
       SET external_id = $1
       WHERE id = $2
         AND (external_id IS NULL OR external_id = $1)`,
      [yooResponse.data.id, paymentId]
    );

    if (externalIdUpdate.rowCount !== 1) {
      throw new Error("payment_external_id_update_failed");
    }

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

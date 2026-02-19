import express from "express";

export default function paymentsRouter(pool, authMiddleware) {
  const router = express.Router();

/*
POST /api/payments/create
Создать платеж
*/
router.post("/create", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const amount = Number(req.body.amount);
    const tokens = Number(req.body.tokens);

    if (!amount || !tokens) {
      return res.status(400).json({
        ok: false,
        error: "invalid_data"
      });
    }

    const result = await pool.query(
      `INSERT INTO payments (user_id, amount, tokens, status, provider)
       VALUES ($1, $2, $3, 'pending', 'mock')
       RETURNING id`,
      [userId, amount, tokens]
    );

    const paymentId = result.rows[0].id;

    // ===============================
// 🔥 ПОДПИСКА (1 месяц)
// ===============================

// админ всегда активен
const userRole = req.user.role;

if (userRole !== "admin") {

  const sub = await pool.query(
    "SELECT expires_at FROM subscriptions WHERE user_id = $1",
    [userId]
  );

  if (sub.rows.length === 0) {
    await pool.query(
      `INSERT INTO subscriptions (user_id, expires_at)
       VALUES ($1, NOW() + INTERVAL '1 month')`,
      [userId]
    );
  } else {
    await pool.query(
      `UPDATE subscriptions
       SET expires_at = GREATEST(expires_at, NOW()) + INTERVAL '1 month'
       WHERE user_id = $1`,
      [userId]
    );
  }
}

    return res.json({
      ok: true,
      paymentId
    });

  } catch (e) {
    console.error("CREATE PAYMENT ERROR:", e);
    res.status(500).json({
      ok: false,
      error: "server_error"
    });
  }
});

return router;
}
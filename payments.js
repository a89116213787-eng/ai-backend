import express from "express";
import pool from "../db.js";
import auth from "../middleware/auth.js";

const router = express.Router();

/*
POST /api/payments/create
Создать платеж
*/
router.post("/create", auth, async (req, res) => {
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

export default router;
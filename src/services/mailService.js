import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: 587,
  secure: process.env.SMTP_SECURE === "false", // true для 465, false для 587
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
    },
  tls: {
    rejectUnauthorized: false,
  },
});

export async function sendMail({ to, subject, html }) {
  const info = await transporter.sendMail({
    from: process.env.MAIL_FROM,
    to,
    subject,
    html,
  });

  console.log("📧 Mail sent:", info.messageId);
}
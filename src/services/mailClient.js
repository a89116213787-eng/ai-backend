export async function sendMail({ to, subject, html }) {
  const MAIL_SERVICE_URL =
    process.env.MAIL_SERVICE_URL || "http://localhost:3333/send";

  try {
    const res = await fetch(MAIL_SERVICE_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ to, subject, html }),
    });

    const data = await res.json();

    if (!res.ok || data.ok === false) {
      console.error("MAIL SERVICE ERROR:", data);
      throw new Error(data.error || "mail service failed");
    }

    console.log("📨 Mail sent:", data.messageId);
    return data;
  } catch (e) {
    console.error("❌ sendMail failed:", e.message);
    throw e;
  }
}
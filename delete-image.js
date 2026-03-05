import express from "express";
import { S3Client, DeleteObjectCommand } from "@aws-sdk/client-s3";

const router = express.Router();

const s3 = new S3Client({
  region: "auto",
  endpoint: process.env.R2_ENDPOINT,
  credentials: {
    accessKeyId: process.env.R2_KEY,
    secretAccessKey: process.env.R2_SECRET
  }
});

router.post("/delete-image", async (req, res) => {

  try {

    const { url } = req.body;

    if (!url) {
      return res.json({ ok: false });
    }

    const key = url.split("/").pop();

    await s3.send(new DeleteObjectCommand({
      Bucket: process.env.R2_BUCKET,
      Key: key
    }));

    res.json({ ok: true });

  } catch (e) {

    console.error("delete r2 error", e);

    res.json({ ok: false });

  }

});

export default router;
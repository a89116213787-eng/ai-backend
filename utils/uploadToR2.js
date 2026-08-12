import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import crypto from "crypto";

const s3 = new S3Client({
  region: "auto",
  endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: process.env.R2_ACCESS_KEY,
    secretAccessKey: process.env.R2_SECRET_KEY,
  },
});

export async function uploadToR2(buffer, folder = "i") {

  const { url } = await uploadToR2WithKey(buffer, folder);
  return url;
}

export async function uploadToR2WithKey(buffer, folder = "i") {

  const id = crypto.randomUUID();
  const key = `${folder}/${id}.webp`;

  await s3.send(
    new PutObjectCommand({
      Bucket: process.env.R2_BUCKET,
      Key: key,
      Body: buffer,
      ContentType: "image/webp",
    })
  );

  const url = `https://pub-4492119d79ef42ebb8609370399fa7b8.r2.dev/${key}`;

  return {
    url,
    key
  };
}

function getPromptImageOwnerSegment(userId) {
  const owner = String(userId);

  if (!/^[A-Za-z0-9_-]+$/.test(owner)) {
    throw new Error("invalid prompt image owner");
  }

  return owner;
}

export async function uploadPromptImageToR2(buffer, userId) {

  const owner = getPromptImageOwnerSegment(userId);
  const id = crypto.randomUUID();
  const key = `i/prompt-${owner}-${id}.webp`;

  await s3.send(
    new PutObjectCommand({
      Bucket: process.env.R2_BUCKET,
      Key: key,
      Body: buffer,
      ContentType: "image/webp",
    })
  );

  const url = `https://pub-4492119d79ef42ebb8609370399fa7b8.r2.dev/${key}`;

  return {
    url,
    key
  };
}

import { S3Client, PutObjectCommand, DeleteObjectCommand, GetObjectCommand } from "@aws-sdk/client-s3";
import crypto from "crypto";

const s3 = new S3Client({
  region: "auto",
  endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: process.env.R2_ACCESS_KEY,
    secretAccessKey: process.env.R2_SECRET_KEY,
  },
});

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

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

export async function uploadGeneratedImagePreviewToR2(buffer, imageKey) {

  const match = String(imageKey).match(/^i\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.webp$/i);

  if (!match) {
    throw new Error("invalid generated image key");
  }

  const key = `i/${match[1]}-preview.webp`;

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

  if (!UUID_PATTERN.test(owner)) {
    throw new Error("invalid prompt image owner");
  }

  return owner;
}

function getPromptImageUploadSegment(uploadId) {
  const id = String(uploadId);

  if (!UUID_PATTERN.test(id)) {
    throw new Error("invalid prompt image upload id");
  }

  return id;
}

export async function uploadPromptImageToR2(buffer, userId, uploadId) {

  const owner = getPromptImageOwnerSegment(userId);
  const id = getPromptImageUploadSegment(uploadId);
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

export async function uploadPromptImagePreviewToR2(buffer, userId, uploadId) {

  const owner = getPromptImageOwnerSegment(userId);
  const id = getPromptImageUploadSegment(uploadId);
  const key = `i/prompt-${owner}-${id}-preview.webp`;

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

export async function uploadVideoToR2WithKey(buffer) {
  const id = crypto.randomUUID();
  const key = `videos/${id}.mp4`;

  await s3.send(
    new PutObjectCommand({
      Bucket: process.env.R2_BUCKET,
      Key: key,
      Body: buffer,
      ContentType: "video/mp4",
    })
  );

  return {
    key,
    videoKey: id,
    url: `https://api.dizain.pro/api/download-video/${id}.mp4`
  };
}

export async function uploadVideoPosterToR2WithKey(buffer, videoKey) {
  const match = String(videoKey).match(/^videos\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.mp4$/i);

  if (!match) {
    throw new Error("invalid generated video key");
  }

  const key = `videos/${match[1]}-poster.webp`;

  await s3.send(
    new PutObjectCommand({
      Bucket: process.env.R2_BUCKET,
      Key: key,
      Body: buffer,
      ContentType: "image/webp",
    })
  );

  return {
    key,
    url: `/api/video-poster/${match[1]}-poster.webp`
  };
}

export async function deletePromptImageFromR2(key) {
  await s3.send(
    new DeleteObjectCommand({
      Bucket: process.env.R2_BUCKET,
      Key: key
    })
  );
}

export async function deleteFromR2ByKey(key) {
  await s3.send(
    new DeleteObjectCommand({
      Bucket: process.env.R2_BUCKET,
      Key: key
    })
  );
}

export async function getObjectFromR2ByKey(key) {
  return s3.send(
    new GetObjectCommand({
      Bucket: process.env.R2_BUCKET,
      Key: key
    })
  );
}

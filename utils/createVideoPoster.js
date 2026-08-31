import { spawn } from "child_process";
import crypto from "crypto";
import fs from "fs/promises";
import os from "os";
import path from "path";
import ffmpegPath from "ffmpeg-static";
import sharp from "sharp";

const POSTER_TIMESTAMPS_SECONDS = [0.5, 0.1];
const FFMPEG_TIMEOUT_MS = 15000; // Bounded one-frame extraction for generated videos.
const MAX_STDERR_BYTES = 64 * 1024;
const MAX_FRAME_BYTES = 25 * 1024 * 1024;

function appendBounded(existing, chunk, maxBytes) {
  const next = Buffer.concat([existing, chunk]);
  return next.length > maxBytes ? next.subarray(next.length - maxBytes) : next;
}

function extractFrame(tempVideoPath, timestampSeconds) {
  return new Promise((resolve, reject) => {
    if (!ffmpegPath) {
      reject(new Error("ffmpeg-static path is not available"));
      return;
    }

    const child = spawn(ffmpegPath, [
      "-hide_banner",
      "-loglevel",
      "error",
      "-ss",
      String(timestampSeconds),
      "-i",
      tempVideoPath,
      "-frames:v",
      "1",
      "-an",
      "-f",
      "image2pipe",
      "-vcodec",
      "png",
      "pipe:1",
    ]);

    const stdoutChunks = [];
    let stdoutBytes = 0;
    let stderr = Buffer.alloc(0);
    let settled = false;
    let timedOut = false;

    const finish = (error, frameBuffer) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timeout);
      if (error) {
        reject(error);
        return;
      }
      resolve(frameBuffer);
    };

    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, FFMPEG_TIMEOUT_MS);

    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX_FRAME_BYTES) {
        child.kill("SIGKILL");
        finish(new Error("ffmpeg frame output exceeded size limit"));
        return;
      }
      stdoutChunks.push(chunk);
    });

    child.stderr.on("data", (chunk) => {
      stderr = appendBounded(stderr, chunk, MAX_STDERR_BYTES);
    });

    child.on("error", (error) => {
      finish(error);
    });

    child.on("close", (code, signal) => {
      if (settled) {
        return;
      }

      if (timedOut) {
        finish(new Error(`ffmpeg poster extraction timed out after ${FFMPEG_TIMEOUT_MS}ms`));
        return;
      }

      if (code !== 0) {
        const message = stderr.toString("utf8").trim();
        finish(new Error(`ffmpeg poster extraction failed with code ${code}${message ? `: ${message}` : ""}`));
        return;
      }

      const frameBuffer = Buffer.concat(stdoutChunks);
      if (frameBuffer.length === 0) {
        finish(new Error(`ffmpeg poster extraction produced no frame${signal ? ` (signal ${signal})` : ""}`));
        return;
      }

      finish(null, frameBuffer);
    });
  });
}

export async function createVideoPoster(videoBuffer) {
  if (!Buffer.isBuffer(videoBuffer) || videoBuffer.length === 0) {
    throw new TypeError("createVideoPoster expects a non-empty MP4 Buffer");
  }

  const tempVideoPath = path.join(os.tmpdir(), `dizain-video-poster-${crypto.randomUUID()}.mp4`);

  try {
    await fs.writeFile(tempVideoPath, videoBuffer);

    let lastError = null;
    for (const timestampSeconds of POSTER_TIMESTAMPS_SECONDS) {
      try {
        const frameBuffer = await extractFrame(tempVideoPath, timestampSeconds);
        return sharp(frameBuffer)
          .resize({
            width: 1024,
            height: 1024,
            fit: "inside",
            withoutEnlargement: true,
          })
          .webp({ quality: 65 })
          .toBuffer();
      } catch (error) {
        lastError = error;
      }
    }

    throw lastError || new Error("ffmpeg poster extraction failed");
  } finally {
    await fs.rm(tempVideoPath, { force: true });
  }
}

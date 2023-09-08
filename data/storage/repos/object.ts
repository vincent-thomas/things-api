import { env } from "@core/env";
import { s3 } from "../client";
import { GetObjectCommand, PutObjectCommand } from "@aws-sdk/client-s3";
import { decrypt, encrypt } from "crypted";
import { fromBuffer } from "bformat";

export const uploadObject = async (
  userId: string,
  objectId: string,
  encryptionKey: Buffer,
  Body: Buffer
) => {
  const toSend = encrypt(fromBuffer(Body), encryptionKey);
  try {
    const command = new PutObjectCommand({
      Bucket: env.getEnv("s3Bucket"),
      Key: `${userId}/drive/${objectId}`,
      Body: toSend
    });
    await s3.send(command);
    return { success: true };
  } catch (e) {
    console.trace(e);
    return { success: false };
  }
};


export const getStorageObject = async (userId: string, objectId: string) => {
  const command = new GetObjectCommand({
    Key: `${userId}/drive/${objectId}`,
    Bucket: env.getEnv("s3Bucket"),
  });

  const response = await s3.send(command);
  const Uint8Array = await response.Body.transformToByteArray();

  const bufferBody = Buffer.from(Uint8Array);

  return {success: true, data: bufferBody};
}
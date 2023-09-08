import { createDBObject, getDBObject, getStorageObject, uploadObject } from "@core/data";
import { fromBuffer, toBuffer } from "bformat";
import { decrypt } from "crypted";

interface CreateObjectI {
  filename: string;
  fileType: string;
}

export const createObject = async (
  folderId: string,
  userId: string,
  meta: CreateObjectI,
  body: Buffer
) => {
  const result = await createDBObject(
    {
      folderId,
      userId
    },
    meta
  );

  if (!result.success || !result.data?.objectId) {
    return { success: false };
  }

  const uploadResult = await uploadObject(
    userId,
    result.data.objectId,
    result.data.encryptionKey,
    body
  );
  return uploadResult;
};


export const getObjectData = async (userId: string, objectId: string) => {
  const {data, success} = await getDBObject(userId, objectId);
  if (!success) {
    return {success: false};
  }

  const result = await getStorageObject(userId, data.id);
  return {success: true, data: decrypt(fromBuffer(result.data), toBuffer(data.encryptionKey))};
};
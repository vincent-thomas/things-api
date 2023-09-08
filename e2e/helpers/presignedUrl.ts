import request from "supertest";
import app from "@app";
import { z } from "zod";

export const createPresignedUrl = async (authToken: string) => {
  const res = await request(app)
    .post("/drive/object")
    .set("Authorization", `Bearer ${authToken}`)
    .send({
      fileKey: "testing",
      fileType: "txt",
      folderId: "testing"
    });
  const parsed = z
    .object({ url: z.string().url(), expires: z.string() })
    .safeParse(res.body);

  if (parsed.success === false) {
    throw new Error();
  }
  return parsed.data.url;
};

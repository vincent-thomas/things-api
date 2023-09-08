import app from "@app";
import request from "supertest";
import {
  createTestUserAndToken,
  removeTestUser,
  createPresignedUrl
} from "@e2e/helpers";
import { APP_URL } from "@e2e/data/defaults";
import test from "ava";

let authToken: string;
let presignedUrl: string;

const prefix = "drive/object/uploading";

test.before(async () => {
  authToken = await createTestUserAndToken(prefix);
  presignedUrl = (await createPresignedUrl(authToken)).replace(APP_URL, "");
})

test.after(async () => {
  await removeTestUser(prefix);
});

test("Uploading to the presigned Url", async (t) => {
  const res = await request(app)
    .post(presignedUrl)
    .set("Authorization", `Bearer ${authToken}`)
    .send(Buffer.from("Hello world"));
  t.assert(res.status === 201);
});

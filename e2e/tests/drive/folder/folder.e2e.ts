import app from "@app";
import test from "ava";
import request from "supertest";
import { createTestUserAndToken, removeTestUser } from "@e2e/helpers";

let authToken: string;
const prefix = "/drive/folder";

test.before(async () => {
  authToken = await createTestUserAndToken(prefix);
});

test.after(async () => {
  await removeTestUser(prefix);
});

// Jobbar på denna
test.skip("Getting folder", async (t) => {
    const res = await request(app)
      .get("/drive/folder")
      .set("Authorization", `Bearer ${authToken}`);
    t.assert(res.statusCode === 404);
});
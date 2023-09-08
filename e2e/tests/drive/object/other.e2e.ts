import request from "supertest";
import app from "@app";
import test from "ava";
import { createTestUserAndToken, removeTestUser } from "@e2e/helpers";

let authToken: string;

const suffix = "drive/object/other"


test.before(async () => {
  authToken = await createTestUserAndToken(suffix);
});

test.after(async () => {
  removeTestUser(suffix);
});

test("Getting object that doesn't exist", async (t) => {
    const res = await request(app)
      .get("/drive/object/testing_not_existing")
      .set("Authorization", `Bearer ${authToken}`);
    t.assert(res.statusCode === 404);
});

test("Updating object that doesn't exist", async (t) => {
    const res = await request(app)
      .patch("/drive/object/testing_not_existing")
      .set("Authorization", `Bearer ${authToken}`);
    t.assert(res.statusCode === 404);
    t.assert(!!res.body?.error);
});

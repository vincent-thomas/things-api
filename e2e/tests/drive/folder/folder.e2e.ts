import { upsertUser } from "@core/data";
import { createToken } from "@core/hooks";
import app from "@app";
import test from "ava";
import request from "supertest";

let authToken: string;

test.before(async () => {
  await upsertUser({
    email: "test@example.com",
    id: "TEST",
    locale: "en",
    name: "TESTING",
    verified_email: false,
    picture: "https://example.com"
  });
  authToken = createToken("TEST");
});

// Jobbar på denna
test.skip("Getting folder", async (t) => {
    const res = await request(app)
      .get("/drive/folder")
      .set("Authorization", `Bearer ${authToken}`);
    t.assert(res.statusCode === 404);
});

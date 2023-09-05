import { upsertUser } from "@core/data";
import { createToken } from "@core/hooks";
import app from "@app";
import request from "supertest";

let authToken: string;

beforeAll(async () => {
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
test.skip("[WIP] Getting folder", (done) => {
  async function toTest() {
    const res = await request(app)
      .get("/drive/folder")
      .set("Authorization", `Bearer ${authToken}`);
    expect(res.statusCode).toBe(404);
    done();
  }
  toTest();
});

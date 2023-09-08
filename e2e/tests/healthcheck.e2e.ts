import request from "supertest";
import app from "../../app";
import test from "ava";

test("It should response the GET method", async (t) => {
  const response = await request(app)
    .get("/healthcheck");
  t.assert(response.statusCode === 200);
});

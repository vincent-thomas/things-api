import { upsertUser, removeUser } from "../../data/db/repos";
import { createToken } from "../../core/hooks";

export const createTestUserAndToken = async (suffix: string) => {
  await upsertUser({
    email: `test+${suffix}@example.com`,
    id: "TEST-" + suffix,
    locale: "en",
    name: "TESTING",
    verified_email: false,
    picture: "https://example.com"
  });
  return createToken("TEST");
};

export const removeTestUser = (suffix: string) => {
  return removeUser("TEST-" + suffix);
};

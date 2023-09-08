import { Router } from "express";
import { validate } from "@core/middleware";
import { z } from "zod";
import { env } from "@core/env";
import { stringify } from "qs";
import axios from "axios";
import { upsertUser } from "@core/data";
import { createToken } from "@core/hooks";

const googleAuthCallback: Router = Router();

interface Shit {
  src: "web" | "terminal";
  redirect_uri: string;
}

const validator = validate(
  z.object({
    query: z.object({
      code: z.string(),
      state: z.preprocess(
        (string: unknown): Shit => JSON.parse(string as string) as Shit,
        z.object({
          src: z.enum(["web", "terminal"]).optional().default("web"),
          redirect_uri: z.string()
        })
      )
    })
  })
);

interface GoogleTokenResult {
  access_token: string;
  expires_in: number;
  refresh_token: string;
  scope: string;
  id_token: string;
}

async function getGoogleToken(code: string) {
  const url = "https://oauth2.googleapis.com/token";
  const queries = {
    code,
    client_id: env.getEnv("authGoogleId"),
    client_secret: env.getEnv("authGoogleSecret"),
    redirect_uri: "http://localhost:8080/auth/google/callback",
    grant_type: "authorization_code"
  };
  const response = await axios.post<GoogleTokenResult>(
    url,
    stringify(queries),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      }
    }
  );

  return response.data;
}

interface GetGoogleUserInput {
  accessToken: string;
  idToken: string;
}

interface GoogleUserResult {
  id: string;
  email: string;
  verified_email: boolean;
  name: string;
  picture: string;
  locale: string;
}

export async function getGoogleUser(input: GetGoogleUserInput) {
  try {
    const res = await axios.get<GoogleUserResult>(
      `https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=${input.accessToken}`,
      {
        headers: {
          Authorization: `Bearer ${input.idToken}`
        }
      }
    );
    return res.data;
  } catch (error) {
    console.trace(error);
    return null;
  }
}

googleAuthCallback.get("/", validator.input, async (req, res) => {
  const { query } = validator.values(req);
  const { access_token, id_token } = await getGoogleToken(query.code);

  const googleUser = await getGoogleUser({
    accessToken: access_token,
    idToken: id_token
  });

  if (googleUser === null) {
    res.send("error");
    return;
  }

  const user = await upsertUser(googleUser);
  if (user === undefined) {
    console.trace("error");
    return res.send("error");
  }

  const result = createToken(user.id);
  // TODO
  const state = query.state as Shit;
  const { redirect_uri, src } = state;
  if (src === "terminal") {
    return res.send(`Copy this into the terminal!: ${result}`);
  }

  const url = new URL(redirect_uri);
  url.searchParams.set("access_token", result);
  res.redirect(url.toString());
});

export { googleAuthCallback };

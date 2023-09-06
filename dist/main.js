import 'dotenv/config';
import { z } from 'zod';
import express, { Router } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import * as jwt from 'jsonwebtoken';
import { verify, sign } from 'jsonwebtoken';
import { uid } from 'uid/secure';
import { relations, and, eq, isNull } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/mysql2';
import { createPool } from 'mysql2/promise';
import { varchar, mysqlTable, uniqueIndex, binary, boolean, text, timestamp } from 'drizzle-orm/mysql-core';
import { randomUUID, pbkdf2Sync } from 'crypto';
import { toBuffer, fromBuffer, formatTo } from 'bformat';
import { createClient } from 'redis';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { encrypt, decrypt } from 'crypted';
import { URLSearchParams } from 'url';
import { stringify } from 'qs';
import axios from 'axios';

var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var obj = {
  s3Key: "API_S3_KEY",
  s3Secret: "API_S3_SECRET",
  appUrl: "API_APP_URL",
  redisUrl: "API_REDIS_URL",
  signKey: "API_AUTH_SIGN_KEY",
  s3Region: "API_S3_REGION",
  s3AccountId: "API_S3_ACCOUNT_ID",
  s3Bucket: "API_S3_BUCKET",
  databaseUrl: "API_DATABASE_URL",
  authGoogleId: "API_GOOGLE_OAUTH_ID",
  authGoogleSecret: "API_GOOGLE_OAUTH_SECRET",
  masterEncKey: "API_ENCRYPTION_MASTER_KEY"
};
var schemaKeys = {
  API_S3_KEY: z.string(),
  API_S3_SECRET: z.string(),
  API_APP_URL: z.string().url("API_APP_URL must be a valid URL"),
  API_REDIS_URL: z.string().url("API_APP_URL must be a valid URL"),
  API_AUTH_SIGN_KEY: z.string(),
  API_S3_REGION: z.string(),
  API_S3_ACCOUNT_ID: z.string(),
  API_S3_BUCKET: z.string(),
  API_DATABASE_URL: z.string(),
  API_GOOGLE_OAUTH_SECRET: z.string(),
  API_GOOGLE_OAUTH_ID: z.string(),
  API_ENCRYPTION_MASTER_KEY: z.string()
};
var schema = z.object(schemaKeys);
var EnvValidator = class {
  constructor(environment) {
    this.environment = environment;
    this.#unvalidatedValues = environment;
  }
  #unvalidatedValues;
  validate() {
    schema.parse(this.#unvalidatedValues);
  }
  getEnv(variable) {
    return schema.parse(this.#unvalidatedValues)[obj[variable]];
  }
};
var env = new EnvValidator(process.env);

// core/http/public_api.ts
var sendResult = (res, payload, status = 200 /* OK */) => {
  res.status(status).json(payload);
};

// core/senders/error.ts
var errorSender = ({ errors, status }) => {
  if (status > 451 && status < 500 || status > 511) {
    throw new Error("Error code doesn't exist");
  } else if (status < 400) {
    throw new Error("Not an error code");
  }
  return {
    success: false,
    data: [],
    errors,
    _sendMeta: {
      status
    }
  };
};
var sender = (res, sender2) => {
  const { status } = sender2._sendMeta;
  const requestId = uid(16);
  res.status(status).json({
    data: sender2.data,
    errors: sender2.errors,
    success: sender2.success,
    timestamp: (/* @__PURE__ */ new Date()).getTime(),
    requestId
  });
  console.info(
    `status=${res.statusCode} requestId=${requestId} path=${res.req.baseUrl}`
  );
};

// core/middleware/authorize.ts
var getAuthorizationValues = (authHeaderValue) => {
  const [type, token] = authHeaderValue.split(" ");
  return [type, token];
};
var ifNotAuthorized = (res) => sender(
  res,
  errorSender({
    errors: [
      {
        cause: "UNAUTHORIZED_ERROR" /* UNAUTHORIZED_ERROR */,
        message: "You are not authorized to perform this action"
      }
    ],
    status: 401
  })
);
var authorize = (req, res, next) => {
  if (!req.headers?.authorization) {
    return ifNotAuthorized(res);
  }
  const [type, value] = getAuthorizationValues(req.headers?.authorization);
  if (type.toLowerCase() !== "bearer") {
    return ifNotAuthorized(res);
  }
  const validToken = jwt.verify(value, env.getEnv("signKey"));
  if (validToken?.exp === void 0) {
    return ifNotAuthorized(res);
  }
  next();
};

// core/middleware/validateInput.ts
var validateZodError = (error) => {
  if (error.name === "ZodError") {
    const customErrors = error.issues.map((v) => ({
      type: "INVALID_INPUT",
      reason: v.message,
      where: v.path[0],
      value: v.path[1]
    }));
    return customErrors;
  } else
    return error;
};
var validate = (schema2) => ({
  input: (req, res, next) => {
    const { body, params, query, headers } = req;
    const isValid = schema2.safeParse({ body, params, query, headers });
    if (!isValid.success) {
      res.status(400).json({
        error: validateZodError(isValid.error)
      });
    } else
      next();
  },
  values: (req) => {
    const { body, params, query, headers } = req;
    return schema2.parse({ body, params, query, headers });
  }
});
var getToken = (req, shouldUseCookies = false) => {
  const authHeader = req.headers?.authorization;
  const token = authHeader?.split(" ")[1];
  if (!token && shouldUseCookies) {
    const token2 = req.cookies.access_token;
    return validateToken(token2);
  } else {
    const headerToken = validateToken(token);
    return headerToken;
  }
};
var validateToken = (token) => {
  try {
    const value = verify(token, env.getEnv("signKey"));
    return value;
  } catch (e) {
    return null;
  }
};
var createToken = (userId2) => {
  const result = sign(
    {
      sub: userId2
    },
    env.getEnv("signKey"),
    {
      algorithm: "HS256",
      expiresIn: 86400,
      issuer: "https://things-api.v-thomas.com",
      noTimestamp: false
    }
  );
  return result;
};

// data/db/schema/index.ts
var schema_exports = {};
__export(schema_exports, {
  file: () => file,
  fileRelation: () => fileRelation,
  fileType: () => fileType,
  folder: () => folder,
  folderRelation: () => folderRelation,
  user: () => user
});
var createdAt = (name) => timestamp(name).defaultNow().notNull();
var userId = (columnName) => varchar(columnName, { length: 36 }).notNull();
var id = varchar("id", { length: 36 }).primaryKey().$defaultFn(() => randomUUID());

// data/db/schema/drive.ts
var fileType = varchar("fileType", { length: 3 }).notNull();
var folder = mysqlTable(
  "folders",
  {
    id,
    folderName: varchar("folderName", { length: 36 }).notNull(),
    ownedById: userId("ownedById"),
    parentFolderId: varchar("parentFolderId", { length: 36 }),
    createdAt: createdAt("created_at")
  },
  (folder3) => ({
    nameIndex: uniqueIndex("folder_name").on(
      folder3.folderName,
      folder3.parentFolderId
    )
  })
);
var folderRelation = relations(folder, ({ one, many }) => ({
  folders: many(folder, { relationName: "child_folder" }),
  parentFolder: one(folder, {
    fields: [folder.parentFolderId],
    references: [folder.id],
    relationName: "child_folder"
  }),
  files: many(file)
}));
var file = mysqlTable("files", {
  id,
  filename: varchar("filename", { length: 36 }).notNull(),
  fileType,
  encryptionKey: binary("encryptionKey", {
    length: 32
  }).notNull(),
  parentFolderId: varchar("parentFolderId", { length: 36 }),
  createdAt: createdAt("created_at")
});
var fileRelation = relations(file, ({ one }) => ({
  parentFolder: one(folder, {
    fields: [file.parentFolderId],
    references: [folder.id]
  })
}));
var user = mysqlTable("users", {
  id: userId("id").primaryKey(),
  email: varchar("email", { length: 254 }).unique().notNull(),
  verified_email: boolean("verified_email").notNull().default(false),
  name: text("name").notNull(),
  picture: text("picture"),
  locale: text("locale"),
  updatedAt: createdAt("updated_at"),
  createdAt: createdAt("created_at")
});

// data/db/client.ts
var connection = createPool({
  uri: env.getEnv("databaseUrl")
});
var db = drizzle(connection, { schema: schema_exports, mode: "default" });
var getFolder = async (userId2, folderId) => {
  let theFolderId;
  if (folderId === void 0) {
    const result = await db.query.folder.findFirst({
      where: and(eq(folder.ownedById, userId2), isNull(folder.parentFolderId))
    });
    if (!result) {
      return null;
    }
    theFolderId = result.id;
  } else {
    theFolderId = folderId;
  }
  return await db.query.folder.findFirst({
    where: and(eq(folder.id, theFolderId), eq(folder.ownedById, userId2))
  }) || null;
};
var getDBObject = async (userId2, objectId) => {
  const result = await db.query.file.findFirst({
    where: eq(file.id, objectId),
    with: {
      parentFolder: {
        columns: {
          ownedById: true
        }
      }
    }
  });
  if (!result || result?.parentFolder === null || result.parentFolder.ownedById !== userId2) {
    return { success: false, data: null };
  }
  const { parentFolder, ...toReturn } = result;
  return { success: true, data: toReturn };
};
var createDBObject = async (meta, data) => {
  const parent = await db.query.folder.findFirst({
    where: eq(folder.id, meta.folderId)
  });
  if (!parent) {
    return { success: false, error: "FOLDER_DOESNT_EXIST" };
  }
  const id2 = randomUUID();
  const encryptionKey = pbkdf2Sync(
    toBuffer(`${env.getEnv("masterEncKey")}${meta.userId}${id2}`, "utf-8"),
    toBuffer(uid(16), "utf-8"),
    1e5,
    32,
    "sha512"
  );
  const storableEncKey = fromBuffer(encryptionKey);
  await db.insert(file).values({
    ...data,
    parentFolderId: meta.folderId,
    encryptionKey: storableEncKey
  });
  return { success: true, data: { objectId: id2, encryptionKey } };
};
var updateDBObject = async (objectId, { fileKey }) => {
  try {
    await db.update(file).set({
      filename: fileKey
    }).where(eq(file.id, objectId));
    return { success: true };
  } catch (e) {
    const error = e;
    if (error.message === "No values to set") {
      return { success: false, error: "NO_VALUES_TO_SET" };
    }
    console.trace(e);
    return { success: false, error: "Unknown" };
  }
};
var redis = createClient({
  url: env.getEnv("redisUrl")
});
redis.connect();

// data/db/repos/user.ts
var ONE_WEEK_IN_SECONDS = 604800;
var upsertUser = async (data) => {
  const existingUser = await db.query.user.findFirst({
    where: eq(user.id, data.id)
  });
  if (existingUser)
    return existingUser;
  await db.insert(user).values({ ...data, createdAt: /* @__PURE__ */ new Date() });
  const newUser = await db.query.user.findFirst({
    where: eq(user.id, data.id)
  });
  await redis.json.set(`user-data:${newUser.id}`, ".", newUser);
  await redis.expire(`user-data:${newUser.id}`, ONE_WEEK_IN_SECONDS);
  return newUser;
};
var getUser = async (userId2) => {
  const maybeFast = await redis.json.get(`user-data:${userId2}`);
  if (maybeFast !== null) {
    return maybeFast;
  }
  const userFromDb = await db.query.user.findFirst({
    where: eq(user.id, userId2)
  });
  if (userFromDb === void 0) {
    return null;
  }
  await redis.json.set(`user-data:${userFromDb.id}`, ".", userFromDb);
  await redis.expire(`user-data:${userFromDb.id}`, ONE_WEEK_IN_SECONDS);
  return userFromDb;
};
var s3 = new S3Client({
  endpoint: `https://${env.getEnv("s3AccountId")}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: env.getEnv("s3Key"),
    secretAccessKey: env.getEnv("s3Secret")
  }
});
var uploadObject = async (userId2, objectId, encryptionKey, Body) => {
  const toSend = encrypt(fromBuffer(Body), encryptionKey);
  try {
    const command = new PutObjectCommand({
      Bucket: env.getEnv("s3Bucket"),
      Key: `${userId2}/drive/${objectId}`,
      Body: toSend
    });
    await s3.send(command);
    return { success: true };
  } catch (e) {
    console.trace(e);
    return { success: false };
  }
};

// app/modules/drive/routes/folder.ts
var folder2 = Router();
var { input: getFoldersBalidator, values: getFolderValues } = validate(
  z.object({
    query: z.object({
      folders: z.string().optional().default("false"),
      files: z.string().optional().default("false")
    }),
    params: z.object({
      folderId: z.string().optional()
    })
  })
);
folder2.get("/:folderId?", authorize, getFoldersBalidator, async (req, res) => {
  const { query, params } = getFolderValues(req);
  const token = getToken(req);
  const result = await getFolder(token.sub, params.folderId);
  if (result === null) {
    return sendResult(
      res,
      { error: "Folder not found" },
      404 /* NOT_FOUND */
    );
  }
  sendResult(res, result, 200 /* OK */);
});
var { input: createFolderValidator, values: getFolderInputValues } = validate(
  z.object({
    body: z.object({
      folderKey: z.string().min(1, "Folder-name cannot be less than 1 character").max(10, "Folder-name cannot be more than 10 character"),
      parentFolderId: z.string().optional()
    })
  })
);
folder2.post("/", authorize, createFolderValidator, async (req, res) => {
  getFolderInputValues(req);
  getToken(req);
  sendResult(res, { todo: true });
});
var seperator = "$";
var presigned = (schema2) => ({
  createPayload: (data, validSeconds) => {
    const dataToSign = JSON.stringify(schema2.parse(data));
    const dataBase64 = formatTo(dataToSign, "utf-8", "base64");
    const signed = encrypt(
      `${dataToSign}${seperator}${dataBase64}${seperator}${( new Date()).getTime() + validSeconds * 1e3}`,
      toBuffer(env.getEnv("masterEncKey"), "base64")
    );
    return signed;
  },
  validate: (data) => {
    const deCryptData = decrypt(
      data,
      toBuffer(env.getEnv("masterEncKey"), "base64")
    );
    const [rawData, base64Data, validUntil] = deCryptData.split(seperator);
    const hasntBenChanged = rawData === formatTo(base64Data, "base64", "utf-8");
    const isValid = parseInt(validUntil) > (/* @__PURE__ */ new Date()).getTime();
    if (!hasntBenChanged || !isValid) {
      return { success: false };
    }
    return { data: schema2.parse(JSON.parse(rawData)), success: true };
  }
});

// app/modules/drive/lib/object.ts
var createObject = async (folderId, userId2, meta, body) => {
  const result = await createDBObject(
    {
      folderId,
      userId: userId2
    },
    meta
  );
  if (!result.success || !result.data?.objectId) {
    return { success: false };
  }
  const uploadResult = await uploadObject(
    userId2,
    result.data.objectId,
    result.data.encryptionKey,
    body
  );
  return uploadResult;
};

// app/modules/drive/routes/file.ts
var file2 = Router();
var { input: getFileValidator, values: getFileValues } = validate(
  z.object({
    params: z.object({
      fileId: z.string()
    })
  })
);
file2.get("/:fileId", authorize, getFileValidator, async (req, res) => {
  const user2 = getToken(req);
  const { params } = getFileValues(req);
  const { success, data } = await getDBObject(user2.sub, params.fileId);
  if (!success) {
    return res.status(404).json({ error: "DOESNT EXIST", data: null });
  }
  sendResult(res, data, 200 /* OK */);
});
var presignedSchema = z.object({
  fileKey: z.string(),
  fileType: z.string().min(2).max(4),
  folderId: z.string()
});
var { input: createFileValidator, values: getFileInput } = validate(
  z.object({
    body: presignedSchema
  })
);
var { createPayload: createSign, validate: validateSign } = presigned(presignedSchema);
file2.post("/", authorize, createFileValidator, async (req, res) => {
  const { body } = getFileInput(req);
  const payload = createSign(body, 300);
  sendResult(
    res,
    {
      url: `${env.getEnv("appUrl")}/drive/object/objectUpload/${payload}`,
      expires: "5m"
    },
    201 /* CREATED */
  );
});
var { input: validatorThis, values: theValues } = validate(
  z.object({
    params: z.object({
      data: z.string()
    })
  })
);
var readBodyAsBuffer = (req) => {
  return new Promise((resolve, reject) => {
    const body = [];
    req.on("data", (chunk) => {
      body.push(chunk);
    });
    req.on("end", () => {
      resolve(Buffer.concat(body));
    });
    req.on("error", (err) => {
      reject(err);
    });
  });
};
file2.post("/objectUpload/:data", validatorThis, async (req, res) => {
  const {
    params: { data: values }
  } = theValues(req);
  const { data: fileMeta, success } = validateSign(values);
  if (!success || !fileMeta) {
    return res.json({ error: "Link not valid" });
  }
  const user2 = getToken(req, true);
  const theBody = await readBodyAsBuffer(req);
  const result = await createObject(
    fileMeta.folderId,
    user2.sub,
    {
      filename: fileMeta.fileKey,
      fileType: fileMeta.fileType
    },
    theBody
  );
  if (result) {
    sendResult(res, void 0, 201 /* CREATED */);
  } else {
    res.status(500).json({ error: "Something went wrong" });
  }
});
var { input: updateFileInput, values: updateFileValues } = validate(
  z.object({
    params: z.object({
      fileId: z.string()
    }),
    body: z.object({
      fileKey: z.string().optional()
    })
  })
);
file2.patch("/:fileId", authorize, updateFileInput, async (req, res) => {
  const { params, body } = updateFileValues(req);
  const { success, error } = await updateDBObject(params.fileId, {
    fileKey: body.fileKey
  });
  if (!success) {
    return res.status(404).json({ error });
  }
  sendResult(res, { success: true, message: ":(" });
});

// app/modules/drive/index.ts
var driveRouter = Router();
driveRouter.use("/folder", folder2);
driveRouter.use("/object", file2);
var drive_default = driveRouter;
var authorizeV1 = Router();
var validator = validate(
  z.object({
    query: z.object({
      redirect_uri: z.string(),
      src: z.enum(["web", "terminal"]).optional().default("web"),
      cookie: z.enum(["true", "false"]).optional()
    })
  })
);
var options = {
  redirect_uri: "http://localhost:8080/auth/google/callback",
  client_id: env.getEnv("authGoogleId"),
  access_type: "offline",
  response_type: "code",
  prompt: "consent",
  scope: [
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email"
  ].join(" ")
};
var googleAuthUrl = "https://accounts.google.com/o/oauth2/v2/auth";
authorizeV1.get("/", validator.input, async (req, res) => {
  const { query } = validator.values(req);
  const token = getToken(req, true);
  if (token === null) {
    options.state = JSON.stringify(query);
    const qs = new URLSearchParams(options);
    return res.redirect(`${googleAuthUrl}?${qs.toString()}`);
  }
  res.send(token);
});
var googleAuthCallback = Router();
var validator2 = validate(
  z.object({
    query: z.object({
      code: z.string(),
      state: z.preprocess(
        (string) => JSON.parse(string),
        z.object({
          src: z.enum(["web", "terminal"]).optional().default("web"),
          redirect_uri: z.string()
        })
      )
    })
  })
);
async function getGoogleToken(code) {
  const url = "https://oauth2.googleapis.com/token";
  const queries = {
    code,
    client_id: env.getEnv("authGoogleId"),
    client_secret: env.getEnv("authGoogleSecret"),
    redirect_uri: "http://localhost:8080/auth/google/callback",
    grant_type: "authorization_code"
  };
  const response = await axios.post(
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
async function getGoogleUser(input) {
  try {
    const res = await axios.get(
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
googleAuthCallback.get("/", validator2.input, async (req, res) => {
  const { query } = validator2.values(req);
  const { access_token, id_token } = await getGoogleToken(query.code);
  const googleUser = await getGoogleUser({
    accessToken: access_token,
    idToken: id_token
  });
  if (googleUser === null) {
    res.send("error");
    return;
  }
  const user2 = await upsertUser(googleUser);
  if (user2 === void 0) {
    console.trace("error");
    return res.send("error");
  }
  const result = createToken(user2.id);
  const state = query.state;
  const { redirect_uri, src } = state;
  if (src === "terminal") {
    return res.send(`Copy this into the terminal!: ${result}`);
  }
  const url = new URL(redirect_uri);
  url.searchParams.set("access_token", result);
  res.redirect(url.toString());
});
var userRouter = Router();
userRouter.get("/", async (req, res) => {
  const token = getToken(req, true);
  if (token === null) {
    res.json({ error: "No token" });
    return;
  }
  const user2 = await getUser(token.sub);
  res.json(user2);
});
userRouter.get("/picture", async (req, res) => {
  const token = getToken(req, true);
  if (token === null) {
    res.json({ error: "No token" });
    return;
  }
  const user2 = await getUser(token.sub);
  if (user2 === null) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  if (user2.picture === null) {
    return res.status(404).json({ error: "No Picture" });
  }
  const pic = await axios.get(user2.picture, { responseType: "arraybuffer" });
  const imageBuffer = Buffer.from(pic.data, "binary");
  res.contentType("image/jpeg");
  res.end(imageBuffer);
});

// app/modules/auth/index.ts
var auth_default = Router().use("/google/authorize", authorizeV1).use("/google/callback", googleAuthCallback).use("/user", userRouter);

// app/app.ts
var app = express();
app.use(
  helmet(),
  cors(),
  cookieParser(),
  (_req, res, next) => {
    res.setHeader("X-Powered-By", "Things");
    next();
  },
  express.json()
);
app.get("/healthcheck", (req, res) => {
  res.status(200).send({ status: "up", code: 200 });
});
app.use("/drive", drive_default);
app.use("/auth", auth_default);
var app_default = app;

// app/main.ts
async function bootstrap() {
  const port = process.env.PORT || 8080;
  const server = app_default.listen(port, () => {
    console.info(`Api started at: http://localhost:${port}`);
  });
  server.on("error", console.error);
}
new EnvValidator(process.env).validate();
bootstrap();

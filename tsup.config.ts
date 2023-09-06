import { Options } from "tsup";
import { resolve } from "node:path";

export default {
  tsconfig: "tsconfig.json",
  clean: true,
  treeshake: true,
  format: "esm",
  entryPoints: ["./app/main.ts"],
  outDir: resolve("dist")
} as Options;

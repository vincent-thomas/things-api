import { Options } from "tsup";
import { resolve } from "node:path";

export default {
  tsconfig: "tsconfig.json",
  clean: true,
  treeshake: true,
  format: "esm",
  entryPoints: ["./main.ts"],
  outDir: resolve(".things/dist"),
  silent: true
} as Options;

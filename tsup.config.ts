import { Options } from "tsup";
import packageJson from "./package.json";
import { copyFileSync, writeFileSync } from "fs";
import { resolve } from "path";

const OUTPUT_PATH = resolve("dist");

export default {
  tsconfig: "tsconfig.json",
  clean: true,
  noExternal: ["@things/format", "@things/crypto"],
  treeshake: true,
  format: ["cjs"],
  entryPoints: ["./app/main.ts"],
  outDir: OUTPUT_PATH,
  onSuccess: () => {
    const withOut = { ...packageJson, dependencies: {} };
    for (const dep in packageJson.dependencies) {
      if (packageJson.dependencies[dep] !== "workspace:*") {
        withOut.dependencies[dep] = packageJson.dependencies[dep];
      }
    }
    writeFileSync(
      `${OUTPUT_PATH}/package.json`,
      JSON.stringify(withOut, null, 2)
    );
    copyFileSync("./Dockerfile", `${OUTPUT_PATH}/Dockerfile`);
  }
} as Options;

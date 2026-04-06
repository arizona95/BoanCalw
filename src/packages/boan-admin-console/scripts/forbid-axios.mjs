import fs from "node:fs";
import path from "node:path";

const packageJsonPath = path.resolve(process.cwd(), "package.json");
const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf8"));

const dependencySections = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
];

for (const section of dependencySections) {
  const deps = packageJson[section] || {};
  if (Object.prototype.hasOwnProperty.call(deps, "axios")) {
    console.error("axios is forbidden in boan-admin-console. Use fetch or existing helpers instead.");
    process.exit(1);
  }
}

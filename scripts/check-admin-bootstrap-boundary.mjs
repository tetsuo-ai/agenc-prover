import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import process from "node:process";

const repoRoot = path.resolve(import.meta.dirname, "..");
const adminToolsDir = path.join(repoRoot, "admin-tools");

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

if (!existsSync(adminToolsDir)) {
  fail(`admin-tools directory is missing: ${adminToolsDir}`);
}

const forbiddenFiles = [
  "verifier-localnet.ts",
  "benchmark-private-e2e.mts",
  "benchmark-private-e2e-cli.ts",
  "benchmark-private-e2e-artifact.ts",
];

for (const file of forbiddenFiles) {
  const filePath = path.join(adminToolsDir, file);
  if (existsSync(filePath)) {
    fail(`forbidden shared proof-harness file present in admin-tools: ${file}`);
  }
}

const forbiddenPatterns = [
  "scripts/setup-verifier-localnet",
  "scripts/run-e2e-zk-local",
  "scripts/agenc-localnet-soak-launch",
  "scripts/idl/",
  "verifier-localnet",
  "benchmark-private-e2e",
];

const allowedFiles = readdirSync(adminToolsDir).filter((entry) => {
  return (
    entry.endsWith(".ts") ||
    entry.endsWith(".mts") ||
    entry === "package.json" ||
    entry === "package-lock.json" ||
    entry === "tsconfig.json"
  );
});

for (const file of allowedFiles) {
  const filePath = path.join(adminToolsDir, file);
  const contents = readFileSync(filePath, "utf8");
  for (const pattern of forbiddenPatterns) {
    if (contents.includes(pattern)) {
      fail(`forbidden proof-harness reference "${pattern}" found in admin-tools/${file}`);
    }
  }
}

const packageJson = JSON.parse(
  readFileSync(path.join(adminToolsDir, "package.json"), "utf8"),
);

if ("benchmark:e2e" in (packageJson.scripts ?? {})) {
  fail("admin-tools package must not expose benchmark:e2e");
}

if ("verifier:localnet" in (packageJson.scripts ?? {})) {
  fail("admin-tools package must not expose verifier:localnet");
}

process.stdout.write("admin bootstrap boundary check passed\n");

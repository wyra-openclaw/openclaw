#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..");
const uiDir = path.join(repoRoot, "ui");

const WINDOWS_SHELL_EXTENSIONS = new Set([".cmd", ".bat", ".com"]);
const WINDOWS_UNSAFE_SHELL_ARG_PATTERN = /[\r\n"&|<>^%!]/;
const DEFAULT_UI_ENV_SECRET_NAME = "wyra-api-new-dev";
const DEFAULT_UI_SECRET_PROVIDER = "auto";

function usage() {
  // keep this tiny; it's invoked from npm scripts too
  process.stderr.write("Usage: node scripts/ui.js <install|dev|build|test> [...args]\n");
}

function which(cmd) {
  try {
    const key = process.platform === "win32" ? "Path" : "PATH";
    const paths = (process.env[key] ?? process.env.PATH ?? "")
      .split(path.delimiter)
      .filter(Boolean);
    const extensions =
      process.platform === "win32"
        ? (process.env.PATHEXT ?? ".EXE;.CMD;.BAT;.COM").split(";").filter(Boolean)
        : [""];
    for (const entry of paths) {
      for (const ext of extensions) {
        const candidate = path.join(entry, process.platform === "win32" ? `${cmd}${ext}` : cmd);
        try {
          if (fs.existsSync(candidate)) {
            return candidate;
          }
        } catch {
          // ignore
        }
      }
    }
  } catch {
    // ignore
  }
  return null;
}

function resolveRunner() {
  const pnpm = which("pnpm");
  if (pnpm) {
    return { cmd: pnpm, kind: "pnpm" };
  }
  return null;
}

export function shouldUseShellForCommand(cmd, platform = process.platform) {
  if (platform !== "win32") {
    return false;
  }
  const extension = path.extname(cmd).toLowerCase();
  return WINDOWS_SHELL_EXTENSIONS.has(extension);
}

export function assertSafeWindowsShellArgs(args, platform = process.platform) {
  if (platform !== "win32") {
    return;
  }
  const unsafeArg = args.find((arg) => WINDOWS_UNSAFE_SHELL_ARG_PATTERN.test(arg));
  if (!unsafeArg) {
    return;
  }
  // SECURITY: `shell: true` routes through cmd.exe; reject risky metacharacters
  // in forwarded args to prevent shell control-flow/env-expansion injection.
  throw new Error(
    `Unsafe Windows shell argument: ${unsafeArg}. Remove shell metacharacters (" & | < > ^ % !).`,
  );
}

function createSpawnOptions(cmd, args, envOverride) {
  const useShell = shouldUseShellForCommand(cmd);
  if (useShell) {
    assertSafeWindowsShellArgs(args);
  }
  return {
    cwd: uiDir,
    stdio: "inherit",
    env: envOverride ?? process.env,
    ...(useShell ? { shell: true } : {}),
  };
}

function run(cmd, args) {
  const envForRun = resolveUiEnv(actionFromArgs(args));
  let child;
  try {
    child = spawn(cmd, args, createSpawnOptions(cmd, args, envForRun));
  } catch (err) {
    console.error(`Failed to launch ${cmd}:`, err);
    process.exit(1);
    return;
  }

  child.on("error", (err) => {
    console.error(`Failed to launch ${cmd}:`, err);
    process.exit(1);
  });
  child.on("exit", (code) => {
    if (code !== 0) {
      process.exit(code ?? 1);
    }
  });
}

function runSync(cmd, args, envOverride) {
  let result;
  try {
    result = spawnSync(cmd, args, createSpawnOptions(cmd, args, envOverride));
  } catch (err) {
    console.error(`Failed to launch ${cmd}:`, err);
    process.exit(1);
    return;
  }
  if (result.signal) {
    process.exit(1);
  }
  if ((result.status ?? 1) !== 0) {
    process.exit(result.status ?? 1);
  }
}

function actionFromArgs(args) {
  if (args.length < 2) {
    return null;
  }
  if (args[0] !== "run") {
    return null;
  }
  return args[1] ?? null;
}

function readGcpSecretValue(secretName) {
  const gcloud = which("gcloud");
  if (!gcloud) {
    return {
      value: null,
      error: "Missing gcloud CLI. Install gcloud and authenticate before running UI.",
      provider: "gcp",
    };
  }
  const result = spawnSync(
    gcloud,
    ["secrets", "versions", "access", "latest", `--secret=${secretName}`],
    {
      cwd: uiDir,
      stdio: ["ignore", "pipe", "pipe"],
      env: process.env,
      encoding: "utf8",
    },
  );
  if ((result.status ?? 1) !== 0) {
    const stderr = typeof result.stderr === "string" ? result.stderr.trim() : "";
    return {
      value: null,
      error: `Failed reading secret '${secretName}' from Secret Manager.${stderr ? ` ${stderr}` : ""}`,
      provider: "gcp",
    };
  }
  const secret = typeof result.stdout === "string" ? result.stdout.trim() : "";
  if (!secret) {
    return {
      value: null,
      error: `Secret '${secretName}' is empty.`,
      provider: "gcp",
    };
  }
  return {
    value: secret,
    error: null,
    provider: "gcp",
  };
}

function readAwsSecretValue(secretName) {
  const aws = which("aws");
  if (!aws) {
    return {
      value: null,
      error: "Missing aws CLI. Install AWS CLI and authenticate before running UI.",
      provider: "aws",
    };
  }
  const region = process.env.AWS_REGION?.trim() || process.env.AWS_DEFAULT_REGION?.trim() || "";
  const args = [
    "secretsmanager",
    "get-secret-value",
    "--secret-id",
    secretName,
    "--query",
    "SecretString",
    "--output",
    "text",
  ];
  if (region) {
    args.push("--region", region);
  }
  const result = spawnSync(aws, args, {
    cwd: uiDir,
    stdio: ["ignore", "pipe", "pipe"],
    env: process.env,
    encoding: "utf8",
  });
  if ((result.status ?? 1) !== 0) {
    const stderr = typeof result.stderr === "string" ? result.stderr.trim() : "";
    return {
      value: null,
      error: `Failed reading secret '${secretName}' from AWS Secrets Manager.${stderr ? ` ${stderr}` : ""}`,
      provider: "aws",
    };
  }
  const secret = typeof result.stdout === "string" ? result.stdout.trim() : "";
  if (!secret || secret === "None") {
    return {
      value: null,
      error: `Secret '${secretName}' is empty or has no SecretString value.`,
      provider: "aws",
    };
  }
  return {
    value: secret,
    error: null,
    provider: "aws",
  };
}

function readSecretValue(secretName) {
  const provider = process.env.OPENCLAW_UI_SECRET_PROVIDER?.trim() || DEFAULT_UI_SECRET_PROVIDER;
  if (provider === "aws") {
    return readAwsSecretValue(secretName);
  }
  if (provider === "gcp") {
    return readGcpSecretValue(secretName);
  }
  // auto mode: prefer AWS if available, otherwise try GCP.
  if (which("aws")) {
    return readAwsSecretValue(secretName);
  }
  if (which("gcloud")) {
    return readGcpSecretValue(secretName);
  }
  return {
    value: null,
    error:
      "Missing secret manager CLI. Install AWS CLI (preferred) or gcloud CLI, then authenticate before running UI.",
    provider: "auto",
  };
}

function parseDotenvLikeSecret(rawSecret) {
  const parsed = {};
  const lines = rawSecret.split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }
    const equalsIndex = line.indexOf("=");
    if (equalsIndex <= 0) {
      continue;
    }
    const key = line.slice(0, equalsIndex).trim();
    const value = line.slice(equalsIndex + 1).trim();
    if (!key.startsWith("VITE_")) {
      continue;
    }
    parsed[key] = value;
  }
  return parsed;
}

function parseJsonSecret(rawSecret) {
  try {
    const parsed = JSON.parse(rawSecret);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return null;
    }
    const out = {};
    for (const [key, value] of Object.entries(parsed)) {
      if (!key.startsWith("VITE_")) {
        continue;
      }
      if (value == null) {
        continue;
      }
      out[key] = String(value).trim();
    }
    return out;
  } catch {
    return null;
  }
}

function parseUiSecretPayload(rawSecret) {
  const jsonParsed = parseJsonSecret(rawSecret);
  if (jsonParsed && Object.keys(jsonParsed).length > 0) {
    return jsonParsed;
  }
  const dotenvParsed = parseDotenvLikeSecret(rawSecret);
  if (Object.keys(dotenvParsed).length > 0) {
    return dotenvParsed;
  }
  // Backward compatibility: if secret is only the token value.
  return { VITE_GATEWAY_TOKEN: rawSecret.trim() };
}

function resolveUiEnv(action) {
  const needsUiSecrets = action === "dev" || action === "build" || action === "test";
  if (!needsUiSecrets) {
    return process.env;
  }
  const logSecretValues = process.env.OPENCLAW_UI_LOG_SECRET_VALUES?.trim() === "1";
  const existingViteKeys = Object.keys(process.env)
    .filter((key) => key.startsWith("VITE_") && String(process.env[key] ?? "").trim())
    .sort();
  if (existingViteKeys.length > 0) {
    console.log(
      `[ui] using ${existingViteKeys.length} VITE_* key(s) from process env: ${existingViteKeys.join(", ")}`,
    );
    if (logSecretValues) {
      const values = Object.fromEntries(existingViteKeys.map((key) => [key, String(process.env[key])]));
      console.log("[ui] VITE_* values from process env", values);
    }
    return process.env;
  }

  const strictSecretLoading = process.env.OPENCLAW_UI_ENV_REQUIRED?.trim() === "1";
  const secretName = process.env.OPENCLAW_UI_ENV_SECRET_NAME?.trim() || DEFAULT_UI_ENV_SECRET_NAME;
  const secretResult = readSecretValue(secretName);
  if (!secretResult.value) {
    if (strictSecretLoading) {
      throw new Error(secretResult.error ?? "Failed loading UI secrets from Secret Manager.");
    }
    console.warn(
      `[ui] ${secretResult.error ?? "Failed loading UI secrets from Secret Manager."} Continuing without Secret Manager keys.`,
    );
    return process.env;
  }
  const secretPayload = secretResult.value;
  const parsedSecrets = parseUiSecretPayload(secretPayload);
  if (Object.keys(parsedSecrets).length === 0) {
    const message = `Secret '${secretName}' must contain at least one VITE_* key (JSON or KEY=VALUE format).`;
    if (strictSecretLoading) {
      throw new Error(message);
    }
    console.warn(`[ui] ${message} Continuing without Secret Manager keys.`);
    return process.env;
  }
  const loadedKeys = Object.keys(parsedSecrets).sort();
  console.log(
    `[ui] loaded ${loadedKeys.length} VITE_* key(s) from ${secretResult.provider ?? "secret manager"} secret '${secretName}': ${loadedKeys.join(", ")}`,
  );
  if (logSecretValues) {
    console.log(
      `[ui] VITE_* values from ${secretResult.provider ?? "secret manager"} secret '${secretName}'`,
      parsedSecrets,
    );
  }
  return {
    ...process.env,
    ...parsedSecrets,
  };
}

function depsInstalled(kind) {
  try {
    const require = createRequire(path.join(uiDir, "package.json"));
    require.resolve("vite");
    require.resolve("dompurify");
    if (kind === "test") {
      require.resolve("vitest");
      require.resolve("@vitest/browser-playwright");
      require.resolve("playwright");
    }
    return true;
  } catch {
    return false;
  }
}

function resolveScriptAction(action) {
  if (action === "install") {
    return null;
  }
  if (action === "dev") {
    return "dev";
  }
  if (action === "build") {
    return "build";
  }
  if (action === "test") {
    return "test";
  }
  return null;
}

export function main(argv = process.argv.slice(2)) {
  const [action, ...rest] = argv;
  if (!action) {
    usage();
    process.exit(2);
  }

  const runner = resolveRunner();
  if (!runner) {
    process.stderr.write("Missing UI runner: install pnpm, then retry.\n");
    process.exit(1);
  }

  const script = resolveScriptAction(action);
  if (action !== "install" && !script) {
    usage();
    process.exit(2);
  }

  if (action === "install") {
    run(runner.cmd, ["install", ...rest]);
    return;
  }

  if (!depsInstalled(action === "test" ? "test" : "build")) {
    const installEnv =
      action === "build" ? { ...process.env, NODE_ENV: "production" } : process.env;
    const installArgs = action === "build" ? ["install", "--prod"] : ["install"];
    runSync(runner.cmd, installArgs, installEnv);
  }

  run(runner.cmd, ["run", script, ...rest]);
}

const isDirectExecution = (() => {
  const entry = process.argv[1];
  return Boolean(entry && path.resolve(entry) === fileURLToPath(import.meta.url));
})();

if (isDirectExecution) {
  main();
}

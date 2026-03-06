import { CognitoIdentityProviderClient } from "@aws-sdk/client-cognito-identity-provider";

type RuntimeApiConfig = {
  region?: string;
  userPoolId?: string;
  clientId?: string;
  gatewayToken?: string;
};

const LOCAL_RUNTIME_CONFIG_URL = "https://api-backend.eficensittest.com/api/config";

function readRuntimeApiConfig(): RuntimeApiConfig {
  if (typeof window === "undefined") {
    return {};
  }
  const cfg = (
    window as Window & {
      __OPENCLAW_API_CONFIG__?: RuntimeApiConfig;
    }
  ).__OPENCLAW_API_CONFIG__;
  return cfg ?? {};
}

function normalizeRuntimeConfig(payload: RuntimeApiConfig): RuntimeApiConfig {
  return {
    region: typeof payload.region === "string" ? payload.region.trim() : "",
    userPoolId: typeof payload.userPoolId === "string" ? payload.userPoolId.trim() : "",
    clientId: typeof payload.clientId === "string" ? payload.clientId.trim() : "",
    gatewayToken: typeof payload.gatewayToken === "string" ? payload.gatewayToken.trim() : "",
  };
}

export async function refreshRuntimeApiConfig(options?: { required?: boolean }) {
  if (typeof window === "undefined" || typeof fetch !== "function") {
    return;
  }
  const candidates = [LOCAL_RUNTIME_CONFIG_URL];
  const failures: string[] = [];

  for (const baseUrl of candidates) {
    const url = `${baseUrl}${baseUrl.includes("?") ? "&" : "?"}ts=${Date.now()}`;
    try {
      const response = await fetch(url, {
        method: "GET",
        headers: { Accept: "application/json" },
        credentials: "omit",
      });
      if (!response.ok) {
        failures.push(`${baseUrl} -> HTTP ${response.status}`);
        continue;
      }
      const payload = (await response.json()) as RuntimeApiConfig;
      (
        window as Window & {
          __OPENCLAW_API_CONFIG__?: RuntimeApiConfig;
        }
      ).__OPENCLAW_API_CONFIG__ = normalizeRuntimeConfig(payload);
      return;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      failures.push(`${baseUrl} -> ${message}`);
    }
  }

  if (options?.required) {
    throw new Error(`Unable to load runtime API config. Tried: ${failures.join(" | ")}`);
  }
}

export function getCognitoConfig() {
  const runtime = readRuntimeApiConfig();
  const region = typeof runtime.region === "string" ? runtime.region.trim() : "";
  const userPoolId = typeof runtime.userPoolId === "string" ? runtime.userPoolId.trim() : "";
  const clientId = typeof runtime.clientId === "string" ? runtime.clientId.trim() : "";
  return { region, userPoolId, clientId };
}

let cachedRegion = "";
let cachedClient: CognitoIdentityProviderClient | null = null;

export function getCognitoClient() {
  const { region } = getCognitoConfig();
  if (!region) {
    throw new Error("Missing Cognito region in runtime API config.");
  }
  if (!cachedClient || cachedRegion !== region) {
    cachedClient = new CognitoIdentityProviderClient({ region });
    cachedRegion = region;
  }
  return cachedClient;
}

export function assertCognitoConfig() {
  const { userPoolId, clientId, region } = getCognitoConfig();
  if (!userPoolId || !clientId || !region) {
    throw new Error("Missing Cognito config from runtime API (/api/config).");
  }
}

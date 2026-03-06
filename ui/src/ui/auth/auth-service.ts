import {
  ConfirmForgotPasswordCommand,
  ConfirmSignUpCommand,
  ForgotPasswordCommand,
  GlobalSignOutCommand,
  InitiateAuthCommand,
  ResendConfirmationCodeCommand,
  SignUpCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import {
  assertCognitoConfig,
  getCognitoClient,
  getCognitoConfig,
  refreshRuntimeApiConfig,
} from "./cognito-client.ts";
import { isTokenExpired } from "./jwt.ts";
import {
  clearStoredTokens,
  getStoredTokens,
  setStoredTokens,
  type AuthTokens,
} from "./token-store.ts";

export function mapAuthError(error: unknown): string {
  const name =
    typeof error === "object" && error != null && "name" in error ? String(error.name) : "";
  const rawMessage =
    typeof error === "object" && error != null && "message" in error
      ? String(error.message ?? "")
      : "";
  const lowerMessage = rawMessage.toLowerCase();

  if (lowerMessage.includes("secret hash")) {
    return "Cognito app client secret is enabled. For browser-only auth, use a User Pool app client without a client secret.";
  }
  if (lowerMessage.includes("sign up is not permitted")) {
    return "Sign-up is disabled for this Cognito app client. Enable self-registration/sign-up in User Pool settings.";
  }

  switch (name) {
    case "UserNotConfirmedException":
      return "Email is not verified yet. Please verify OTP first.";
    case "NotAuthorizedException":
      return rawMessage || "Not authorized. Check app client settings and credentials.";
    case "UsernameExistsException":
      return "An account with this email already exists.";
    case "CodeMismatchException":
      return "Invalid OTP code.";
    case "ExpiredCodeException":
      return "OTP code expired. Request a new one.";
    case "UserNotFoundException":
      return "No account found with this email.";
    case "InvalidPasswordException":
      return rawMessage || "Password does not match Cognito password policy.";
    case "InvalidParameterException":
      return rawMessage || "Invalid request parameters for Cognito.";
    case "ResourceNotFoundException":
      return "Cognito User Pool or App Client not found. Check region, user pool id, and client id.";
    default:
      return rawMessage || (error instanceof Error ? error.message : "Authentication failed.");
  }
}

function toTokens(
  auth: {
    AccessToken?: string;
    IdToken?: string;
    RefreshToken?: string;
    TokenType?: string;
  },
  previousRefreshToken: string | null,
): AuthTokens {
  if (!auth.AccessToken || !auth.IdToken) {
    throw new Error("Missing auth tokens from Cognito.");
  }
  const refreshToken = auth.RefreshToken ?? previousRefreshToken;
  if (!refreshToken) {
    throw new Error("Missing refresh token.");
  }
  return {
    accessToken: auth.AccessToken,
    idToken: auth.IdToken,
    refreshToken,
    tokenType: auth.TokenType ?? "Bearer",
    issuedAt: Date.now(),
  };
}

let refreshInFlight: Promise<AuthTokens> | null = null;

async function getAuthClientContext() {
  await refreshRuntimeApiConfig({ required: true });
  assertCognitoConfig();
  const client = getCognitoClient();
  const { clientId } = getCognitoConfig();
  return { client, clientId };
}

export async function signUp(email: string, password: string) {
  const { client, clientId } = await getAuthClientContext();
  return client.send(
    new SignUpCommand({
      ClientId: clientId,
      Username: email,
      Password: password,
      UserAttributes: [{ Name: "email", Value: email }],
    }),
  );
}

export async function verifySignUpOtp(email: string, code: string) {
  const { client, clientId } = await getAuthClientContext();
  return client.send(
    new ConfirmSignUpCommand({
      ClientId: clientId,
      Username: email,
      ConfirmationCode: code,
    }),
  );
}

export async function resendSignUpOtp(email: string) {
  const { client, clientId } = await getAuthClientContext();
  return client.send(
    new ResendConfirmationCodeCommand({
      ClientId: clientId,
      Username: email,
    }),
  );
}

export async function login(email: string, password: string, persist = true) {
  const { client, clientId } = await getAuthClientContext();
  const result = await client.send(
    new InitiateAuthCommand({
      ClientId: clientId,
      AuthFlow: "USER_PASSWORD_AUTH",
      AuthParameters: {
        USERNAME: email,
        PASSWORD: password,
      },
    }),
  );
  const tokens = toTokens(result.AuthenticationResult ?? {}, null);
  setStoredTokens(tokens, persist);
  return tokens;
}

export async function requestForgotPasswordOtp(email: string) {
  const { client, clientId } = await getAuthClientContext();
  return client.send(
    new ForgotPasswordCommand({
      ClientId: clientId,
      Username: email,
    }),
  );
}

export async function resetPasswordWithOtp(email: string, code: string, nextPassword: string) {
  const { client, clientId } = await getAuthClientContext();
  return client.send(
    new ConfirmForgotPasswordCommand({
      ClientId: clientId,
      Username: email,
      ConfirmationCode: code,
      Password: nextPassword,
    }),
  );
}

export async function refreshTokens() {
  const current = getStoredTokens();
  if (!current?.refreshToken) {
    throw new Error("Missing refresh token.");
  }
  const { client, clientId } = await getAuthClientContext();
  const result = await client.send(
    new InitiateAuthCommand({
      ClientId: clientId,
      AuthFlow: "REFRESH_TOKEN_AUTH",
      AuthParameters: {
        REFRESH_TOKEN: current.refreshToken,
      },
    }),
  );
  const tokens = toTokens(result.AuthenticationResult ?? {}, current.refreshToken);
  setStoredTokens(tokens, true);
  return tokens;
}

export async function getValidAccessToken() {
  const current = getStoredTokens();
  if (!current) {
    return null;
  }
  if (!isTokenExpired(current.accessToken)) {
    return current.accessToken;
  }
  if (!refreshInFlight) {
    refreshInFlight = refreshTokens().finally(() => {
      refreshInFlight = null;
    });
  }
  const next = await refreshInFlight;
  return next.accessToken;
}

export async function logout() {
  const current = getStoredTokens();
  try {
    if (current?.accessToken) {
      const client = getCognitoClient();
      await client.send(
        new GlobalSignOutCommand({
          AccessToken: current.accessToken,
        }),
      );
    }
  } catch {
    // Best effort only.
  } finally {
    clearStoredTokens();
  }
}

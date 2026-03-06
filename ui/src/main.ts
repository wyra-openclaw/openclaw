import "./styles.css";
import { refreshRuntimeApiConfig } from "./ui/auth/cognito-client.ts";

async function bootstrap() {
  await refreshRuntimeApiConfig();
  await import("./ui/app.ts");
}

// Some browser extensions inject async message listeners that can emit
// this noisy rejection in page apps. Ignore only this known extension error.
window.addEventListener("unhandledrejection", (event) => {
  const reason = event.reason;
  const message =
    typeof reason === "string"
      ? reason
      : reason instanceof Error
        ? reason.message
        : "";
  if (
    message.includes(
      "A listener indicated an asynchronous response by returning true, but the message channel closed before a response was received",
    )
  ) {
    event.preventDefault();
  }
});

void bootstrap();

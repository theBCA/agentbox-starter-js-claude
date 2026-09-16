const PROVIDERS = {
  anthropic: {
    apiKeyEnv: "ANTHROPIC_API_KEY",
    baseUrlEnv: "ANTHROPIC_BASE_URL",
    path: "",
  },
  google: {
    apiKeyEnv: "GOOGLE_API_KEY",
    baseUrlEnv: "GOOGLE_API_BASE",
    path: "",
  },
  openai: {
    apiKeyEnv: "OPENAI_API_KEY",
    baseUrlEnv: "OPENAI_BASE_URL",
    path: "/v1",
  },
};

function managedByAgentBox() {
  return Boolean((process.env.AGENTBOX_APP_ID ?? "").trim()) ||
    process.env.KOBIL_SECUREPROXY_REQUIRED === "1";
}

function providerBaseUrl(proxyUrl, path) {
  return `${proxyUrl.replace(/\/+$/, "")}${path}`;
}

/**
 * Bind a provider SDK to AgentBox's model-agnostic SecureProxy contract.
 *
 * The application still chooses a provider-specific model name. Credentials
 * and transport are forced through SecureProxy whenever AgentBox manages the
 * process; raw provider credentials cannot silently become a fallback route.
 */
export function configureSecureProxy(provider) {
  const contract = PROVIDERS[provider];
  if (!contract) throw new Error(`Unsupported SecureProxy provider: ${provider}`);

  const proxyUrl = (process.env.KOBIL_SECUREPROXY_URL ?? "").trim();
  const virtualKey = (process.env.KOBIL_SECUREPROXY_API_KEY ?? "").trim();
  const required = managedByAgentBox() || Boolean(proxyUrl || virtualKey);
  if (!required) return null;
  if (!proxyUrl || !virtualKey) {
    throw new Error(
      "AgentBox-managed model calls require KOBIL_SECUREPROXY_URL and " +
        "KOBIL_SECUREPROXY_API_KEY; direct provider fallback is disabled.",
    );
  }

  const baseURL = providerBaseUrl(proxyUrl, contract.path);
  process.env[contract.apiKeyEnv] = virtualKey;
  process.env[contract.baseUrlEnv] = baseURL;
  if (provider === "google") process.env.GOOGLE_GEMINI_BASE_URL = baseURL;
  return { apiKey: virtualKey, baseURL };
}

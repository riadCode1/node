function getEnv() {
  return process.env.QF_ENV === "production" ? "production" : "prelive";
}

const ENV_MAP = {
  prelive: {
    authBaseUrl: "https://prelive-oauth2.quran.foundation",
    apiBaseUrl: "https://apis-prelive.quran.foundation",
  },
  production: {
    authBaseUrl: "https://oauth2.quran.foundation",
    apiBaseUrl: "https://apis.quran.foundation",
  },
};

function getQfOAuthConfig() {
  const clientId = process.env.QF_CLIENT_ID;
  const clientSecret = process.env.QF_CLIENT_SECRET;
  const env = getEnv();

  if (!clientId) {
    throw new Error(
      "Missing Quran Foundation API credentials. Request access: https://api-docs.quran.foundation/request-access"
    );
  }

  return {
    env,
    clientId,
    clientSecret,
    ...ENV_MAP[env],
  };
}

module.exports = { getQfOAuthConfig };
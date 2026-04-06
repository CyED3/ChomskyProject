// Good practice: using env vars
const dbHost = process.env.DB_HOST;

// Bad practice: hardcoded API key
const apiKey = "AKIA1234567890ABCDEF";

// Leak: logging the credential
console.log(apiKey);

// TODO: migrate apiKey to environment variable

export default () => ({
  jwt: {
    privateKey: Buffer.from(
      process.env.JWT_SECRET_BASE64 || '',
      'base64',
    ).toString('utf8'),
    jwksUrl: process.env.JWT_JWKS_URL || '',
  },
  crypto: {
    saltRounds: Number(process.env.CRYPTO_ITERATIONS) || 10,
  },
  cors: {
    origin: process.env.CORS_ORIGIN || '*',
  },
  mail: {
    transport: process.env.EMAIL_TRANSPORT || '',
  },
});

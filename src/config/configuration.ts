export default () => ({
  jwt: {
    privateKey: Buffer.from(
      process.env.JWT_SECRET_BASE64 || '',
      'base64',
    ).toString('utf8'),
  },
});

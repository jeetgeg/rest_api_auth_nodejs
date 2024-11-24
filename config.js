require("dotenv").config();

module.exports = {
  accessTokenSecret: process.env.JWT_SECRET,
  accessTokenExpiresIn: "30m",

  refreshTokenSecret: process.env.JWT_SECRET_REFRESH,
  refreshTokenExpiresIn: "1w",

  cacheTemoraryTokenPrefix: "temporaryToken",
  cacheTemporaryTokenExpiresInSeconds: 60 * 3,

  port: process.env.PORT,
};

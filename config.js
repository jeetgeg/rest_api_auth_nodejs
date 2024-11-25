require("dotenv").config();

module.exports = {
  accessTokenSecret: process.env.JWT_SECRET,
  accessTokenExpiresIn: "30m",

  refreshTokenSecret: process.env.JWT_SECRET_REFRESH,
  refreshTokenExpiresIn: "1w",

  cacheTemoraryTokenPrefix: "temp_token",
  cacheTemporaryTokenExpiresInSeconds: 180,

  port: process.env.PORT,
};

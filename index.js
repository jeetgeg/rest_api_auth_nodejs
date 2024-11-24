const express = require("express");
const Datastore = require("nedb-promises");
const bcrypt = require("bcryptjs");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");
const config = require("./config");

// Initialize the app with express
const app = express(0);

const users = Datastore.create("X_Users.db");
const userRefreshTokens = Datastore.create("X_UserRefreshTokens.db");
const userInvalidTokens = Datastore.create("X_UserInvalidTokens.db");

// Configure body parser
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan("dev"));

// Define the routes
app.get("/", (req, res) => {
  res.send("REST API Authentication and Authorization with JWT");
});

// Register a new user
app.post("/api/auth/register", async (req, res) => {
  try {
    // Get the user input
    const { name, email, password, role } = req.body;
    // Validate the user input
    if (!name || !email || !password) {
      return res
        .status(422)
        .json({ message: "Please fill in the fields (name, email, password)" });
    }

    if (await users.findOne({ email })) {
      return res.status(409).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    // Create a new user
    const newUser = await users.insert({
      name,
      email,
      password: hashedPassword,
      role: role ?? "member",
    });
    // Remove the password field from the object

    return res
      .status(201)
      .json({ message: "New User Created", id: newUser._id });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

// Login a user
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate the user input
    if (!email || !password) {
      return res
        .status(422)
        .json({ message: " Please fill in the fields (email, password)" });
    }

    // Check if the user exists
    const user = await users.findOne({ email });
    if (!user) {
      return res
        .status(401)
        .json({ message: "Email or password is invalid , ErrorCode:NF" });
    }

    // Check if the password is correct
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res
        .status(401)
        .json({ message: "Email or password is invalid , ErrorCode:PMm" });
    }

    // Generate a JWT token
    const accessToken = jwt.sign(
      { userId: user._id },
      config.accessTokenSecret,
      {
        subject: "accessAPI",
        expiresIn: config.accessTokenExpiresIn,
      }
    );

    // Generate Refresh Token
    const refreshToken = jwt.sign(
      { userId: user._id },
      config.refreshTokenSecret,
      {
        subject: "refreshToken",
        expiresIn: config.refreshTokenExpiresIn,
      }
    );

    await userRefreshTokens.insert({
      refreshToken,
      userId: user._id,
    });

    // return the token
    return res.status(200).json({
      id: user._id,
      name: user.name,
      email: user.email,
      accessToken,
      refreshToken,
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

// refresh Token
app.post("/api/auth/refresh-token", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(401).json({ message: "Refresh Token not found!" });
    }

    const decodedRefreshToken = jwt.verify(
      refreshToken,
      config.refreshTokenSecret
    );

    const userRefreshToken = await userRefreshTokens.findOne({
      refreshToken,
      userId: decodedRefreshToken.userId,
    });
    if (!userRefreshToken) {
      return res
        .status(401)
        .json({ message: "Refresh Token is invalid or expired! 11" });
    }

    await userRefreshTokens.remove({ _id: userRefreshToken._id });
    await userRefreshTokens.compactDatafile();

    // Generate a JWT token
    const accessToken = jwt.sign(
      { userId: decodedRefreshToken.userId },
      config.accessTokenSecret,
      {
        subject: "accessAPI",
        expiresIn: config.accessTokenExpiresIn,
      }
    );

    // Generate Refresh Token // Optional
    const newRefreshToken = jwt.sign(
      { userId: decodedRefreshToken.userId },
      config.refreshTokenSecret,
      {
        subject: "refreshToken",
        expiresIn: config.refreshTokenExpiresIn,
      }
    );

    await userRefreshTokens.insert({
      refreshToken: newRefreshToken,
      userId: decodedRefreshToken.userId,
    });

    // return the token
    return res.status(200).json({
      accessToken,
      refreshToken,
    });
  } catch (error) {
    if (
      error instanceof jwt.TokenExpiredError ||
      error instanceof jwt.JsonWebTokenError
    ) {
      return res
        .status(401)
        .json({ message: "Refresh token invalid or expired." });
    }
    return res.status(500).json({ message: error.message });
  }
});

// Logout User
app.get("/api/auth/logout", ensureAuthenticated, async (req, res) => {
  // will logout from all the devices for the user
  // if you want to logout from a perticular device the . get the accessToken as POST from that device. and delete that access token only
  try {
    // delete all the refresh tokens related to user.
    await userRefreshTokens.removeMany({ userId: req.user.id });
    await userRefreshTokens.compactDatafile();

    await userInvalidTokens.insert({
      accessToken: req.accessToken.value,
      userId: req.user.id,
      expirationTime: req.accessToken.exp,
    });

    return res.status(204).send();
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

// current User
app.get("/api/users/current", ensureAuthenticated, async (req, res) => {
  try {
    const user = await users.findOne({ _id: req.user.id });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({
      id: user._id,
      name: user.name,
      email: user.email,
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

// Admin user
app.get("/api/admin", ensureAuthenticated, authorize(["admin"]), (req, res) => {
  return res
    .status(200)
    .json({ message: "Hey Admin, You can access this route" });
});

// Moderator User
app.get(
  "/api/moderator",
  ensureAuthenticated,
  authorize(["admin", "moderator"]),
  (req, res) => {
    return res.status(200).json({ message: "Moderator + Admin Area" });
  }
);

// Middleware to check if the user is authenticated
async function ensureAuthenticated(req, res, next) {
  const accessToken = req.headers.authorization;
  if (!accessToken) {
    return res.status(401).json({ message: "Access token is missing" });
  }
  if (await userInvalidTokens.findOne({ accessToken })) {
    return res
      .status(401)
      .json({ message: "Access token invalid", code: "AccessTokenInvalid" });
  }

  try {
    const decodedAccessToken = jwt.verify(
      accessToken,
      config.accessTokenSecret
    );
    req.accessToken = { value: accessToken, exp: decodedAccessToken.exp };
    req.user = { id: decodedAccessToken.userId };
    next();
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      return res
        .status(401)
        .json({ message: "Access token expired", code: "AccessTokenExpired" });
    } else if (error instanceof jwt.JsonWebTokenError) {
      return res
        .status(401)
        .json({ message: "Access token invalid", code: "AccessTokenInvalid" });
    } else {
      return res.status(500).json({ message: error.message });
    }
  }
}

function authorize(roles = []) {
  return async function (req, res, next) {
    const user = await users.findOne({ _id: req.user.id });
    console.log(user);
    if (!user || !roles.includes(user.role)) {
      return res.status(403).json({ message: "Not Allowed! Access Denied!" });
    }
    next();
  };
}

// Start the server
const PORT = config.port || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

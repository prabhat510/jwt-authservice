const express = require("express");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const redis = require("redis");
const mongodb = require("mongodb");
const cors = require("cors");
const app = express();

app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));
dotenv.config();

const port = process.env.PORT || 3000;
const mongoClient = mongodb.MongoClient;
const redisClient = redis.createClient({
  password: process.env.REDIS_PASSWORD,
  socket: {
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT,
  },
});

app.post("/auth/login", async (req, res) => {
  const user = req.body;
  if (!user) return res.sendStatus(400);
  const mongodbClient = await mongoClient.connect(process.env.MONGODB_URI);
  try {
    await redisClient.connect();
    const db = await mongodbClient.db("capstone");
    const userExists = await db
      .collection("users")
      .findOne({ username: user?.username, password: user?.password });
    if (userExists) {
      const userData = { username: user.username, email: user.email };
      const accessToken = generateJWTToken("ACCESS_TOKEN", userData);
      const refreshToken = generateJWTToken("REFRESH_TOKEN", userData);
      await redisClient.SADD("refreshTokens", refreshToken);
      return res.json({ accessToken: accessToken, refreshToken: refreshToken });
    } else {
      res.sendStatus(404);
    }
  } catch (error) {
    console.log("error", error);
  } finally {
    // close connections
    redisClient.quit();
    mongodbClient.close();
  }
});

app.post("/token", async (req, res) => {
  const refreshToken = req.body.token;
  if (refreshToken === null) {
    return res.sendStatus(401);
  }
  try {
    await redisClient.connect();
    const isValidRefreshToken = await redisClient.SISMEMBER(
      "refreshTokens",
      refreshToken
    );
    if (!isValidRefreshToken) return res.sendStatus(403);
    // using verify method so that we can decode the user info from the token and then use it to create the accessToken
    jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET,
      (error, user) => {
        if (error) {
          return res.sendStatus(403);
        }
        const accessToken = generateJWTToken("ACCESS_TOKEN", {
          username: user.username,
        });
        res.json({ accessToken: accessToken });
      }
    );
  } catch (error) {
    console.log("error", error);
  } finally {
    // close connections
    redisClient.quit();
  }
});

app.delete("/auth/logout", async (req, res) => {
  const refreshToken = req.body.token;

  try {
    await redisClient.connect();
    // TODO: for now we are only removing refresh_Token from redis (invalidating refresh_token) but the access_token might still
    // have the access even after user has logged out. Therefore, a different storage can be maintained where we can store the access_tokens
    // after user has logged out and everytime a request with access token is made, it can be checked against these invalid access tokens.
    redisClient.SREM("refreshTokens", refreshToken);
    return res.sendStatus(200);
  } catch (error) {
    console.log("error", error);
  } finally {
    redisClient.quit();
  }
});

app.listen(port, () => {
  console.log("listening on port", port);
});

function generateJWTToken(type, payload) {
  let token;
  if (type === "ACCESS_TOKEN") {
    token = jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, {
      expiresIn: "1m",
    });
  } else if (type === "REFRESH_TOKEN") {
    token = jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET);
  } else if (type === "PASSWORD_TOKEN") {
    token = jwt.sign(payload, process.env.PASSWORD_TOKEN_SECRET);
  }
  return token;
}

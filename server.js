const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const redis = require("redis");
const mongodb = require("mongodb");
const cors = require("cors");
const bodyParser = require('body-parser');
const app = express();
const utility = require("./utility");

const allowedOrigins = [process.env.ORIGIN, 'https://go-swiftcart.netlify.app', 'https://readersnest.netlify.app/'];
app.use(express.json());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors({ origin: allowedOrigins, credentials: true, exposedHeaders: ['Set-Cookie', 'Date', 'ETag']} ));
dotenv.config();


const port = process.env.PORT || 3000;
// tokenExpiry should be in minutes
const mongoClient = mongodb.MongoClient;
const redisClient = redis.createClient({
  password: process.env.REDIS_PASSWORD,
  socket: {
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT,
    timeout: 60000
  }
});

redisClient.on("error", (error) => {
  console.error("redisclient error", error);
});

redisClient.connect();


app.get("/api/auth/status", (req, res) => {
  res.status(200).send("ok");
});

app.get("/api/auth/users", utility.authenticateToken, async (req, res) => {
  const offset = req.query.offset;
  const limit = req.query.limit;
  const mongodbClient = await mongoClient.connect(process.env.MONGODB_URI);
  console.log("db::", process.env.DB)
  console.log("COLLECTION::", process.env.COLLECTION)
  console.log("MONGODB_URI::", process.env.MONGODB_URI)
  try {
    const db = await mongodbClient.db(process.env.DB);
    const count = await db.collection(process.env.COLLECTION).countDocuments();
    const users = await db.collection(process.env.COLLECTION).find()
      .project({ _id: 0, password: 0, __v: 0 })
      .sort({ _id: 1 })
      .skip(parseInt(offset))
      .limit(parseInt(limit))
      .toArray();
    res.json({ users: users, totalCount: count });
  } catch (error) {
    console.log(error);
  } finally {
    mongodbClient.close();
  }
});

app.post("/api/auth/login", async (req, res) => {
  const user = req.body;
  if (!user) return res.status(400).send("user details are not present");
  const mongodbClient = await mongoClient.connect(process.env.MONGODB_URI);
  try {
    const db = await mongodbClient.db(process.env.DB);
    const userExists = await db.collection(process.env.COLLECTION).findOne({ username: user?.username });
    if (userExists) {
      console.log("userExists", userExists);
      const passwordMatched = await bcrypt.compare(
        user.password,
        userExists.password
      );
      if (passwordMatched) {
        const userData = {
          name: userExists.name,
          username: userExists.username,
          email: userExists.email,
          userId: userExists._id
        };

        const accessToken = utility.generateJWTToken("ACCESS_TOKEN", userData);
        const refreshToken = utility.generateJWTToken("REFRESH_TOKEN", userData);
        await redisClient.SADD("refreshTokens", refreshToken);
        res.cookie("token", accessToken, {maxAge: utility.getNextYearEpochTime()});
        res.cookie("refresh_token", refreshToken, {maxAge: utility.getNextYearEpochTime()});
        return res.send();
      } else {
        res.status(404).send("password is invalid");
      }
    } else {
      res.status(404).send("user doesnot exists");
    }
  } catch (error) {
    console.log("error", error);
  } finally {
    mongodbClient.close();
  }
});

app.post("/api/auth/token", async (req, res) => {
  const refreshToken = req?.body?.token;
  if (refreshToken === null) {
    return res.status(401).send('refresh token not present');
  }
  try {
  
    const isValidRefreshToken = await redisClient.SISMEMBER("refreshTokens", refreshToken);
    if (!isValidRefreshToken) return res.status(403).send('invalid refresh token');
    // using verify method so that we can decode the user info from the token and then use it to create the accessToken
    jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET,
       (error, user) => {
        if (error) {
          return res.status(403).send('error validating refresh token');
        }
        const accessToken = utility.generateJWTToken("ACCESS_TOKEN", {username: user.username,});
        const newRefreshToken = utility.generateJWTToken("REFRESH_TOKEN", {username: user.username});
        redisClient.SADD("refreshTokens", newRefreshToken);
        redisClient.SREM("refreshTokens", refreshToken);
        res.cookie("token", accessToken, {maxAge: utility.getNextYearEpochTime()});
        res.cookie("refresh_token", refreshToken, {maxAge: utility.getNextYearEpochTime()});
        return res.send();
      }
    );
  } catch (error) {
    console.log("error", error);
  } finally {
    // close connections
    // redisClient.quit()
  }
});

app.delete("/api/auth/logout", async (req, res) => {
  const refreshToken = req.body.token;

  try {
    // TODO: for now we are only removing refresh_Token from redis (invalidating refresh_token) but the access_token might still
    // have the access even after user has logged out. Therefore, a different storage can be maintained where we can store the access_tokens
    // after user has logged out and everytime a request with access token is made, it can be checked against these invalid access tokens.
    if(refreshToken) {
      redisClient.SREM("refreshTokens", refreshToken);
      return res.status(200).send("logged out successfully");
    } else {
      return res.status(404).send("refresh token not present");
    }
  } catch (error) {
    console.log("error", error);
  } finally {
    // redisClient.quit();
  }
});

app.listen(port, () => {
  console.log("listening on port", port);
});

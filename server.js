const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const redis = require("redis");
const mongodb = require("mongodb");
const cors = require("cors");
const app = express();
const generateJWTToken = require('./tokenGenerator');

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

app.get('/api/auth/users', async (req, res)=>{
  const offset = req.query.offset;
  const limit = req.query.limit;
  const mongodbClient = await mongoClient.connect(process.env.MONGODB_URI);

  try {
    const db = await mongodbClient.db("capstone");
    const count = await db.collection("users").count();
    const users = await db.collection("users").find().project({_id: 0, password: 0, __v: 0}).sort({_id: 1}).skip(parseInt(offset)).limit(parseInt(limit)).toArray();
    res.json({users: users, totalCount: count});
  } catch (error) {
    console.log(error);
  } finally {
    mongodbClient.close();
  }
})

app.post("/api/auth/login", async (req, res) => {
  const user = req.body;
  if (!user) return res.sendStatus(400);
  const mongodbClient = await mongoClient.connect(process.env.MONGODB_URI);
  try {
    await redisClient.connect();
    const db = await mongodbClient.db("capstone");
    const userExists = await db
      .collection("users")
      .findOne({ username: user?.username });
    if (userExists) {
      console.log('userExists', userExists);
      const passwordMatched = await bcrypt.compare(user.password, userExists.password);
      if(passwordMatched) {
        const userData = { username: user.username };
        const accessToken = generateJWTToken("ACCESS_TOKEN", userData);
        const refreshToken = generateJWTToken("REFRESH_TOKEN", userData);
        await redisClient.SADD("refreshTokens", refreshToken);
        delete userExists.password;
        delete userExists._id;
        return res.json({ accessToken: accessToken, refreshToken: refreshToken, user: userExists });
      } else {
        res.sendStatus(404);
      }
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

app.post("/api/auth/token", async (req, res) => {
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


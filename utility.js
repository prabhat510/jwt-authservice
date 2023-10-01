const jwt = require("jsonwebtoken");
require("dotenv").config();
const accessTokenExpiry = process.env.ACCESS_TOKEN_EXPIRY || 1; 
const refreshTokenExpiry = process.env.REFRESH_TOKEN_EXPIRY || 5; 

function generateJWTToken(type, payload) {
  let token;
  if (type === "ACCESS_TOKEN") {
    token = jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, {
      expiresIn: accessTokenExpiry,
    });
  } else if (type === "REFRESH_TOKEN") {
    token = jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET);
  } else if (type === "PASSWORD_TOKEN") {
    token = jwt.sign(payload, process.env.PASSWORD_TOKEN_SECRET, {
      expiresIn: refreshTokenExpiry
    });
  }
  return token;
}

// middlewear to check for token validity
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token === null) {
    // token is not present, therefore its Unauthorized request
    return res.sendStatus(401);
  }
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (error, user) => {
    if (error) {
      // the token is present but its not valid
      return res.sendStatus(403);
    }
    req.user = user;
    console.log("ssss", user);
    next();
  });
}

module.exports = { generateJWTToken, authenticateToken };

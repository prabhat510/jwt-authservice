const jwt = require("jsonwebtoken");
require("dotenv").config();

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

module.exports = generateJWTToken;
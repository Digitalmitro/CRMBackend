const jwt = require('jsonwebtoken');

const secret_key = process.env.secret_key

const authenticateToken = (req, res, next) => {
  console.log("cookier",req.cookies)

    const token = req.cookies.accessToken;
    if (!token) {
      return res.status(401).json({ status: "Access Denied" });
    }
  
    try {
      const verified = jwt.verify(token, secret_key);
      req.user = verified; 
      next();
    } catch (error) {
      return res.status(403).json({ status: "Invalid Token" });
    }
  };
  
  module.exports = authenticateToken;
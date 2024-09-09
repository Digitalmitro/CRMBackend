const jwt = require("jsonwebtoken");
const {
  RegisteradminModal,
} = require("../models/AdminModel/RegisterAdminModel");

const adminAuth = async (req, res, next) => {
  try {
    const token = req.headers.token;
    const verifyToken = jwt.verify(token, process.env.secret_key);

    console.log(verifyToken);

    const rootUser = await RegisteradminModal.findOne({ _id: verifyToken._id });


    console.log(rootUser);

    if (!rootUser) {
      throw new Error("Admin Not Found.");
    }

    req.token = token;
    req.rootUser = rootUser;

    next();
  } catch (error) {
    res.status(401).send("Unauthorized : No token provided");
    console.log(error);
  }
};

module.exports = adminAuth;





// const jwt = require("jsonwebtoken");
// const {
//   RegisteradminModal,
// } = require("../models/AdminModel/RegisterAdminModel");
// const Session = require("../models/SessionModel"); // Import your Session model

// const adminAuth = async (req, res, next) => {
//   try {
//     const token = req.headers.token;

//     if (!token) {
//       return res.status(401).send("Unauthorized: No token provided");
//     }

//     // Verify JWT token
//     jwt.verify(token, process.env.secret_key, async (err, user) => {
//       if (err) return res.status(403).send("Forbidden: Invalid token");

//       // Check if the session is valid
//       const validSession = await Session.findOne({ userId: user._id, token: token });
//       if (!validSession) return res.status(403).send("Forbidden: Invalid session");

//       // Fetch the user
//       const rootUser = await RegisteradminModal.findOne({ _id: user._id });
//       if (!rootUser) return res.status(404).send("Admin Not Found");

//       // Attach user and token to the request
//       req.token = token;
//       req.rootUser = rootUser;
//       req.user = user;

//       next();
//     });
//   } catch (error) {
//     res.status(500).send("Internal Server Error");
//     console.log(error);
//   }
// };

// module.exports = adminAuth;


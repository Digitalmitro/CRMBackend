const jwt = require("jsonwebtoken");
const {RegisteradminModal} = require("../models/AdminModel/RegisterAdminModel");
const {RegisteruserModal} = require("../models/UserModel/RegisterUserModel")

const commonAuth = async (req, res, next) => {
    try {
        const token = req.headers.token;
        const verifyToken = jwt.verify(token,process.env.secret_key);
        
        let rootAdmin;
        let rootUser;

        rootAdmin = await RegisteradminModal.findOne({_id:verifyToken._id})
        
        rootUser = await RegisteruserModal.findOne({_id:verifyToken._id})

        if(!rootAdmin && !rootUser){
          throw new Error("User Not Found.");
        }

        req.token = token;
        req.rootUser = rootUser ?? rootAdmin;
        console.log("rootUser", rootUser)
        next();

    } catch (error) {
        res.status(401).send("Unauthorized : No token provided");
        console.log(error);
    }
};

module.exports = commonAuth;
const jwt = require('jsonwebtoken');
const User = require('../model/user.model');
const TOKEN_KEY = process.env.TOKEN_KEY || "ashdjdjd";

const checkToken = async (req, res, next) => {
    try {
        let token;

        if (req.cookies && req.cookies.accessToken) {
            token = req.cookies.accessToken;
        } else if (req.headers && req.headers.authorization) {
            token = req.headers.authorization.split(" ")[1];
        }

        if (!token) {
            return res.status(401).send({ status: 401, message: "Token is missing" });
        }

        const userData = jwt.verify(token, TOKEN_KEY);
        if (!userData) {
            return res.status(401).send({ status: 401, message: "Invalid token" });
        }

        const user = await User.findById(userData._id);
        if (!user) {
            return res.status(404).send({ status: 404, message: "User not found" });
        }

        req.user = {
            userId: userData._id,
            userName: userData.userName
        };

        next();
    } catch (error) {
        return res.status(401).send({ status: 401, message: "Invalid token", error: error.message });
    }
}

module.exports = { checkToken };

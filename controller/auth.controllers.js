const User = require('../model/user.model');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const options = {
    httpOnly: true,
    secure: true
};

// Generate Tokens
const getGenerateToken = async (userId) => {
    try {
        const userData = await User.findById(userId);
        const accessToken = await userData.generateToken();
        const refreshToken = await userData.generateRefreshToken();
        return { accessToken, refreshToken };
    } catch (error) {
        throw new Error("Something went wrong");
    }
};

// Register User
exports.register = async (req, res) => {
    try {
        const { userName, email, password } = req.body;
        if (!userName || !email || !password) {
            return res.status(400).send({ status: 400, message: "userName, email, and password are required for user creation" });
        }

        const user = new User({ userName, email, password });
        const data = await user.save();
        const { accessToken, refreshToken } = await getGenerateToken(user._id);

        await User.findByIdAndUpdate(user._id, { $set: { refreshTokens: [refreshToken] } });

        return res.status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", refreshToken, options)
            .send({ status: 200, data: { accessToken, refreshToken } });

    } catch (error) {
        return res.status(500).send({ status: 500, message: "Internal Server Error", error: error.message });
    }
};

// Login User
exports.login = async (req, res) => {
    try {
        const { userName, email, password } = req.body;
        if (!(userName || email) || !password) {
            return res.status(400).send({ status: 400, message: "userName/email and password are required for login" });
        }

        const user = await User.findOne({
            $or: [{ userName }, { email }]
        });

        if (!user) {
            return res.status(404).send({ status: 404, message: "User not found" });
        }

        const isValidPassword = await user.isValidPassword(password);
        if (!isValidPassword) {
            return res.status(401).send({ status: 401, message: 'Invalid password' });
        }

        const { accessToken, refreshToken } = await getGenerateToken(user._id);
        await User.findByIdAndUpdate(user._id, { $push: { refreshTokens: refreshToken } });

        return res.status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", refreshToken, options)
            .send({ status: 200, data: { accessToken, refreshToken } });

    } catch (error) {
        return res.status(500).send({ status: 500, message: "Internal Server Error", error: error.message });
    }
};

// Refresh Token
exports.refreshToken = async (req, res) => {
    const { token: refreshToken } = req.body;
    if (!refreshToken) {
        return res.status(401).send({ status: 401, message: 'Refresh token is required' });
    }

    try {
        const user = await User.findOne({ refreshTokens: refreshToken });
        if (!user) {
            return res.status(403).send({ status: 403, message: 'Invalid refresh token' });
        }

        const accessToken = await user.generateToken();
   
        return res.status(200)
            .cookie("accessToken", accessToken, options)
            .send({ status: 200, data: { accessToken } });

    } catch (error) {
        return res.status(500).send({ status: 500, message: "Internal Server Error", error: error.message });
    }
};

// Logout User
exports.logout = async (req, res) => {
    try {
        const userId = req?.user?.userId;
        const { refreshToken } = req.body;
        if (!refreshToken) {
            return res.status(400).send({ status: 400, message: 'Refresh token is required' });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).send({ status: 404, message: 'User not found' });
        }

        const refreshTokens = user.refreshTokens.filter(token => token !== refreshToken);
        await User.findByIdAndUpdate(userId, { $set: { refreshTokens } });

        return res.status(200).send({ status: 200, message: 'Logged out successfully' });
    } catch (error) {
        return res.status(500).send({ status: 500, message: "Internal Server Error", error: error.message });
    }
};

// Update User Password
exports.updateUser = async (req, res) => {
    try {
        const userId = req?.user?.userId;
        const { oldPassword, newPassword } = req.body;
        if (!oldPassword || !newPassword) {
            return res.status(400).send({ status: 400, message: 'oldPassword and newPassword are required' });
        }
        if (oldPassword === newPassword) {
            return res.status(400).send({ status: 400, message: 'New password must be different from the old password' });
        }

        const user = await User.findById(userId);
        const isValidOldPassword = await user.isValidPassword(oldPassword);
        if (!isValidOldPassword) {
            return res.status(400).send({ status: 400, message: 'Old password is incorrect' });
        }

        const newPasswordHash = await bcrypt.hash(newPassword, 10);
        await User.findByIdAndUpdate(userId, { $set: { password: newPasswordHash } });

        return res.status(200).send({ status: 200, message: 'Password changed successfully' });
    } catch (error) {
        return res.status(500).send({ status: 500, message: "Internal Server Error", error: error.message });
    }
};

// Forget Password
exports.forgetPassword = async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).send({ status: 400, message: "Email is required" });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).send({ status: 404, message: "User not found" });
        }

        const resetToken = crypto.randomBytes(32).toString("hex");
        const hashedToken = await bcrypt.hash(resetToken, 10);
        user.resetPasswordToken = hashedToken;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

        await user.save();

        // Set up nodemailer
        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.EMAIL,
                pass: process.env.EMAIL_PASSWORD
            }
        });

        const mailOptions = {
            from: process.env.EMAIL,
            to: user.email,
            subject: 'Password Reset',
            text: `You are receiving this email because you (or someone else) have requested the reset of the password for your account.\n\n
                Please click on the following link, or paste this into your browser to complete the process within one hour of receiving it:\n\n
                http://localhost:3000/reset/${resetToken}\n\n
                If you did not request this, please ignore this email and your password will remain unchanged.\n`
        };

        await transporter.sendMail(mailOptions);

        return res.status(200).send({ status: 200, message: 'Reset password email sent' });
    } catch (error) {
        return res.status(500).send({ status: 500, message: "Internal Server Error", error: error.message });
    }
};

// Reset Password
exports.resetPassword = async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        if (!token || !newPassword) {
            return res.status(400).send({ status: 400, message: 'Token and newPassword are required' });
        }

        const user = await User.findOne({
            resetPasswordToken: { $exists: true },
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).send({ status: 400, message: 'Invalid or expired reset token' });
        }

        const isValidToken = await bcrypt.compare(token, user.resetPasswordToken);
        if (!isValidToken) {
            return res.status(400).send({ status: 400, message: 'Invalid reset token' });
        }

        const newPasswordHash = await bcrypt.hash(newPassword, 10);
        user.password = newPasswordHash;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        await user.save();

        return res.status(200).send({ status: 200, message: 'Password reset successfully' });
    } catch (error) {
        return res.status(500).send({ status: 500, message: "Internal Server Error", error: error.message });
    }
};

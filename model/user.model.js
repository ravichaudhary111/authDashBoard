const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const TOKEN_KEY = process.env.TOKEN_KEY || "ashdjdjd";
const TOKEN_EXPIRE_TIME = process.env.TOKEN_EXPIRE_TIME || '50m';
const REFRESH_TOKEN_KEY = process.env.REFRESH_TOKEN_KEY || "ahsjsjsskskk";
const REFRESH_EXPIRE_TIME = process.env.REFRESH_EXPIRE_TIME || '240m';

const Schema = mongoose.Schema;

const UserSchema = new Schema({
    userName: {
        type: String,
        unique: true,
        required: true
    },
    email: {
        type: String,
        unique: true,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    refreshTokens: [{
        type: String
    }],
    resetPasswordToken: {
        type: String
    },
    resetPasswordExpires: {
        type: Date
    }
}, {
    versionKey: false,
    timestamps: true
});

// Hash the password before saving the user
UserSchema.pre("save", async function (next) {
    if (this.isModified("password") || this.isNew) {
        this.password = await bcrypt.hash(this.password, 10);
    }
    next();
});

// Compare the provided password with the hashed password
UserSchema.methods.isValidPassword = async function (password) {
    return bcrypt.compare(password, this.password);
};

// Generate JWT access token
UserSchema.methods.generateToken = function () {
    return jwt.sign(
        {
            _id: this._id,
            userName: this.userName
        },
        TOKEN_KEY,
        { expiresIn: TOKEN_EXPIRE_TIME }
    );
};

// Generate JWT refresh token
UserSchema.methods.generateRefreshToken = function () {
    return jwt.sign(
        {
            _id: this._id,
            userName: this.userName
        },
        REFRESH_TOKEN_KEY,
        { expiresIn: REFRESH_EXPIRE_TIME }
    );
};

const User = mongoose.model('User', UserSchema, 'User');

module.exports = User;

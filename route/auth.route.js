const express = require('express');
const router = express.Router();
const authController = require('../controller/auth.controllers');

const { checkToken } = require('../middleware/auth.middleware');

router.route('/register')
    .post(authController.register);

router.route('/login')
    .post(authController.login);

router.route('/refreshToken')
    .post(authController.refreshToken);

router.route('/logout')
    .post(checkToken, authController.logout);

router.route('/updateUser')
    .post(checkToken, authController.updateUser);

router.route('/forgetPassword')
    .post(authController.forgetPassword);

router.route('/resetPassword')
    .post(authController.resetPassword);

module.exports = router;

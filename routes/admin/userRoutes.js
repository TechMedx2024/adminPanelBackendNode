import express from 'express';
const router = express.Router();

import UserController from '../../controllers/admin/userController.js'
import '../../config/passport-jwt-strategy.js'

import passport from 'passport';
import setAuthHeader from '../../middleware/admin/setAuthHeader.js';

//Public Routes
router.post('/register', UserController.userRegistration)
router.post('/verify-email', UserController.verificationEmail)
router.post('/login', UserController.userLogin)
router.post('/verifyOTP', UserController.verifyOTP)
router.post('/reset-password-link', UserController.sendUserPasswordResetEmail)
router.post('/reset-password/:id/:token', UserController.userPasswordReset)



// private routes
router.get('/userProfile', setAuthHeader, passport.authenticate('jwt', { session: false }), UserController.userProfile);
router.get('/getAllUsers', setAuthHeader, passport.authenticate('jwt', { session: false }), UserController.getAllUsers);
router.post('/change-password', setAuthHeader, passport.authenticate('jwt', { session: false }), UserController.changeUserPassword);
router.post('/logout', setAuthHeader, passport.authenticate('jwt', { session: false }), UserController.userLogout);
export default router

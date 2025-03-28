import { register, login, logout, sendVerifyOtp, verifyEmail, isAuthenticated, sendResetOtp, resetPassword } from "../Controllers/authController.js";
import express from 'express';
import authMiddleware from "../Middleware/authMiddleware.js";

const route = express.Router();

route.post('/register', register);
route.post('/login', login);
route.post('/logout', logout);
route.post('/send-verify-otp', authMiddleware, sendVerifyOtp);
route.post('/verify-account', authMiddleware, verifyEmail);
route.get('/is-auth', authMiddleware, isAuthenticated);
route.post('/send-reset-otp', sendResetOtp);
route.post('/reset-password', resetPassword)


export default route;
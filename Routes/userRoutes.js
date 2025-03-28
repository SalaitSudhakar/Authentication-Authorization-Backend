import express from 'express';
import { getUserData } from '../Controllers/userController.js';  
import authMiddleware from './../Middleware/authMiddleware.js';

const route = express.Router();

route.get('/data', authMiddleware, getUserData);

export default route
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const authMiddleware = async (req, res, next) => {

    try {

        if (!req.cookies || !req.cookies.token){
            return res.status(401).json({success: false, message: 'Token is missing'})
        }

        const token = req.cookies.token;

        if (!process.env.JWT_SECRET) {
            return res.status(500).json({success: false, message: 'JWT_SECRET is Missing'})
        }
        
       const tokenDecoded = jwt.verify(token, process.env.JWT_SECRET);
       
       if (tokenDecoded.id){
        req.body.userId = tokenDecoded.id
       } else {
        return res.status(401).json({success: false, message: 'Not Authorized. Login Again'})
       }

       next();

    } catch (error) {
       return res.status(500).json({success: false, message: error.message})
    }
}

export default authMiddleware;
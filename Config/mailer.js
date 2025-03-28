import nodemailer from 'nodemailer';


const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.PASS_MAIL,
        pass: process.env.PASS_KEY
    }
})

export default transporter;
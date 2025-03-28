import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import User from "../Models/userModel.js";
import transporter from "../Config/mailer.js";
import {
  EMAIL_VERIFY_TEMPLATE,
  PASSWORD_RESET_TEMPLATE,
} from "../utills/emailTemplates.js";

dotenv.config();

// Register
export const register = async (req, res) => {
  // Destructure json data from req.body
  const { name, email, password } = req.body;

  // validate datas
  if (!name || !email || !password) {
    return res.status(400).json({ success: false, message: "Missing Details" });
  }

  try {
    // Check for existing user with the same email
    const existingUser = await User.findOne({ email });

    // return if user already exist
    if (existingUser) {
      return res
        .status(409)
        .json({ success: false, message: "User already exists" });
    }

    // If user is not already exist , create new user
    // hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // store the user details in the database
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();

    // generate jwt token
    const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    /* Send Email */
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: email,
      subject: "Welcome to My Website",
      text: `Welcome to MySite. Your account has been created with email id: ${email} `,
    };

    try {
      await transporter.sendMail(mailOptions);
      console.log("Email sent successfully!");
    } catch (emailError) {
      console.error("Email sending failed:", emailError);
    }

    // return cookie and messages
    res
      .status(201)
      .cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "None" : "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000, // convert 7days into milli seconds
      })
      .json({ success: true, message: "User Registerd Successfully" });
  } catch (error) {
    // catch errors and return it to front end
    res.status(500).json({ success: false, message: error.message });
  }
};

// Login
export const login = async (req, res) => {
  // Destructure user login details
  const { email, password } = req.body;

  // validate the datas
  if (!email || !password) {
    return res
      .status(400)
      .json({ success: false, message: "Email and Password are required" });
  }

  try {
    // find the user from database using the received email
    const user = await User.findOne({ email });

    // if not user exists, return the message
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not exists or Invalid email" });
    }

    // If user exists and then
    // check for password match
    const isMatch = await bcrypt.compare(password, user.password);

    // if passsword does not match, send the message
    if (!isMatch) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid Password" });
    }

    // Generate the token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    // Send the token in cookie and return the messages
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "None" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // convert 7days into milli seconds
    });

    res
      .status(200)
      .json({ success: true, message: "User Loggedin successfully" });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
};

// Logout
export const logout = async (req, res) => {
  // Clear the token in the cookie
  try {
    res.clearCookie("token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
    });

    return res
      .status(200)
      .json({ success: true, message: "User Logged out successfully" });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
};

// Send Verification OTP
export const sendVerifyOtp = async (req, res) => {
  try {
    // Get userId and destructure it
    const { userId } = req.body;

    // Check for the user in database
    const user = await User.findById(userId);

    // if user not found, send message
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    // If Account already verified
    if (user.isAccoundVerified) {
      return res
        .status(409)
        .json({ success: false, message: "User is already verified" });
    }

    // Generate otp
    const otp = String(Math.floor(100000 + Math.random() * 900000));

    // store otp in database
    user.verifyOtp = otp;
    user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000; // 24 h in milliseconds from otp generated time

    // save in the database
    await user.save();

    // Send the otp to user mail;
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Account Verification",
      // text: `Your OTP is ${otp}. Verify your account using this OTP `,
      html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}", otp).replace(
        "{{email}}",
        user.email
      ),
    };
    await transporter.sendMail(mailOptions);

    res.status(200).json({ success: true, message: "otp send successfully" });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// Verify account
export const verifyEmail = async (req, res) => {
  try {
    // Destructure the data
    const { userId, otp } = req.body;

    // Validate data
    if (!userId || !otp) {
      return res
        .status(400)
        .json({ success: false, message: "UserId or OTP is missing" });
    }

    // Find the user from the database
    const user = await User.findById(userId);

    // If User not exists
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    // Validate and verify OTP
    if (user.verifyOtp === "" || user.verifyOtp != otp) {
      return res.status(401).json({ success: false, message: "Invalid OTP" });
    }

    // Check if the OTP expired
    if (user.verifyOtpExpireAt < Date.now()) {
      return res
        .status(410)
        .json({ success: false, message: "OTP is expired" });
    }

    // Make accound verify true and reset datas
    user.isAccountVerified = true;
    user.verifyOTP = "";
    user.verifyOtpExpireAt = 0;

    await user.save(); // save the change

    // return the success message
    return res
      .status(200)
      .json({ success: true, message: "email verified successfully" });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
};

// Check if a user is authenticated
export const isAuthenticated = async (req, res) => {
  res.status(200).json({ success: true, message: "User is authenticated" });
};

// Send password reset OTP
export const sendResetOtp = async (req, res) => {
  // Destructure Email
  const { email } = req.body;

  // Validate email
  if (!email) {
    return res
      .status(400)
      .json({ success: false, message: "Email is required" });
  }

  try {
    // Retrieve the user data from Database
    const user = await User.findOne({ email });

    // If user is not found
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "user not found" });
    }

    // Generate otp
    const otp = String(Math.floor(100000 + Math.random() * 900000));

    // store otp in database
    user.resetOtp = otp;
    user.resetOtpExpiredAt = Date.now() + 15 * 60 * 1000; // 15 minutes in milliseconds from otp generated time

    // save in the database
    await user.save();

    // Send the otp to user mail;
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Password reset Request",
      text: `Your Password reset OTP is ${otp}. Reset Password using this OTP `,
      html: PASSWORD_RESET_TEMPLATE.replace("{{otp}}", otp).replace(
        "{{email}}",
        user.email
      ),
    };
    await transporter.sendMail(mailOptions);

    res
      .status(200)
      .json({ success: true, message: "OTP sent to your email successfully" });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
};

// Reset User password
export const resetPassword = async (req, res) => {
  const { email, otp, newPassword } = req.body;

  console.log(email, otp, newPassword);
  if (!email || !otp || !newPassword) {
    res.status(400).json({
      success: false,
      message: "Email, OTP and new Password are required",
    });
  }

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    if (user.resetOtp === "" || user.resetOtp != otp) {
      return res.status(401).json({ success: false, message: "Invalid OTP" });
    }

    if (user.resetOtpExpiredAt < Date.now()) {
      return res
        .status(410)
        .json({ success: false, message: "OTP is expired" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedPassword;
    user.resetOtp = "";
    user.resetOtpExpireAt = 0;

    await user.save();

    res
      .status(200)
      .json({ success: true, message: "Password Reset successful" });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

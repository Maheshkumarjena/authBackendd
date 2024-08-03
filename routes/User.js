import express from 'express';
import bcrypt from 'bcrypt';
import User from '../models/user.js';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';

const router = express.Router();

const verifyUser = async (req, res, next) => {
  try {
    const token = req.cookies.token;
    
    if (!token) {
      return res.json({ status: false, message: "No token provided" });
    }

    await jwt.verify(token, process.env.KEY);
    next();
  } catch (err) {
    return res.json({ status: false, message: "Invalid token" });
  }
};

// Signup route
router.post('/signup', async (req, res) => {
  try {
    const { userName, email, password } = req.body.user;

    if (!userName || !email || !password) {
      return res.status(400).json({ message: 'Please enter all fields' });
    }

    const existingUsername = await User.findOne({ userName });
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    } else if (existingUsername) {
      return res.status(400).json({ message: 'Choose a different userName' });
    }

    const hashedPassword = await bcrypt.hash(password, 5);

    const newUser = new User({
      userName,
      email,
      password: hashedPassword,
    });

    await newUser.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error("Error during signup:", error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Login route
router.post('/login', async (req, res) => {
  const { EmOrUn, password } = req.body.user;

  if (!EmOrUn || !password) {
    return res.status(400).json({ message: 'Please enter all fields' });
  }

  try {
    const user = await User.findOne({ $or: [{ userName: EmOrUn }, { email: EmOrUn }] });

    if (!user) {
      return res.status(400).json({ message: 'User is not registered' });
    }

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(400).json({ message: 'Password is incorrect' });
    }

    const token = jwt.sign({ userName: user.userName }, process.env.KEY, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true, maxAge: 3600000 });
    res.cookie('user', user, { httpOnly: true, maxAge: 3600000 });

    return res.json({ status: true, message: 'Login successful', user });
  } catch (error) {
    console.error('Error during login:', error);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Forgot Password route
router.post('/forgotpassword', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.json({ status: false, message: "User is not registered" });
    }

    const token = jwt.sign({ id: user._id }, process.env.KEY, { expiresIn: '5m' });

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Reset Password',
      text: `Click the link to reset your password: http://localhost:3001/resetpassword/${token}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log("Error sending email:", error);
        return res.json({ status: false, message: "Error sending email" });
      } else {
        return res.json({ status: true, message: "Email sent" });
      }
    });
  } catch (error) {
    console.error("Error during forgot password:", error);
    return res.json({ status: false, message: "An error occurred" });
  }
});

// Reset Password route
router.put('/resetpassword/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    const decoded = await jwt.verify(token, process.env.KEY);
    const hashPassword = await bcrypt.hash(password, 10);
    await User.findByIdAndUpdate(decoded.id, { password: hashPassword });
    return res.json({ status: true, message: "Password updated successfully" });
  } catch (err) {
    console.error("Error during password reset:", err);
    return res.json({ status: false, message: "Invalid token" });
  }
});

// Verify route
router.get('/verify', verifyUser, (req, res) => {
  const username = req.cookies.user.userName;
  const email = req.cookies.user.email;
  return res.json({ status: true, message: "Authorized", username, email });
});

// Logout route
router.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.clearCookie('user');
  return res.json({ status: true, message: "Logged out successfully" });
});

export default router;

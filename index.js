import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import UserRouter from './routes/User.js';
import cors from 'cors';
import cookieParser from 'cookie-parser';

dotenv.config();

const app = express();

// CORS configuration

app.use(cors({
  origin: 'https://auth-frontend-alpha-nine.vercel.app', // Allow this origin
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  credentials: true, // Allow credentials
  optionsSuccessStatus: 204
}));


// Middleware
app.use(cookieParser());
app.use(express.json()); // Convert frontend data to JSON format

// Routes
app.use('/auth', UserRouter);

// Server configuration
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;

// Connect to MongoDB
mongoose.connect(MONGO_URI, {
 
})
  .then(() => {
    console.log("Connected to the database");

    // Start the server
    app.listen(PORT, () => {
      console.log(`Server is running on http://localhost:${PORT}`);
    });
  })
  .catch(err => {
    console.error("Database connection error:", err);
  });

// Additional error handling for uncaught errors
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  // application specific logging, throwing an error, or other logic here
});

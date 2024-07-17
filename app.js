import dotenv from 'dotenv';
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import passport from 'passport';
import userRoutes from './routes/admin/userRoutes.js';
import client from './config/databasepg.js'; // Import the connected client instance

import bodyParser from 'body-parser'
dotenv.config();

const app = express();
const port = process.env.PORT || 8000;

// CORS setup
const corsOptions = {
    origin: process.env.FRONTEND_HOST || 'http://localhost:3000',
    credentials: true,
    optionsSuccessStatus: 200,
};
app.use(bodyParser.json())
app.use(
    bodyParser.urlencoded({
        extended: true,
    })
)

app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());
app.use(passport.initialize());

// Load Routes
app.use("/api/user", userRoutes);

// PostgreSQL query using the imported client
// client.query(`SELECT * FROM users`, (error, result) => {
//     if (error) {
//         console.error('Error executing query:', error.message);
//     } else {
//         console.log('Query result:', result.rows);
//     }
//     // No need to end the client here, it should be managed globally
// });

// Start server
app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
});

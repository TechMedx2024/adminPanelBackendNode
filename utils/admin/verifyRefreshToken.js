import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import client from '../../config/databasepg.js'; // Adjust based on your PostgreSQL connection

dotenv.config();

const verifyRefreshToken = async (refreshToken) => {
    try {
        const privateKey = process.env.JWT_REFRESH_TOKEN_SECRET_KEY;

        // Query to fetch the user refresh token from PostgreSQL
        const findRefreshTokenQuery = `
            SELECT * FROM userrefreshtokens
            WHERE token = $1
        `;
        const { rows } = await client.query(findRefreshTokenQuery, [refreshToken]);
        const userRefreshToken = rows[0];

        // If refresh token not found, reject with an error
        if (!userRefreshToken) {
            throw { error: true, message: "Invalid refresh token" };
        }

        // Verify the refresh token
        const tokenDetails = jwt.verify(refreshToken, privateKey);

        // If verification succeeds, resolve with token details
        return {
            tokenDetails,
            error: false,
            message: "Valid refresh token",
        };
    } catch (error) {
        throw { error: true, message: "Invalid refresh token" };
    }
};

export default verifyRefreshToken;

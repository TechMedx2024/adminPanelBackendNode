// import jwt from 'jsonwebtoken';
// import dotenv from 'dotenv';
// import UserRefreshTokenModel from '../../models/admin/UserRefreshToken.js';
// dotenv.config();
// const generateTokens = async (user) => {
//     try {
//         const payload = {
//             _id: user._id,
//             roles: user.roles,
//         };
//         // generate access token with expiry date
//         const accessTokenExp = Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 1); // set token time expire in this time
//         const accessToken = jwt.sign({ ...payload, exp: accessTokenExp }, process.env.JWT_ACCESS_TOKEN_SECRET_KEY);


//         //generate refresh token with expiry date
//         const refreshTokenExp = Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 5); // 7 days
//         const refreshToken = jwt.sign({ ...payload, exp: refreshTokenExp }, process.env.JWT_REFRESH_TOKEN_SECRET_KEY);

//         const userRefreshToken = await UserRefreshTokenModel.findOneAndDelete({ userId: user._id })


//         // Save the new refresh token
//         await new UserRefreshTokenModel({ userId: user._id, token: refreshToken }).save();


//         return Promise.resolve({ accessToken, refreshToken, accessTokenExp, refreshTokenExp });
//     } catch (error) {
//         console.error('Error generating tokens:', error);
//         throw error;
//     }
// };

// export default generateTokens;


import jwt from 'jsonwebtoken';
import client from '../../config/databasepg.js'; // PostgreSQL pool configuration

const generateTokens = async (user) => {
    try {
        const payload = {
            user_id: user.user_id,
            role: user.role,
        };
        // Generate access token with expiry date (1 day)
        const accessTokenExp = Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 1);
        const accessToken = jwt.sign({ ...payload, exp: accessTokenExp }, process.env.JWT_ACCESS_TOKEN_SECRET_KEY);

        // Generate refresh token with expiry date (5 days)
        const refreshTokenExp = Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 5);
        const refreshToken = jwt.sign({ ...payload, exp: refreshTokenExp }, process.env.JWT_REFRESH_TOKEN_SECRET_KEY);

        // Delete existing refresh token if any
        await client.query('DELETE FROM userrefreshtokens WHERE user_id = $1', [user.user_id]);

        // Save the new refresh token
        const insertTokenQuery = `
            INSERT INTO userrefreshtokens (token, user_id)
            VALUES ($1, $2)
            RETURNING urfs_id
        `;
        const { rows } = await client.query(insertTokenQuery, [refreshToken, user.user_id]);

        return Promise.resolve({ accessToken, refreshToken, accessTokenExp, refreshTokenExp });
    } catch (error) {
        console.error('Error generating tokens:', error);
        throw error;
    }
};

export default generateTokens;

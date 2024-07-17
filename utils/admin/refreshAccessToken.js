import client from '../../config/databasepg.js'; // Adjust based on your PostgreSQL connection
import generateTokens from '../../utils/admin/generateTokens.js';
import verifyRefreshToken from './verifyRefreshToken.js'; // Assuming this verifies JWT refresh tokens

const refreshAccessToken = async (req, res) => {
    try {
        const oldRefreshToken = req.cookies.refreshToken;

        // Verify the refresh token
        const { tokenDetails, error } = await verifyRefreshToken(oldRefreshToken);
        if (error) {
            return res.status(401).send({ status: "failed", message: "Invalid refresh token" });
        }

        // Fetch user details from PostgreSQL
        const getUserQuery = `
            SELECT * FROM users
            WHERE user_id = $1
        `;
        const { rows } = await client.query(getUserQuery, [tokenDetails.user_id]);
        const user = rows[0];

        if (!user) {
            return res.status(404).send({ status: "failed", message: "User not found" });
        }

        // Fetch user's refresh token from PostgreSQL
        const getUserRefreshTokenQuery = `
            SELECT * FROM userrefreshtokens
            WHERE userId = $1
        `;
        const userRefreshTokenResult = await client.query(getUserRefreshTokenQuery, [tokenDetails.user_id]);
        const userRefreshToken = userRefreshTokenResult.rows[0];

        if (!userRefreshToken || oldRefreshToken !== userRefreshToken.token || userRefreshToken.blacklisted) {
            return res.status(401).send({ status: "failed", message: "Invalid or blacklisted refresh token" });
        }

        // Generate new tokens
        const { accessToken, refreshToken, accessTokenExp, refreshTokenExp } = await generateTokens(user);

        // Respond with new tokens
        return res.status(200).json({
            newAccessToken: accessToken,
            newRefreshToken: refreshToken,
            newAccessTokenExp: accessTokenExp,
            newRefreshTokenExp: refreshTokenExp
        });
    } catch (error) {
        console.error('Error during refresh token process:', error);
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).send({ status: "failed", message: 'Invalid refresh token' });
        }
        if (error.name === 'TokenExpiredError') {
            return res.status(401).send({ status: "failed", message: 'Refresh token expired' });
        }
        return res.status(500).send({ status: "failed", message: `Error verifying refresh token: ${error.message}` });
    }
};

export default refreshAccessToken;

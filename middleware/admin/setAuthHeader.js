// import dotenv from 'dotenv';
import isTokenExpire from '../../utils/admin/isTokenExpired.js';
import refreshAccessToken from "../../utils/admin/refreshAccessToken.js";
import setTokensCookies from "../../utils/admin/setTokensCookies.js";

// dotenv.config();

// const setAuthHeader = async (req, res, next) => {
//     try {
//         const accessToken = req.cookies.accessToken;

//         if (accessToken && !isTokenExpire(accessToken)) {
//             req.headers['authorization'] = `Bearer ${accessToken}`;
//         } else if (!accessToken || isTokenExpire(accessToken)) {
//             const refreshToken = req.cookies.refreshToken;
//             if (!refreshToken) {
//                 return res.status(401).json({ error: 'Unauthorized', message: 'Refresh Token is missing' });
//             }

//             const { newAccessToken, newRefreshToken, newAccessTokenExp, newRefreshTokenExp } = await refreshAccessToken(req, res);

//             // Set the new tokens as cookies
//             setTokensCookies(res, newAccessToken, newRefreshToken, newAccessTokenExp, newRefreshTokenExp);

//             // Update the authorization header with the new access token
//             req.headers['authorization'] = `Bearer ${newAccessToken}`;
//         }

//         // Proceed to the next middleware
//         next();
//     } catch (error) {
//         // Handle any errors by sending a response and ensuring no further response methods are called
//         if (!res.headersSent) {
//             res.status(401).json({ error: 'Unauthorized', message: 'Access token is missing or invalid' });
//         }
//     }
// };

// export default setAuthHeader;


const setAuthHeader = async (req, res, next) => {
    try {
        const accessToken = req.cookies.accessToken;

        if (accessToken && !isTokenExpire(accessToken)) {
            req.headers['authorization'] = `Bearer ${accessToken}`;
            next(); // Proceed to next middleware
        } else if (!accessToken || isTokenExpire(accessToken)) {
            const refreshToken = req.cookies.refreshToken;
            if (!refreshToken) {
                return res.status(401).json({ error: 'Unauthorized', message: 'Refresh Token is missing' });
            }

            const { newAccessToken, newRefreshToken, newAccessTokenExp, newRefreshTokenExp } = await refreshAccessToken(req, res);

            // Set the new tokens as cookies
            setTokensCookies(res, newAccessToken, newRefreshToken, newAccessTokenExp, newRefreshTokenExp);

            // Update the authorization header with the new access token
            req.headers['authorization'] = `Bearer ${newAccessToken}`;
            next(); // Proceed to next middleware
        }
    } catch (error) {
        console.error('Error in setAuthHeader middleware:', error);
        if (!res.headersSent) {
            res.status(401).json({ error: 'Unauthorized', message: 'Access token is missing or invalid' });
        }
    }
};

export default setAuthHeader;


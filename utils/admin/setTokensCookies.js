// const setTokensCookies = (res, accessToken, refreshToken, newAccessTokenExp, newRefreshTokenExp) => {
//     const accessTokenMaxAge = (newAccessTokenExp - Math.floor(Date.now() / 1000)) + (60 * 60 * 24 * 1); // Convert to milliseconds
//     const refreshTokenMaxAge = (newRefreshTokenExp - Math.floor(Date.now() / 1000)) + (60 * 60 * 24 * 5); // Convert to milliseconds
//     if (isNaN(accessTokenMaxAge) || isNaN(refreshTokenMaxAge)) {
//         throw new Error('Invalid maxAge for cookies');
//     }
//     // Set access token
//     res.cookie('accessToken', accessToken, {
//         httpOnly: true,
//         secure: process.env.JWT_ACCESS_TOKEN_SECRET_KEY === 'production',
//         maxAge: accessTokenMaxAge,
//     });
//     // Set refresh token
//     res.cookie('refreshToken', refreshToken, {
//         httpOnly: true,
//         secure: process.env.JWT_ACCESS_TOKEN_SECRET_KEY === 'production',
//         maxAge: refreshTokenMaxAge,
//     });
//     res.cookie('is_auth', true, { secure: true });

// };

// export default setTokensCookies;


const setTokensCookies = (res, accessToken, refreshToken, newAccessTokenExp, newRefreshTokenExp) => {
    // Calculate the max age in milliseconds
    const accessTokenMaxAge = (newAccessTokenExp - Math.floor(Date.now() / 1000)) * 1000; // Convert seconds to milliseconds
    const refreshTokenMaxAge = (newRefreshTokenExp - Math.floor(Date.now() / 1000)) * 1000; // Convert seconds to milliseconds

    // Check if maxAge calculations are valid numbers
    if (isNaN(accessTokenMaxAge) || isNaN(refreshTokenMaxAge)) {
        throw new Error('Invalid maxAge for cookies');
    }

    // Set access token cookie
    res.cookie('accessToken', accessToken, {
        httpOnly: true,
        secure: process.env.JWT_ACCESS_TOKEN_SECRET_KEY === 'production',
        maxAge: accessTokenMaxAge,
    });

    // Set refresh token cookie
    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.JWT_ACCESS_TOKEN_SECRET_KEY === 'production',
    });

    // Set authentication flag cookie
    res.cookie('is_auth', true, { secure: true });
};

export default setTokensCookies;

import jwt from 'jsonwebtoken';
import UserRefreshTokenModel from '../../models/admin/UserRefreshToken.js';

export const generateTokens = async (user) => {
    try {
        const payload = { _id: user._id, roles: user.roles };
        const accessTokenExp = Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 1); // set expiry time
        const accessToken = jwt.sign({ ...payload, exp: accessTokenExp }, process.env.JWT_ACCESS_TOKEN_SECRET_KEY);

        const refreshTokenExp = Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 5; // expires in 5 days from now
        const refreshToken = jwt.sign({ ...payload, exp: refreshTokenExp }, process.env.JWT_REFRESH_TOKEN_SECRET_KEY);

        await UserRefreshTokenModel.findOneAndUpdate(
            { userId: user._id },
            { token: refreshToken },
            { new: true, upsert: true }
        );

        return { accessToken, refreshToken, accessTokenExp, refreshTokenExp };
    } catch (error) {
        throw new Error('Unable to generate tokens');
    }
};

export const refreshAccessToken = async (req, res) => {
    try {
        const refreshToken = req.cookies.refresh_token;
        if (!refreshToken) {
            throw new Error('Refresh token not found');
        }

        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_TOKEN_SECRET_KEY);
        const user = await UserModel.findOne({ _id: decoded._id });
        if (!user) {
            throw new Error('User not found');
        }

        const payload = { _id: user._id, roles: user.roles };
        const newAccessTokenExp = Math.floor(Date.now() / 1000) + 100; // set expiry time
        const newAccessToken = jwt.sign({ ...payload, exp: newAccessTokenExp }, process.env.JWT_ACCESS_TOKEN_SECRET_KEY);

        const newRefreshTokenExp = Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 5; // expires in 5 days from now
        const newRefreshToken = jwt.sign({ ...payload, exp: newRefreshTokenExp }, process.env.JWT_REFRESH_TOKEN_SECRET_KEY);

        await UserRefreshTokenModel.findOneAndUpdate(
            { userId: user._id },
            { token: newRefreshToken },
            { new: true, upsert: true }
        );

        return { newAccessToken, newRefreshToken, newAccessTokenExp, newRefreshTokenExp };
    } catch (error) {
        console.error(error);
        throw new Error('Unable to generate a new token');
    }
};

export const setTokensCookies = (res, accessToken, refreshToken, accessTokenExp, refreshTokenExp) => {
    res.cookie('access_token', accessToken, { httpOnly: true, expires: new Date(accessTokenExp * 1000) });
    res.cookie('refresh_token', refreshToken, { httpOnly: true, expires: new Date(refreshTokenExp * 1000) });
};

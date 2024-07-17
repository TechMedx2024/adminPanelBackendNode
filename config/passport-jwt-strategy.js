// import passport from "passport";
// import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";
// import UserModel from "../models/admin/User.js";

// import dotenv from "dotenv";

// dotenv.config();

// const opts = {
//     jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
//     secretOrKey: process.env.JWT_ACCESS_TOKEN_SECRET_KEY,
// };

// passport.use(new JwtStrategy(opts, async (jwtPayload, done) => {
//     try {
//         // Find user by ID from JWT payload
//         const user = await UserModel.findOne({ _id: jwtPayload._id }, '-password');

//         if (user) {
//             return done(null, user); // Found user, pass user to next middleware
//         } else {
//             return done(null, false); // User not found
//         }
//     } catch (error) {
//         return done(error, false); // Error while searching for user
//     }
// }));

import passport from 'passport';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import client from './databasepg.js';

const opts = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_ACCESS_TOKEN_SECRET_KEY,
};

passport.use(
    new JwtStrategy(opts, async (jwtPayload, done) => {
        try {
            // Query to fetch user by ID from JWT payload
            const queryText = 'SELECT * FROM users WHERE user_id = $1';
            const { rows } = await client.query(queryText, [jwtPayload.user_id]);

            if (rows.length > 0) {
                const user = rows[0];
                // Remove sensitive information like password before passing to the next middleware
                delete user.password_hash;
                return done(null, user);
            } else {
                return done(null, false); // User not found
            }
        } catch (error) {
            return done(error, false); // Error while querying database
        }
    })
);

export default passport;

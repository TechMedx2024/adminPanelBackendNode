import UserModel from "../../models/admin/User.js";
import bcrypt from 'bcrypt'
import sendEmailVerificationOTP from "../../utils/admin/sendEmailVerificationOTP.js";
import generateTokens from "../../utils/admin/generateTokens.js";
import setTokensCookies from "../../utils/admin/setTokensCookies.js";
import refreshAccessToken from "../../utils/admin/refreshAccessToken.js";
import logUserLogout from "../../utils/admin/logUserLogout.js";
import logUserLogin from "../../utils/admin/logUserLogin.js";
import transporter from "../../config/emailConfig.js";
import jwt from "jsonwebtoken";
import client from '../../config/databasepg.js';
class UserController {

  // ======================================================================================================================================================
  //   USER REGISTRATION
  // ======================================================================================================================================================

  static userRegistration = async (req, res) => {
    try {
      const { username, full_name, email, phone, password_hash, password_confirmation, country_code } = req.body;

      // Check if all required fields are provided
      if (!username || !full_name || !email || !phone || !password_hash || !password_confirmation || !country_code) {
        return res.status(400).json({ status: "failed", message: "All fields are required" });
      }

      // Check if password and password_confirmation match
      if (password_hash !== password_confirmation) {
        return res.status(400).json({ status: "failed", message: "Password and confirm password do not match" });
      }

      // Check if username already exists
      const usernameQuery = 'SELECT * FROM users WHERE username = $1';
      const usernameResult = await client.query(usernameQuery, [username]);
      if (usernameResult.rows.length > 0) {
        return res.status(400).json({ status: "failed", message: "Username already exists, please try again with another username" });
      }

      // Check if email already exists
      const emailQuery = 'SELECT * FROM users WHERE email = $1';
      const emailResult = await client.query(emailQuery, [email]);
      if (emailResult.rows.length > 0) {
        return res.status(400).json({ status: "failed", message: "Email already exists, please try again with another email" });
      }

      // Check if phone number already exists
      const phoneQuery = 'SELECT * FROM users WHERE phone = $1';
      const phoneResult = await client.query(phoneQuery, [phone]);
      if (phoneResult.rows.length > 0) {
        return res.status(400).json({ status: "failed", message: "Phone number already exists, please try again with another phone number" });
      }

      // Generate salt and hash password
      const saltRounds = Number(process.env.SALT) || 10; // Default to 10 if process.env.SALT is not set
      const hashedPassword = await bcrypt.hash(password_hash, saltRounds);

      // Determine role (ensure it is valid)
      const allowedRoles = ['Customer', 'Admin', 'Seller', 'SEOperson'];
      const role = req.body.role && allowedRoles.includes(req.body.role) ? req.body.role : 'Customer';

      // Insert new user into database
      const insertQuery = `
            INSERT INTO users (
                username, 
                password_hash, 
                email, 
                phone, 
                full_name, 
                role, 
                status, 
                is_verified,
                country_code
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING user_id, username, email, phone, role, status
        `;
      const values = [
        username,
        hashedPassword,
        email,
        phone,
        full_name || null,
        role,
        'Inactive', // Default status to 'Inactive'
        false,      // Default is_verified to false
        country_code,
      ];

      const newUser = await client.query(insertQuery, values);
      const user = newUser.rows[0];
      const delayInSeconds = 10;

      // Implementing the delay
      setTimeout(async () => {
        await sendEmailVerificationOTP(user);
      }, delayInSeconds * 1000);
      // await sendEmailVerificationOTP(user);
      // Send success response
      res.status(200).json({
        status: "success",
        message: "Registration successful",
        user: newUser.rows[0],
      });
    } catch (error) {
      console.error(error);
      // Send fail response
      res.status(500).json({ status: "failed", message: "Unable to register, please try again later" });
    }
  };



  // =============================================================================================================================================
  //User Email OTP Verification

  // static verificationEmail = async (req, res) => {
  //   try {
  //     // extract request body parameaaters
  //     const { email, otp } = req.body;

  //     // check if all fields are provided
  //     if (!email || !otp) {
  //       return res.status(400).json({ status: "failed", message: "All fields required" });
  //     }

  //     //check user exist or not
  //     const existingUser = await UserModel.findOne({ email });
  //     //if email dosn't exist
  //     if (!existingUser) {
  //       return res.status(404).json({ status: "failed", message: "Email doesn't exist" });
  //     }

  //     //check if email is already verified
  //     if (existingUser.is_verified) {
  //       return res.status(400).json({ status: "failed", message: "Email already exist" });
  //     }

  //     //check if there is a matching email and veridication OTP
  //     const emailVerification = await EmailVerificationModel.findOne({ userId: existingUser._id, otp });
  //     if (!emailVerification) {
  //       if (!existingUser.is_verified) {
  //         await sendEmailVerificationOTP(req, existingUser);
  //         return res.status(400).json({ status: "failed", message: "Invalid OTP new OTP send to your email" });
  //       }
  //     }
  //     // check if OTP is expired
  //     const currentTime = new Date();
  //     const expirationTime = new Date(emailVerification.createdAt.getTime() + 15 * 60 * 1000);
  //     if (currentTime > expirationTime) {
  //       await sendEmailVerificationOTP(req, existingUser);
  //       return res.status(400).json({ status: "failed", message: "OTP expires new OTP sends to your email" });
  //     }


  //     //OTP is valid and not expired, make email as verified
  //     // existingUser.is_verified = true;
  //     await existingUser.save();

  //     //Delete email verification document
  //     await EmailVerificationModel.deleteMany({ userId: existingUser._id })
  //     return res.status(200).json({ status: "success", message: "Email Verified successfully" });
  //   } catch (error) {
  //     console.error(error);
  //     return res.status(500).json({ status: "failed", message: "Unable to verify email, please try again later" });
  //   }
  // }
  // ======================================================================================================================================================
  //   USER login
  // ======================================================================================================================================================

  static userLogin = async (req, res) => {
    try {
      const { email, password_hash } = req.body;

      // Check if email and password_hash are provided
      if (!email || !password_hash) {
        return res.status(400).json({ status: "failed", message: "Email and Password are required" });
      }

      // Query to find user by email
      const query = `
            SELECT *
            FROM users
            WHERE email = $1
        `;
      const { rows } = await client.query(query, [email]);

      // Check if user exists
      if (rows.length === 0) {
        return res.status(404).json({ status: "failed", message: "Invalid email or password" });
      }

      const user = rows[0];

      // Compare hashed passwords
      const isMatch = await bcrypt.compare(password_hash, user.password_hash);
      if (!isMatch) {
        return res.status(401).json({ status: "failed", message: "Invalid email or password" });
      }

      // Check if user is banned
      if (user.status == 'Banned') {
        return res.status(401).json({ status: "failed", message: "Unable to login, please try again later" });
      }
      if (user.is_verified && user.status === 'Active') {
        return res.status(401).json({ status: "failed", message: "Unable to login, please try again later" });

      }
      // Check if user needs OTP verification
      if (!user.is_verified) {
        // Delay before sending OTP (10 seconds as requested)
        const delayInSeconds = 10;
        setTimeout(async () => {
          await sendEmailVerificationOTP(user);
        }, delayInSeconds * 1000);
        return res.status(200).json({ status: "success", message: "To Verify User must Perform OTP process" });
      }

      // If user is verified and status is 'Active', proceed with login

      res.status(200).json({
        user: { id: user.user_id, email: user.email, name: user.full_name, roles: user.roles },
        status: "success",
        message: "Login successful",
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ status: "failed", message: "Unable to login, please try again later" });
    }
  };


  // ======================================================================================================================================================
  //   EMAIL OTP VERIFICATION
  // ======================================================================================================================================================


  static verifyOTP = async (req, res) => {
    try {

      const { email, otp } = req.body;

      // Check if email or otp is missing
      if (!email || !otp) {
        return res.status(400).json({ status: "failed", message: "Email and OTP are required" });
      }

      // Query to retrieve user information based on email and otp
      const query = `
    SELECT u.user_id, u.username, u.email, u.full_name, u.role, u.status
    FROM users u
    JOIN emailverifications e ON u.user_id = e.user_id
    WHERE u.email = $1 AND e.otp = $2
`;
      // Execute the query
      const { rows } = await client.query(query, [email, otp]);
      // If no matching record found, return failure response
      if (rows.length === 0) {
        return res.status(404).json({ status: 'failed', message: 'Invalid email or OTP' });
      }

      // Update user's is_verified status and set status to 'Active'
      const updateUserQuery = `
    UPDATE users
    SET is_verified = true,
        status = 'Active'
    WHERE user_id = $1
    RETURNING user_id, username, email, full_name, role, status
`;
      const updateUser = await client.query(updateUserQuery, [rows[0].user_id]);

      // Remove OTP record from emailverifications table
      const deleteOTPQuery = `
    DELETE FROM emailverifications
    WHERE user_id = $1
`;
      await client.query(deleteOTPQuery, [rows[0].user_id]);

      // Log user login and get device info
      const deviceInfo = await logUserLogin(rows[0], new Date());
      // Generate tokens
      const { accessToken, refreshToken, accessTokenExp, refreshTokenExp } = await generateTokens(rows[0]);
      setTokensCookies(res, accessToken, refreshToken, accessTokenExp, refreshTokenExp);
      // Return success response with tokens and other details
      res.status(200).json({
        status: 'success',
        message: 'OTP verified and user verified',
        user: updateUser.rows[0],
        access_token: accessToken,
        refresh_token: refreshToken,
        access_token_exp: accessTokenExp,
        refresh_token_exp: refreshTokenExp, // Ensure you include refresh token expiry if needed
        is_auth: true,
        deviceInfo
      });

    } catch (error) {
      console.error('Error verifying OTP:', error);
      res.status(500).json({ status: 'failed', message: 'Unable to verify OTP' });
    }
  };


  // ======================================================================================================================================================
  //   GET ACCESS TOKEN
  // ======================================================================================================================================================

  static getNewAccessToken = async (req, res) => {
    try {
      const { newAccessToken, newRefreshToken, newAccessTokenExp, newRefreshTokenExp } = await refreshAccessToken(req, res);

      // Set cookies with new tokens
      setTokensCookies(res, newAccessToken, newRefreshToken, newAccessTokenExp, newRefreshTokenExp);

      // Send success response with new tokens
      res.status(200).json({
        status: "success",
        message: "New tokens generated",
        access_token: newAccessToken,
        refresh_token: newRefreshToken,
        access_token_exp: newAccessTokenExp,
        refresh_token_exp: newRefreshTokenExp // Ensure you also include refresh token expiry if needed
      });
    } catch (error) {
      console.error('Error generating new access token:', error.message);
      res.status(401).json({ error: true, message: error.message });
    }
  };
  // ======================================================================================================================================================
  //   USER PROFILE
  // ======================================================================================================================================================
  static userProfile = async (req, res) => {
    res.send({ "user": req.user });
  }

  // ======================================================================================================================================================
  //   GET ALL USERS
  // ======================================================================================================================================================

  static getAllUsers = (req, res) => {
    client.query('SELECT * FROM users', (error, results) => {
      if (error) {
        console.error('Error querying users:', error);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      if (!res.headersSent) {
        res.status(200).json(results.rows);
      }
    });
  };


  // ======================================================================================================================================================
  //   CHANGE USER PASSWORD
  // ======================================================================================================================================================


  static changeUserPassword = async (req, res) => {
    try {
      const { password, password_confirmation } = req.body;

      if (!password || !password_confirmation) {
        return res.status(400).json({ status: "fails", message: "New password and confirm password required" });
      }

      if (password !== password_confirmation) {
        return res.status(400).json({ status: "fails", message: "New password and confirm password not matched" });
      }

      // Generate salt and hash the new password
      const salt = await bcrypt.genSalt(10);
      const newHashPassword = await bcrypt.hash(password, salt);

      // Update the user's password in the database
      await UserModel.findByIdAndUpdate(req.user._id, {
        $set: { password: newHashPassword }
      });

      // Respond with success message
      res.status(200).json({ status: "success", message: "Password changed successfully" });
    } catch (error) {
      console.error('Change password error:', error);
      res.status(500).json({ status: "fails", message: "Email is Required" });
    }
  };

  // ======================================================================================================================================================
  //   RESET PASSWORD LINK VIA EMAIL
  // ======================================================================================================================================================

  static sendUserPasswordResetEmail = async (req, res) => {
    try {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({ status: "fails", message: "Email is required" });
      }

      const user = await UserModel.findOne({ email });

      if (!user) {
        return res.status(404).json({ status: "fails", message: "Email does not exist" });
      }

      // Generate token for password reset
      const secret = user._id + process.env.JWT_ACCESS_TOKEN_SECRET_KEY;
      const token = jwt.sign({ userId: user._id }, secret, { expiresIn: '15m' });
      const resetLink = `${process.env.FRONTEND_HOST}/account/reset-password-confirm/${user._id}/${token}`;

      // Send password reset email
      await transporter.sendMail({
        from: process.env.EMAIL_FROM,
        to: user.email,
        subject: "Password Reset Link",
        html: `<p>Hello ${user.name},</p><p>Please <a href="${resetLink}">click here - ${resetLink}</a> to reset your password.</p>`
      });

      res.status(200).json({ status: "success", message: "Password reset email sent successfully" });
    } catch (error) {
      console.error('Password reset email error:', error);
      res.status(500).json({ status: "fails", message: "Unable to send password reset email, Please try again later" });
    }
  };

  // ======================================================================================================================================================
  //   USER PASSWORD RESET
  // ======================================================================================================================================================

  static userPasswordReset = async (req, res) => {
    try {
      const { password, password_confirmation } = req.body;
      const { id, token } = req.params;

      const user = await UserModel.findById(id);
      if (!user) {
        return res.status(404).json({ status: 'failed', message: "User not found" });
      }

      // Verify token
      const new_secret = user._id + process.env.JWT_ACCESS_TOKEN_SECRET_KEY;
      jwt.verify(token, new_secret);

      if (!password || !password_confirmation) {
        return res.status(400).json({ status: "fails", message: "New Password and Confirm Password Required" });
      }

      // Check if password and confirm password match
      if (password !== password_confirmation) {
        return res.status(400).json({ status: "fails", message: "New Password and Confirm Password do not match" });
      }

      // Generate salt and hash new password
      const salt = await bcrypt.genSalt(10);
      const newHashPassword = await bcrypt.hash(password, salt);

      // Update user's password
      await UserModel.findByIdAndUpdate(user._id, { password: newHashPassword });

      // Send success response
      return res.status(200).json({ status: 'success', message: 'Password reset successful' });

    } catch (error) {
      if (error.name === "TokenExpiredError") {
        return res.status(400).json({ status: "fails", message: "Token expired, please request a new reset link" });
      }
      console.error('Password reset error:', error);
      return res.status(500).json({ status: "fails", message: "Unable to reset password, please try again later" });
    }
  };


  // ======================================================================================================================================================
  //   USER REGISTRATION
  // ======================================================================================================================================================


  static userLogout = async (req, res) => {
    try {
      const refreshToken = req.cookies.refreshToken;

      if (!refreshToken) {
        return res.status(400).json({ status: "failed", message: "Refresh token not found" });
      }

      // Blacklist the refresh token in the database
      const queryText = `
            UPDATE userrefreshtokens
            SET blacklisted = TRUE
            WHERE token = $1
            RETURNING user_id
        `;
      const { rows } = await client.query(queryText, [refreshToken]);

      if (rows.length === 0) {
        return res.status(404).json({ status: "failed", message: "Invalid refresh token" });
      }

      const userId = rows[0].user_id;

      // Update user status in the 'users' table
      const updateUserQuery = `
            UPDATE users
            SET is_verified = FALSE,
                status = 'Inactive'
            WHERE user_id = $1
            RETURNING username, email
        `;
      const userUpdateResult = await client.query(updateUserQuery, [userId]);

      if (userUpdateResult.rows.length === 0) {
        return res.status(404).json({ status: "failed", message: "User not found" });
      }
      console.log("this is row", rows[0])
      await logUserLogout(rows[0], new Date());
      // Clear cookies
      res.clearCookie('accessToken');
      res.clearCookie('refreshToken');
      res.clearCookie('is_auth');

      res.status(200).json({ status: "success", message: "Logged out successfully" });
    } catch (error) {
      console.error('Logout error:', error);
      res.status(500).json({ status: "fails", message: "Unable to logout, please try again later" });
    }
  };

  // ==================================================================================================================================


}

export default UserController;
import transporter from "../../config/emailConfig.js";
import client from "../../config/databasepg.js";

const sendEmailVerificationOTP = async (user) => {
    console.log("this is my email", user.email)
    try {
        // Generate 4 digit number OTP
        const otp = Math.floor(1000 + Math.random() * 9000).toString();

        // Save OTP in database
        const insertQuery = `
            INSERT INTO emailverifications (user_id, otp)
            VALUES ($1, $2)
            RETURNING email_id, user_id, otp
        `;
        const values = [user.user_id, otp];
        const { rows } = await client.query(insertQuery, values);

        // OTP verification link (adjust as needed)
        const otpVerificationLink = `${process.env.FRONTEND_HOST}/account/verify-email`;

        // Send OTP email
        await transporter.sendMail({
            from: process.env.EMAIL_FROM,
            to: user.email,
            subject: "OTP - Verify your account",
            html: `
                <p>Dear ${user.name},</p>
                <p>Welcome to MedX Pharmacy. To complete your Authentication, please verify your email address by entering the following one-time password (OTP):</p>
                <h2>OTP: ${otp}</h2>
                <p>This OTP is valid for 15 minutes. If you didn't request this OTP, please ignore this email.</p>
            `
        });

        console.log(`OTP sent to ${user.email}: ${otp}`);
    } catch (error) {
        console.error("Error sending OTP email:", error);
    }
};

export default sendEmailVerificationOTP;

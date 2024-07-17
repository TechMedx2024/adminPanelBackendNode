import transporter from "../../config/emailConfig.js";
import EmailVerificationModel from "../../models/admin/EmailVerification.js";

const sendEmailVerificationOTPLogin = async (user) => {
    try {
        // Generate 4 digit number OTP
        const otp = Math.floor(1000 + Math.random() * 9000).toString();

        // Save OTP in database
        await new EmailVerificationModel({ userId: user._id, otp: otp }).save();

        // OTP verification link
        const otpVerificationLink = `${process.env.FRONTEND_HOST}/account/verify-email-login`;

        await transporter.sendMail({
            from: process.env.EMAIL_FROM,
            to: user.email,
            subject: "OTP - Verify your account",
            html: `
                <p>Dear ${user.name},</p>
                <p>Welcome to MedX Pharmacy. To complete your authorization process, please verify your email address by entering the following one-time password (OTP):</p>
                <h2>OTP: ${otp}</h2>
                <p>This OTP is valid for 15 minutes. If you didn't request this OTP, please ignore this email.</p>
                
            `
        });

        console.log(`OTP sent to ${user.email}: ${otp}`);
    } catch (error) {
        console.error("Error sending OTP email:", error);
    }
};

export default sendEmailVerificationOTPLogin;

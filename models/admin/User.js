import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Name is required'],
        trim: true,
        minlength: [3, 'Name must be at least 3 characters long'],
        maxlength: [50, 'Name must be at most 50 characters long']
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        trim: true,
        unique: true,
        lowercase: true,
        match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email address']
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        trim: true,
        minlength: [8, 'Password must be at least 8 characters long']
    },
    is_verified: {
        type: Boolean,
        default: false
    },
    roles: {
        type: [String],
        enum: ["user", "manager", "admin"],
        default: ["user"]
    },
    status: {
        type: String,
        enum: ["active", "inactive", "block"],
        default: "active"
    },
    phone: {
        type: String,
        required: [true, 'Phone number is required'],
        trim: true,
        unique: true,
        match: [/^\+?[0-9]+$/, 'Please enter a valid phone number']
    },
    created_at: {
        type: Date,
        default: Date.now
    },
    updated_at: {
        type: Date,
        default: Date.now
    }
},);

// Model
const UserModel = mongoose.model("user", userSchema);
export default UserModel;

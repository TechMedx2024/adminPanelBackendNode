import mongoose from 'mongoose';

const userLogSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'User' },
    email: { type: String, required: true },
    name: { type: String, required: true },
    loginStatus: { type: String, required: true },
    loginTime: { type: Date, required: true },
    deviceDetails: {
        type: Map,
        of: String,
        required: false // Make this field optional
    },
    // Other fields as needed
});

export default mongoose.model('UserLog', userLogSchema);

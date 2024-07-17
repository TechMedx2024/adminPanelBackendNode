import mongoose from "mongoose";
const dbUrl = process.env.DATABASE_URL
const connectDB = async (DATABASE_URL) => {
    try {
        const DB_OPTIONS = {
            dbName: process.env.DATABASE_NAME
        }
        await mongoose.connect(DATABASE_URL, DB_OPTIONS)
        console.log("Database Connected Successfully.....")
    } catch (error) {
        console.log(error)

    }
}


export default connectDB
import mongoose from "mongoose";

const testSchema = new mongoose.Schema({

})


// Model
const TestModel = mongoose.model("test", testSchema) 
export default TestModel
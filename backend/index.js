import express from "express";
import dotenv from "dotenv"

import authRoutes from "./routes/auth.route.js";
import { connectDB } from "./db/connectDB.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3002;



app.use("/api/auth", authRoutes);

app.listen(PORT, () => {
    connectDB();
    console.log("server is running on port : "+ PORT);
})
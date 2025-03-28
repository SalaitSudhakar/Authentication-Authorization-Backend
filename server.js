import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import connectDb from "./Database/Config.js";
import authRoute from "./Routes/authRoutes.js";
import userRoute from "./Routes/userRoutes.js";

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

const allowedOrigins = ["http://localhost:5173", "http://localhost:5174"];

app.use(express.json()); // parse the data from front end as json object
app.use(cors({ origin: allowedOrigins, credentials: true })); // enables cors (cross origin resource sharing) in our express server. credentials: true used to allow cookie-parser
app.use(cookieParser()); // enable cookie parser

//API endpoints
app.get("/", (req, res) => {
  res.send("Welcome to my API");
});
app.use("/api/auth", authRoute);
app.use("/api/user", userRoute);

// connect database to the server
connectDb();

// Start the server
app.listen(port, () => {
  console.log("Server is started and running on port");
});

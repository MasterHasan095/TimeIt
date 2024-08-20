import express from "express";
import { config } from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import mongoose from "mongoose";
import User from "./models/userModel.js";
config();
const app = express();
app.use(express.json());

const users = [];

mongoose
  .connect(process.env.mongoDBURL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log(`App connected to database`);
    app.listen(process.env.PORT || 5500, () => {
      console.log(`App is running on port ${process.env.PORT || 5500}`);
    });
  })
  .catch((error) => {
    console.error("Error connecting to MongoDB:", error);
  });

app.post("/register", async (req, res) => {
    console.log("Checkpoint 1");
  const { username, password } = req.body;

  try {
    const existingUser = await User.findOne({ username });
    console.log("Checkpoint 2");

    if (existingUser) {
      return res.status(409).send("Username already taken");
    }
    console.log("Checkpoint 3");

    const hashedPassword = await bcrypt.hash(password, 10);
    console.log("Checkpoint 4");

    const newUser = new User({ username, password: hashedPassword });
    console.log("Checkpoint 5");

    await newUser.save();
    console.log("Checkpoint 6");

    res.status(201).send("User registered");
    console.log("Checkpoint 7");

  } catch (error) {
    res.status(500).send("Error registering user");
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(404).send("User not found");

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).send("Invalid credentials");

    const token = jwt.sign(
      { username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.json({ token });
  } catch (error) {
    res.status(500).send("Error during login");
  }
});

app.get("/protected", authenticateToken, (req, res) => {
  res.status(200).send(`Hello ${req.user.username}, this is a protected route`);
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

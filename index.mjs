import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import bodyParser from "body-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import connectDB from "./db.js";
import Product from "./model/product.js";
import { PORT } from "./PORT.mjs";

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Connect to MongoDB
connectDB();

// In-memory storage (replace with a proper database in production)
const users = [];
const logs = [];

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    console.log("No token provided");
    return res.sendStatus(401); // Unauthorized
  }

  jwt.verify(token, process.env.JWT_SECRET || "your-secret-key", (err, user) => {
    if (err) {
      console.log("Invalid token");
      return res.sendStatus(403); // Forbidden
    }
    req.user = user; // Attach user info to request object
    next(); // Continue to the next middleware or route handler
  });
};

// API Endpoints
// Register
app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json({ error: "Error registering user" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = users.find((u) => u.username === username);

    if (!user) {
      return res.status(400).json({ error: "User not found" });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: "Invalid password" });
    }

    const token = jwt.sign({ username }, process.env.JWT_SECRET || "your-secret-key");
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: "Error logging in" });
  }
});

// Forgot Password
app.post("/api/forgot-password", async (req, res) => {
  try {
    const { username, newPassword } = req.body;

    const user = users.find((u) => u.username === username);
    if (!user) {
      return res.status(400).json({ error: "User not found" });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    res.json({ message: "Password updated successfully" });
  } catch (error) {
    res.status(500).json({ error: "Error resetting password" });
  }
});

// Add a product
app.post("/products", async (req, res) => {
  const { title, description, categories } = req.body;

  try {
    const product = new Product({
      title,
      description,
      categories: categories.split(",").map((cat) => cat.trim()),
    });
    const savedProduct = await product.save();
    console.log("Saved Product:", savedProduct); // Log to confirm save
    res.status(201).json({ message: "Product added successfully", product: savedProduct });
  } catch (error) {
    res.status(500).json({ error: "Failed to add product", details: error.message });
  }
});

// Get all products
app.get("/products", async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch products", details: error.message });
  }
});

// Add logs (Authenticated)
app.post("/api/logs", authenticateToken, (req, res) => {
  const { message, level } = req.body;

  console.log("Received log data:", message, level); // Log incoming data for debugging

  const log = {
    timestamp: new Date(),
    message,
    level,
    user: req.user.username,
  };

  logs.push(log); // Add log to the in-memory array
  console.log("Log added:", log); // Log to confirm it's added

  res.status(201).json(log);
});

// Fetch logs (Authenticated)
app.get("/api/logs", authenticateToken, (req, res) => {
  console.log("Fetching logs..."); // Log that the GET request is being processed
  if (logs.length === 0) {
    console.log("No logs found"); // Log that no logs are available
    return res.status(404).json({ message: "No logs found" });
  }
  console.log("Logs found:", logs); // Log the logs being returned
  res.json(logs); // Return all logs
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});


require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const Student = require("./models/Student");
const Post = require("./models/Post");

const app = express();

app.use(cors());
app.use(express.json({ limit: "25mb" }));


// VERIFY LOGIN TOKEN
function verifyToken(req, res, next) {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                message: "Please login first."
            });
        }

        const token = authHeader.split(" ")[1];

        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        req.userEmail = decoded.email;

        next();

    } catch (error) {
        return res.status(401).json({
            message: "Invalid or expired login. Please login again."
        });
    }
}


// REGISTER API
app.post("/api/register", async (req, res) => {
    try {
        const { firstName, lastName, mobile, email, password } = req.body;

        if (!firstName || !lastName || !mobile || !email || !password) {
            return res.status(400).json({
                message: "All fields are required."
            });
        }

        const normalizedEmail = email.trim().toLowerCase();

        const existingStudent = await Student.findOne({
            email: normalizedEmail
        });

        if (existingStudent) {
            return res.status(409).json({
                message: "Email already registered."
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const student = new Student({
            firstName,
            lastName,
            mobile,
            email: normalizedEmail,
            password: hashedPassword
        });

        await student.save();

        res.status(201).json({
            message: "Registration successful!"
        });

    } catch (error) {
        console.error("Registration error:", error);

        res.status(500).json({
            message: "Registration failed."
        });
    }
});


// LOGIN API
app.post("/api/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                message: "Email and password are required."
            });
        }

        const student = await Student.findOne({
            email: email.trim().toLowerCase()
        });

        if (!student) {
            return res.status(404).json({
                message: "Student not found."
            });
        }

        const isMatch = await bcrypt.compare(
            password,
            student.password
        );

        if (!isMatch) {
            return res.status(401).json({
                message: "Invalid password."
            });
        }

        const token = jwt.sign(
            { email: student.email },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        res.status(200).json({
            message: "Login successful!",
            token,
            student: {
                firstName: student.firstName,
                lastName: student.lastName,
                mobile: student.mobile,
                email: student.email
            }
        });

    } catch (error) {
        console.error("Login error:", error);

        res.status(500).json({
            message: "Login failed."
        });
    }
});


// CREATE POST API - LOGIN REQUIRED
app.post("/api/posts", verifyToken, async (req, res) => {
    try {
        const {
            type,
            itemName,
            category,
            description,
            location,
            date,
            photo,
            currentStatus,
            returnStatus
        } = req.body;

        if (
            !type ||
            !itemName ||
            !category ||
            !description ||
            !location ||
            !date
        ) {
            return res.status(400).json({
                message: "Please fill all required fields."
            });
        }

        if (!["Lost Item", "Found Item"].includes(type)) {
            return res.status(400).json({
                message: "Invalid post type."
            });
        }

        if (
            photo &&
            photo.length * 0.75 > 20 * 1024 * 1024
        ) {
            return res.status(413).json({
                message: "Photo size must be below 20MB."
            });
        }

        const student = await Student.findOne({
            email: req.userEmail
        });

        if (!student) {
            return res.status(404).json({
                message: "Logged-in student not found."
            });
        }

        const newPost = new Post({
            type,
            itemName,
            category,
            description,
            location,
            date,
            photo: photo || "",

            currentStatus:
                type === "Found Item" ? (currentStatus || "") : "",

            returnStatus:
                type === "Found Item"
                    ? (returnStatus || "available")
                    : "available",

            ownerEmail: student.email,
            firstName: student.firstName,
            lastName: student.lastName
        });

        await newPost.save();

        const postResponse = newPost.toObject();
        delete postResponse.ownerEmail;

        res.status(201).json({
            message: "Post created successfully!",
            post: postResponse
        });

    } catch (error) {
        console.error("Create post error:", error);

        res.status(500).json({
            message: "Post creation failed."
        });
    }
});


// GET ALL PUBLIC POSTS
app.get("/api/posts", async (req, res) => {
    try {
        const posts = await Post.find()
            .select("-ownerEmail")
            .sort({ createdAt: -1 });

        res.status(200).json(posts);

    } catch (error) {
        console.error("Get posts error:", error);

        res.status(500).json({
            message: "Failed to fetch posts."
        });
    }
});


// GET FINDER CONTACT DETAILS - LOGIN REQUIRED
app.get("/api/posts/:id/contact", verifyToken, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);

        if (!post) {
            return res.status(404).json({
                message: "Post not found."
            });
        }

        if (post.type !== "Found Item") {
            return res.status(400).json({
                message: "Contact details are not available for this post."
            });
        }

        const student = await Student.findOne({
            email: post.ownerEmail.trim().toLowerCase()
        }).select("mobile email");

        if (!student || !student.mobile || !student.email) {
            return res.status(404).json({
                message: "Finder contact details are incomplete."
            });
        }

        res.status(200).json({
            mobile: student.mobile,
            email: student.email
        });

    } catch (error) {
        console.error("Contact fetch error:", error);

        res.status(500).json({
            message: "Could not fetch finder contact details."
        });
    }
});


// GET ONLY LOGGED-IN STUDENT'S POSTS
app.get("/api/my-posts", verifyToken, async (req, res) => {
    try {
        const posts = await Post.find({
            ownerEmail: req.userEmail
        }).sort({ createdAt: -1 });

        res.status(200).json(posts);

    } catch (error) {
        console.error("My posts error:", error);

        res.status(500).json({
            message: "Failed to fetch your posts."
        });
    }
});


// UPDATE RETURN STATUS - LOGIN REQUIRED
app.patch("/api/posts/:id/return-status", verifyToken, async (req, res) => {
    try {
        const { returnStatus } = req.body;

        if (!["waiting", "confirmed"].includes(returnStatus)) {
            return res.status(400).json({
                message: "Invalid return status."
            });
        }

        const post = await Post.findOneAndUpdate(
            {
                _id: req.params.id,
                ownerEmail: req.userEmail,
                type: "Found Item"
            },
            {
                returnStatus
            },
            {
                new: true,
                runValidators: true
            }
        );

        if (!post) {
            return res.status(404).json({
                message: "Post not found."
            });
        }

        res.status(200).json({
            message: "Return status updated successfully!",
            post
        });

    } catch (error) {
        console.error("Update status error:", error);

        res.status(500).json({
            message: "Could not update return status."
        });
    }
});


// DELETE STUDENT'S OWN POST - LOGIN REQUIRED
app.delete("/api/posts/:id", verifyToken, async (req, res) => {
    try {
        const post = await Post.findOneAndDelete({
            _id: req.params.id,
            ownerEmail: req.userEmail
        });

        if (!post) {
            return res.status(404).json({
                message: "Post not found."
            });
        }

        res.status(200).json({
            message: "Post deleted successfully!"
        });

    } catch (error) {
        console.error("Delete post error:", error);

        res.status(500).json({
            message: "Could not delete post."
        });
    }
});


// HOME ROUTE
app.get("/", (req, res) => {
    res.send("CampusFind Backend is running!");
});


// MONGODB CONNECTION
const PORT = process.env.PORT || 3000;

mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log("MongoDB connected successfully!");

        app.listen(PORT, () => {
            console.log(`Server running on http://localhost:${PORT}`);
        });
    })
    .catch((error) => {
        console.error("MongoDB connection failed:", error);
    });

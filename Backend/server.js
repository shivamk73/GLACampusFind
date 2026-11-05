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

// ADMIN EMAIL FROM RENDER ENVIRONMENT
const ADMIN_EMAIL = process.env.ADMIN_EMAIL
    ? process.env.ADMIN_EMAIL.trim().toLowerCase()
    : "";

// CHECK REQUIRED ENVIRONMENT VARIABLES
if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET is missing.");
}

if (!process.env.MONGO_URI) {
    throw new Error("MONGO_URI is missing.");
}

if (!ADMIN_EMAIL) {
    throw new Error("ADMIN_EMAIL is missing.");
}


// VERIFY LOGIN TOKEN AND FETCH USER FROM DATABASE
async function verifyToken(req, res, next) {
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

        const student = await Student.findOne({
            email: decoded.email.trim().toLowerCase()
        }).select("-password");

        if (!student) {
            return res.status(401).json({
                message: "User account not found. Please login again."
            });
        }

        req.user = student;
        req.userEmail = student.email;

        next();

    } catch (error) {
        return res.status(401).json({
            message: "Invalid or expired login. Please login again."
        });
    }
}


// VERIFY ADMIN ROLE
function requireAdmin(req, res, next) {
    const isAdmin =
        req.user &&
        req.user.role === "admin" &&
        req.user.email.toLowerCase() === ADMIN_EMAIL;

    if (!isAdmin) {
        return res.status(403).json({
            message: "Access denied. Admin permission required."
        });
    }

    next();
}


// REGISTER API
app.post("/api/register", async (req, res) => {
    try {
        const {
            firstName,
            lastName,
            mobile,
            email,
            password
        } = req.body;

        if (
            !firstName ||
            !lastName ||
            !mobile ||
            !email ||
            !password
        ) {
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

            // Role is automatically student.
            // Never accept role from registration form.
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

        const isAdmin =
            student.role === "admin" &&
            student.email.toLowerCase() === ADMIN_EMAIL;

        res.status(200).json({
            message: "Login successful!",
            token,
            student: {
                firstName: student.firstName,
                lastName: student.lastName,
                mobile: student.mobile,
                email: student.email,
                role: isAdmin ? "admin" : "student"
            }
        });

    } catch (error) {
        console.error("Login error:", error);

        res.status(500).json({
            message: "Login failed."
        });
    }
});


// ADMIN CHECK API
app.get(
    "/api/admin/check",
    verifyToken,
    requireAdmin,
    (req, res) => {
        res.status(200).json({
            message: "Admin access granted.",
            role: "admin"
        });
    }
);


// ADMIN - GET ALL POSTS FOR ADMIN DASHBOARD
app.get(
    "/api/admin/posts",
    verifyToken,
    requireAdmin,
    async (req, res) => {
        try {
            const posts = await Post.find()
                .sort({ createdAt: -1 });

            res.status(200).json(posts);

        } catch (error) {
            console.error("Admin posts error:", error);

            res.status(500).json({
                message: "Failed to fetch admin posts."
            });
        }
    }
);


// ADMIN - GET ALL REGISTERED STUDENTS
app.get(
    "/api/admin/students",
    verifyToken,
    requireAdmin,
    async (req, res) => {
        try {
            const students = await Student.find()
                .select("firstName lastName email mobile role")
                .sort({ firstName: 1 });

            res.status(200).json(students);

        } catch (error) {
            console.error("Admin students error:", error);

            res.status(500).json({
                message: "Failed to fetch students."
            });
        }
    }
);


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

            ownerEmail: req.user.email,
            firstName: req.user.firstName,
            lastName: req.user.lastName
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
        if (!mongoose.isValidObjectId(req.params.id)) {
            return res.status(400).json({
                message: "Invalid post ID."
            });
        }

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
            ownerEmail: req.user.email
        }).sort({ createdAt: -1 });

        res.status(200).json(posts);

    } catch (error) {
        console.error("My posts error:", error);

        res.status(500).json({
            message: "Failed to fetch your posts."
        });
    }
});


// UPDATE RETURN STATUS - POST OWNER ONLY
app.patch("/api/posts/:id/return-status", verifyToken, async (req, res) => {
    try {
        if (!mongoose.isValidObjectId(req.params.id)) {
            return res.status(400).json({
                message: "Invalid post ID."
            });
        }

        const { returnStatus } = req.body;

        if (!["waiting", "confirmed"].includes(returnStatus)) {
            return res.status(400).json({
                message: "Invalid return status."
            });
        }

        const post = await Post.findOneAndUpdate(
            {
                _id: req.params.id,
                ownerEmail: req.user.email,
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


// DELETE POST - ADMIN CAN DELETE ANY POST
// STUDENT CAN DELETE ONLY THEIR OWN POST
app.delete("/api/posts/:id", verifyToken, async (req, res) => {
    try {
        if (!mongoose.isValidObjectId(req.params.id)) {
            return res.status(400).json({
                message: "Invalid post ID."
            });
        }

        const isAdmin =
            req.user.role === "admin" &&
            req.user.email.toLowerCase() === ADMIN_EMAIL;

        let deletedPost;

        if (isAdmin) {
            deletedPost = await Post.findByIdAndDelete(
                req.params.id
            );
        } else {
            deletedPost = await Post.findOneAndDelete({
                _id: req.params.id,
                ownerEmail: req.user.email
            });
        }

        if (!deletedPost) {
            const postExists = await Post.exists({
                _id: req.params.id
            });

            if (postExists) {
                return res.status(403).json({
                    message: "You can delete only your own post."
                });
            }

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
            console.log(`Server running on port ${PORT}`);
        });
    })
    .catch((error) => {
        console.error("MongoDB connection failed:", error);
        process.exit(1);
    });
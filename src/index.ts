import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import session from "express-session";
import MongoStore from "connect-mongo";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { User, IUser } from "./userschema";
import { Note, INote } from "./notesschema";

const app = express();
const dbUrl = process.env.DATABASE_URL;
mongoose.connect("mongodb://127.0.0.1:27017/notes");

const jwt_secret = process.env.SECRET_KEY || "mysecretpassword";

const store = MongoStore.create({
  mongoUrl: "mongodb://127.0.0.1:27017/notes",
  crypto: {
    secret: jwt_secret,
  },
  touchAfter: 24 * 3600, // 24 hours
});

store.on("error", (err) => {
  console.log("Error in Mongo store:", err);
});

// Session configuration
const sessionOptions: session.SessionOptions = {
  store,
  secret: jwt_secret,
  resave: false,
  saveUninitialized: false, // Save only initialized sessions
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000, // 1 week
    httpOnly: true,
    secure: process.env.NODE_ENV === "production", // Use true in production for HTTPS
  },
};

app.use(session(sessionOptions));

app.use(cors());
app.use(express.json());

// bycrpt hashing
const hashPassword = async (password: string) => {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
};

const comparePassword = async (password: string, hashedPassword: string) => {
  return bcrypt.compare(password, hashedPassword);
};

const accesstoken = (user: IUser) => {
  return jwt.sign(
    { id: user._id, email: user.email },
    jwt_secret,
    { expiresIn: "1h" } // Token expires in 1 hour
  );
};

const authenticateJWT = (req: any, res: any, next: any) => {
  const token = req.headers.authorization?.split(" ")[1]; // Extract token from "Bearer <token>"

  if (!token)
    return res.status(401).json({ message: "Access token is missing" });

  jwt.verify(token, jwt_secret, (err: any, user: any) => {
    if (err)
      return res.status(403).json({ message: "Invalid or expired token" });

    req.user = user as IUser;
    next();
  });
};

app.get("/api", (req, res) => {
  res.status(200).send("Server is working");
});

app.post("/api/register", async (req, res, next) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required" });
    }

    // const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password });
    await user.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error("Error registering user:", err); // Add this line for detailed logging
    res.status(500).json({ message: "Error registering user" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid user" });
    }

    // Compare provided password with stored hashed password
    const isMatch = await comparePassword(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid  password" });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, jwt_secret, {
      expiresIn: "1h",
    });

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 1 week
    });

    res.status(200).json({ message: "Login successful", token });
  } catch (err) {
    console.error("Error logging in user:", err);
    res.status(500).json({ message: "Error logging in user" });
  }
});

app.get("/api/notes", authenticateJWT, async (req, res) => {
  try {
    const notes = await Note.find();
    res.json(notes);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to retrieve notes" });
  }
});

app.post("/api/notes", authenticateJWT, async (req, res) => {
  try {
    const { title, content, tags } = req.body;

    if (!title || !content) {
      return res
        .status(400)
        .json({ message: "Title and content are required" });
    }

    if (!req.user || typeof req.user !== "object") {
      return res.status(401).json({ message: "User not authenticated" });
    }

    // Type assertion to ensure req.user has userId
    const userId = (req.user as { userId: string }).userId;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid user ID" });
    }

    const newNote = new Note({
      title,
      content,
      tags: tags || [],
      owner: new mongoose.Types.ObjectId(userId), // Convert to ObjectId
    });

    const savedNote = await newNote.save();
    res.status(201).json(savedNote);
  } catch (error) {
    console.error("Error adding note:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/tags", async (req, res) => {
  try {
    const tags = await Note.distinct("tags");
    res.json(tags);
  } catch (error) {
    res.status(500).json({ message: "Error fetching tags" });
  }
});

app.get("/api/notes/:tag", authenticateJWT, async (req, res) => {
  const { tag } = req.params;

  try {
    const notes = await Note.find({ tags: tag });
    res.json(notes);
  } catch (error) {
    console.error("Error fetching notes by tag:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/api/:id/edit", authenticateJWT, async (req, res) => {
  const { id } = req.params;

  try {
    const note = await Note.findById(id).exec();

    if (!note) {
      return res.status(404).json({ message: "Note not found" });
    }

    res.json(note);
  } catch (error) {
    console.error("Error fetching note:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.put("/api/:id/edit", authenticateJWT, async (req, res) => {
  const { id } = req.params;
  const updateData = req.body;

  try {
    const updatedNote = await Note.findByIdAndUpdate(id, updateData, {
      new: true,
      runValidators: true,
    });

    if (!updatedNote) {
      return res.status(404).json({ message: "Note not found" });
    }

    res.json(updatedNote);
  } catch (error) {
    console.error("Error updating Note:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.delete("/api/notes/:id", authenticateJWT, async (req, res) => {
  const noteId = req.params.id;

  try {
    const deletedNote = await Note.findByIdAndDelete(noteId);

    if (!deletedNote) {
      return res.status(404).json({ message: "Note not found" });
    }

    res
      .status(200)
      .json({ message: "Note deleted successfully", note: deletedNote });
  } catch (error) {
    console.error("Error deleting note:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.listen(8080, () => {
  console.log("Listening on port 8080!");
});

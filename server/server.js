import dotenv from "dotenv";
dotenv.config();

import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import session from "express-session";
import passport from "passport";
import cloudinary from "cloudinary";
import multer from "multer";
import { CloudinaryStorage } from "multer-storage-cloudinary";

import Listing from "./models/Listing.js";
import User from "./models/User.js";
import Thread from "./models/Thread.js";
import Message from "./models/Message.js";
import configurePassport from "./passport-config.js";

const app = express();
const PORT = process.env.PORT || 5000;

// Cloudinary Configuration
cloudinary.v2.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Multer + Cloudinary Storage for images
const storage = new CloudinaryStorage({
  cloudinary: cloudinary.v2,
  params: {
    folder: "car-rental/listings",
    resource_type: "auto",
    quality: "auto",
  },
});
const upload = multer({ storage });

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:5173",
  credentials: true,
}));
app.use(express.json());

// Session middleware (required for Passport)
app.use(
  session({
    secret: process.env.SESSION_SECRET || "fallback-secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false, // set to true in production with HTTPS
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  })
);

// Passport middleware
configurePassport();
app.use(passport.initialize());
app.use(passport.session());

const sanitizeUser = (userDoc) => {
  const user = userDoc.toObject ? userDoc.toObject() : userDoc;
  delete user.password;
  delete user.__v;
  return user;
};

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log("Connected to MongoDB");
  })
  .catch((error) => {
    console.error("Error connecting to MongoDB:", error);
  });

// --- User Routes ---
app.post("/api/users/signup", async (req, res) => {
  try {
    const fullName = req.body?.fullName?.trim();
    const email = req.body?.email?.trim().toLowerCase();
    const password = req.body?.password;
    const mobileNumber = req.body?.mobileNumber?.trim();

    if (!fullName || !email || !password) {
      return res.status(400).json({ error: "Full name, email, and password are required." });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters." });
    }

    if (mobileNumber && !/^[6-9]\d{9}$/.test(mobileNumber)) {
      return res.status(400).json({ error: "Mobile number must be 10 digits and start with 6, 7, 8, or 9." });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ error: "Email already in use." });

    const uid = `mongo-user-${email.split("@")[0]}-${Date.now()}`;
    const newUser = new User({ uid, fullName, email, password, mobileNumber: mobileNumber || undefined });
    await newUser.save();
    res.status(201).json(sanitizeUser(newUser));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/users/login", async (req, res) => {
  try {
    const email = req.body?.email?.trim().toLowerCase();
    const password = req.body?.password;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required." });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found." });
    if (user.password !== password)
      return res.status(401).json({ error: "Incorrect password." });

    res.json(sanitizeUser(user));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/users/:uid", async (req, res) => {
  try {
    const user = await User.findOne({ uid: req.params.uid });
    if (!user) {
      // Check for system user
      if (req.params.uid === "system-user-driveluxe-888") {
        return res.json({ email: "DriveLuxe Verified" });
      }
      return res.json({ email: "Unknown User" });
    }
    res.json(sanitizeUser(user));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// --- Image Upload Endpoint ---
app.post("/api/upload-images", upload.array("images", 3), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: "No images uploaded" });
    }

    const imageUrls = req.files.map(file => file.path);
    res.json({ imageUrls });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// --- Listing Routes ---
app.get("/api/listings", async (req, res) => {
  try {
    const listings = await Listing.find({ verificationStatus: "verified", status: "available" });
    // Transform _id to id for frontend compatibility
    const formattedListings = listings.map((l) => {
      const lObj = l.toObject();
      lObj.id = lObj._id.toString();
      delete lObj._id;
      delete lObj.__v;
      return lObj;
    });
    res.json(formattedListings);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get user's own listings (pending or verified)
app.get("/api/listings/user/:sellerUid", async (req, res) => {
  try {
    const listings = await Listing.find({ sellerUid: req.params.sellerUid });
    const formattedListings = listings.map((l) => {
      const lObj = l.toObject();
      lObj.id = lObj._id.toString();
      delete lObj._id;
      delete lObj.__v;
      return lObj;
    });
    res.json(formattedListings);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create new listing with detailed information
app.post("/api/listings", async (req, res) => {
  try {
    const {
      make,
      model,
      year,
      price,
      mileage,
      description,
      vehicleNumber,
      chassisNumber,
      ownerName,
      ownerContactNumber,
      condition,
      imageUrls,
      sellerUid,
    } = req.body;

    // Validate required fields
    if (!make || !model || !year || !price || !mileage || !vehicleNumber || !ownerName || !ownerContactNumber || !sellerUid) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const newListing = new Listing({
      make,
      model,
      year,
      price,
      mileage,
      description,
      vehicleNumber,
      chassisNumber,
      ownerName,
      ownerContactNumber,
      condition,
      imageUrls,
      sellerUid,
      verificationStatus: "pending",
      status: "available",
    });

    await newListing.save();

    const lObj = newListing.toObject();
    lObj.id = lObj._id.toString();
    delete lObj._id;
    delete lObj.__v;

    res.status(201).json(lObj);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put("/api/listings/:id", async (req, res) => {
  try {
    const updatedListing = await Listing.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true },
    );
    if (!updatedListing)
      return res.status(404).json({ error: "Listing not found" });

    const lObj = updatedListing.toObject();
    lObj.id = lObj._id.toString();
    delete lObj._id;
    delete lObj.__v;

    res.json(lObj);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/listings/:id", async (req, res) => {
  try {
    await Listing.findByIdAndDelete(req.params.id);
    res.json({ message: "Listing deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Purchase a car with commission calculation
app.post("/api/listings/:id/purchase", async (req, res) => {
  try {
    const { buyerUid } = req.body;
    const listing = await Listing.findById(req.params.id);

    if (!listing) {
      return res.status(404).json({ error: "Listing not found" });
    }

    const carPrice = listing.price;
    const adminCommission = (carPrice * process.env.ADMIN_COMMISSION_PERCENTAGE) / 100;
    const sellerAmount = carPrice - adminCommission;

    const updatedListing = await Listing.findByIdAndUpdate(
      req.params.id,
      {
        status: "sold",
        buyerUid: buyerUid,
        purchaseDate: new Date(),
        adminCommission: adminCommission,
        sellerAmount: sellerAmount,
      },
      { new: true },
    );

    const lObj = updatedListing.toObject();
    lObj.id = lObj._id.toString();
    delete lObj._id;
    delete lObj.__v;

    res.json({
      ...lObj,
      transactionDetails: {
        carPrice,
        adminCommission,
        sellerAmount,
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// --- Admin Authentication ---
const ADMIN_CREDENTIALS = {
  email: process.env.ADMIN_EMAIL,
  password: process.env.ADMIN_PASSWORD,
};

// Admin Login Route
app.post("/api/admin/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Verify against admin credentials from .env
    if (email === ADMIN_CREDENTIALS.email && password === ADMIN_CREDENTIALS.password) {
      // Return admin user object
      res.json({
        uid: 'admin-user-001',
        email: ADMIN_CREDENTIALS.email,
        isAdmin: true
      });
    } else {
      res.status(401).json({ error: 'Invalid admin credentials' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// --- Admin Routes ---
app.get("/api/admin/listings", async (req, res) => {
  try {
    const status = req.query.status;
    const filter = {};

    if (["pending", "verified", "rejected"].includes(status)) {
      filter.verificationStatus = status;
    }

    const listings = await Listing.find(filter).sort({ createdAt: -1 });
    const formattedListings = listings.map((l) => {
      const lObj = l.toObject();
      lObj.id = lObj._id.toString();
      delete lObj._id;
      delete lObj.__v;
      return lObj;
    });

    res.json(formattedListings);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/admin/listings/pending", async (req, res) => {
  try {
    const listings = await Listing.find({ verificationStatus: "pending" }).sort({ createdAt: -1 });
    const formattedListings = listings.map((l) => {
      const lObj = l.toObject();
      lObj.id = lObj._id.toString();
      delete lObj._id;
      delete lObj.__v;
      return lObj;
    });
    res.json(formattedListings);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/admin/users", async (req, res) => {
  try {
    const users = await User.find({}).sort({ createdAt: -1 });
    const formattedUsers = users.map((u) => {
      const user = sanitizeUser(u);
      user.id = user._id.toString();
      delete user._id;
      return user;
    });

    res.json(formattedUsers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/admin/users/:id", async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Safety guard: do not allow deleting admin accounts through dashboard action.
    if (user.isAdmin || user.email === process.env.ADMIN_EMAIL) {
      return res.status(400).json({ error: "Admin user cannot be deleted" });
    }

    await User.findByIdAndDelete(req.params.id);
    res.json({ message: "User deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get admin dashboard stats
app.get("/api/admin/stats", async (req, res) => {
  try {
    const pendingCount = await Listing.countDocuments({ verificationStatus: "pending" });
    const verifiedCount = await Listing.countDocuments({ verificationStatus: "verified" });
    const rejectedCount = await Listing.countDocuments({ verificationStatus: "rejected" });
    const soldCount = await Listing.countDocuments({ status: "sold" });
    const soldListings = await Listing.find({ status: "sold" }).select("price adminCommission");

    const totalCommission = soldListings.reduce((sum, listing) => {
      if (typeof listing.adminCommission === "number") {
        return sum + listing.adminCommission;
      }
      // Backfill commission for legacy sold records missing adminCommission.
      return sum + (listing.price * Number(process.env.ADMIN_COMMISSION_PERCENTAGE || 2)) / 100;
    }, 0);

    res.json({
      pendingCount,
      verifiedCount,
      rejectedCount,
      soldCount,
      totalCommission,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/admin/listings/:id", async (req, res) => {
  try {
    const deletedListing = await Listing.findByIdAndDelete(req.params.id);
    if (!deletedListing) {
      return res.status(404).json({ error: "Listing not found" });
    }

    res.json({ message: "Listing deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Approve/Verify a listing
app.put("/api/admin/listings/:id/verify", async (req, res) => {
  try {
    const updatedListing = await Listing.findByIdAndUpdate(
      req.params.id,
      { verificationStatus: "verified" },
      { new: true },
    );
    if (!updatedListing)
      return res.status(404).json({ error: "Listing not found" });

    const lObj = updatedListing.toObject();
    lObj.id = lObj._id.toString();
    delete lObj._id;
    delete lObj.__v;

    res.json(lObj);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Reject a listing with reason
app.put("/api/admin/listings/:id/reject", async (req, res) => {
  try {
    const { reason } = req.body;

    if (!reason) {
      return res.status(400).json({ error: "Rejection reason is required" });
    }

    const updatedListing = await Listing.findByIdAndUpdate(
      req.params.id,
      {
        verificationStatus: "rejected",
        rejectionReason: reason,
      },
      { new: true },
    );

    if (!updatedListing)
      return res.status(404).json({ error: "Listing not found" });

    const lObj = updatedListing.toObject();
    lObj.id = lObj._id.toString();
    delete lObj._id;
    delete lObj.__v;

    res.json(lObj);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// --- Chat Routes ---
app.post("/api/chat/threads", async (req, res) => {
  try {
    const {
      listingId,
      listingTitle,
      buyerUid,
      sellerUid,
      buyerEmail,
      sellerEmail,
    } = req.body;

    let thread = await Thread.findOne({ listingId, buyerUid });
    if (!thread) {
      thread = new Thread({
        listingId,
        listingTitle,
        buyerUid,
        sellerUid,
        buyerEmail,
        sellerEmail,
      });
      await thread.save();
    }

    const tObj = thread.toObject();
    tObj.id = tObj._id.toString();
    delete tObj._id;
    delete tObj.__v;
    res.json(tObj);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/chat/threads/:userUid", async (req, res) => {
  try {
    const { userUid } = req.params;
    const threads = await Thread.find({
      $or: [{ buyerUid: userUid }, { sellerUid: userUid }],
    }).sort({ lastTimestamp: -1 });

    const formattedThreads = threads.map((t) => {
      const tObj = t.toObject();
      tObj.id = tObj._id.toString();
      delete tObj._id;
      delete tObj.__v;
      return tObj;
    });

    res.json(formattedThreads);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/chat/messages", async (req, res) => {
  try {
    const { threadId, senderUid, text } = req.body;
    const message = new Message({ threadId, senderUid, text });
    await message.save();

    await Thread.findByIdAndUpdate(threadId, {
      lastMessage: text,
      lastTimestamp: Date.now(),
    });

    const mObj = message.toObject();
    mObj.id = mObj._id.toString();
    delete mObj._id;
    delete mObj.__v;
    res.status(201).json(mObj);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/chat/messages/:threadId", async (req, res) => {
  try {
    const messages = await Message.find({ threadId: req.params.threadId }).sort(
      { timestamp: 1 },
    );
    const formattedMessages = messages.map((m) => {
      const mObj = m.toObject();
      mObj.id = mObj._id.toString();
      delete mObj._id;
      delete mObj.__v;
      return mObj;
    });
    res.json(formattedMessages);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// --- Google OAuth Routes ---
const oauthGuard = (req, res, next) => {
  const googleClientId = process.env.GOOGLE_CLIENT_ID;
  const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET;

  if (
    !googleClientId ||
    !googleClientSecret ||
    googleClientId === "your-google-client-id" ||
    googleClientSecret === "your-google-client-secret"
  ) {
    return res.status(503).json({ error: "Google OAuth is not configured on this server." });
  }
  next();
};

app.get(
  "/api/auth/google",
  oauthGuard,
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/api/auth/google/callback",
  oauthGuard,
  passport.authenticate("google", { failureRedirect: `${process.env.FRONTEND_URL || "http://localhost:5173"}?auth=failed` }),
  (req, res) => {
    // Successful authentication — redirect to frontend with user info
    const user = req.user;
    const userData = {
      uid: user.uid,
      email: user.email,
      fullName: user.fullName,
      mobileNumber: user.mobileNumber,
    };
    const encodedUser = encodeURIComponent(JSON.stringify(userData));
    res.redirect(
      `${process.env.FRONTEND_URL || "http://localhost:5173"}?google_auth=${encodedUser}`
    );
  }
);

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import User from "./models/User.js";

const configurePassport = () => {
  passport.serializeUser((user, done) => {
    done(null, user.uid);
  });

  passport.deserializeUser(async (uid, done) => {
    try {
      const user = await User.findOne({ uid });
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  });

  // Guard: skip Google strategy if credentials are missing to avoid crashing the server
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
    console.warn(
      "⚠️  GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET not set. Google OAuth will be disabled."
    );
    return;
  }

  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: `${process.env.BACKEND_URL}/api/auth/google/callback`,
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          // Check if user already exists by googleId
          let user = await User.findOne({ googleId: profile.id });

          if (user) {
            return done(null, user);
          }

          // Check if user exists by email (linked account)
          const email =
            profile.emails && profile.emails.length > 0
              ? profile.emails[0].value
              : null;

          if (email) {
            user = await User.findOne({ email });
            if (user) {
              // Link Google account to existing user
              user.googleId = profile.id;
              if (!user.fullName || user.fullName === "Google User") {
                user.fullName = profile.displayName || "Google User";
              }
              await user.save();
              return done(null, user);
            }
          }

          // Create new user
          const uid = `google-user-${profile.id}`;
          const newUser = new User({
            uid,
            googleId: profile.id,
            fullName: profile.displayName || "Google User",
            email: email || `${profile.id}@google.placeholder`,
          });

          await newUser.save();
          return done(null, newUser);
        } catch (error) {
          return done(error, null);
        }
      }
    )
  );
};

export default configurePassport;

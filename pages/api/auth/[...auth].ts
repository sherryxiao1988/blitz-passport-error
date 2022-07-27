import { passportAuth } from "@blitzjs/auth"
import db from "db"
import { api } from "app/blitz-server"
import { Strategy as GoogleStrategy } from "passport-google-oauth20"

export default api(
  passportAuth({
    successRedirectUrl: "/",
    errorRedirectUrl: "/",
    strategies: [
      {
        authenticateOptions: { scope: "openid profile email" },
        strategy: new GoogleStrategy(
          {
            clientID: process.env.GOOGLE_CLIENT_ID || "",
            clientSecret: process.env.GOOGLE_CLIENT_SECRET || "",
            callbackURL: process.env.CALLBACK_URL || "",
          },
          async function (_token, _tokenSecret, profile, done) {
            const email = profile.emails && profile.emails[0]?.value

            if (!email) {
              return done(new Error("Auth response doesn't have email."))
            }

            const user = await db.user.upsert({
              where: { email },
              create: {
                email,
                name: profile.displayName,
              },
              update: { email },
            })

            const publicData = {
              userId: user.id,
              roles: [user.role],
              source: "google",
            }
            done(undefined, { publicData })
          }
        ),
      },
    ],
  })
)

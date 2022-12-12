/* eslint-disable no-unused-vars */
const passport = require('passport');
const passportJwt = require('passport-jwt');
const LocalStrategy = require('passport-local').Strategy;
const GithubStrategy = require('passport-github2').Strategy;

const UserService = require('../../services/UserService');

const JWTStrategy = passportJwt.Strategy;
const ExtractJwt = passportJwt.ExtractJwt;

/**
 * This module sets up and configures passport
 * @param {*} config
 */
module.exports = (config) => {
  passport.use(
    new LocalStrategy(
      {
        passReqToCallback: true,
      },
      async (req, username, password, done) => {
        try {
          /**
           * @todo: Try to find the user in the database and try to validate the password
           */
          const user = await UserService.findByUsername(username);
          if (user && (await user.comparePassword(password))) {
            return done(null, user);
          }
          req.session.messages.push({
            text: 'Invalid username or password!',
            type: 'danger',
          });
          // Render the page again and show the errors
          return done(null, false);
          /**
           * @todo: Log the user in by saving the userid to the session and redirect to the index page
           * @todo: Don't forget about 'Remember me'!
           */
        } catch (err) {
          return done(err);
        }
      }
    )
  );
  passport.use(
    new JWTStrategy(
      {
        jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        secretOrKey: config.JWTSECRET,
      },
      async (jwtPayload, done) => {
        try {
          const user = await UserService.findById(jwtPayload.userId);
          return done(null, user);
        } catch (err) {
          return done(err);
        }
      }
    )
  );
  passport.use(
    new GithubStrategy(
      {
        clientID: config.GITHUB_CLIENT_ID,
        clientSecret: config.GITHUB_CLIENT_SECRET,
        scope: ['user:email'],
        callbackURL: 'http://localhost:3000/auth/github/callback',
        passReqToCallback: true,
      },
      async (req, accessToken, refreshToken, profile, done) => {
        try {
          console.log(profile);
          return done(null, false);
        } catch (err) {
          return done(err);
        }
      }
    )
  );
  passport.serializeUser((user, done) => {
    done(null, user._id);
  });
  passport.deserializeUser(async (id, done) => {
    try {
      const user = await UserService.findById(id);
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  });
  return passport;
};

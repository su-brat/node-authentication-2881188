/* eslint-disable no-unused-vars */
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const UserService = require('../../services/UserService');

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

          const user = await UserService.findByUsername(req.body.username);
          if (user && (await user.comparePassword(req.body.password))) {
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

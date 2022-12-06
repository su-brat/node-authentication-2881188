const { Router } = require('express');

// eslint-disable-next-line no-unused-vars
const UserService = require('../../services/UserService');
const validation = require('../../middlewares/validation');

const router = Router();

module.exports = () => {
  /**
   * GET route to display the login form
   */
  router.get('/resetpassword', (req, res) => {
    res.render('auth/resetpassword', { page: 'resetpassword' });
  });

  /**
   * POST route to create the password reset token
   */
  router.post(
    '/resetpassword',
    validation.validateEmail,
    async (req, res, next) => {
      try {
        const validationErrors = validation.validationResult(req);
        const errors = [];
        if (!validationErrors.isEmpty()) {
          validationErrors.errors.forEach((error) => {
            errors.push(error.param);
            req.session.messages.push({
              text: error.msg,
              type: 'danger',
            });
          });
        } else {
          /**
           * @todo: Find the user and create a reset token
           */
          const user = await UserService.findByEmail(req.body.email);
          if (user) UserService.createPasswordResetToken(user._id);
          req.session.messages.push({
            text: 'Reset password link sent to your mail!',
            type: 'warning',
          });
        }

        if (errors.length) {
          // Render the page again and show the errors
          return res.render('auth/resetpassword', {
            page: 'resetpassword',
            data: req.body,
            errors,
          });
        }

        /**
         * @todo: On success, redirect the user to some other page, like the login page
         */
        return res.redirect('/auth/resetpassword');
      } catch (err) {
        return next(err);
      }
    }
  );

  /**
   * GET route to verify the reset token and show the form to change the password
   */
  router.get('/resetpassword/:userId/:resetToken', async (req, res, next) => {
    try {
      /**
       * @todo: Validate the token and render the password change form if valid
       */
      const verifiedToken = await UserService.verifyPasswordResetToken(
        req.params.userId,
        req.params.resetToken
      );
      if (verifiedToken)
        return res.render('auth/changepassword', {
          page: 'resetpassword',
          userId: req.params.userId,
          resetToken: req.params.resetToken,
        });
      req.session.messages.push({
        text: 'Invalid redirect!',
        type: 'danger',
      });
      return res.redirect('/auth/resetpassword');
    } catch (err) {
      return next(err);
    }
  });

  router.post(
    '/resetpassword/:userId/:resetToken',
    validation.validatePassword,
    validation.validatePasswordMatch,
    async (req, res, next) => {
      try {
        /**
         * @todo: Validate the provided credentials
         */
        const verifiedToken = await UserService.verifyPasswordResetToken(
          req.params.userId,
          req.params.resetToken
        );
        if (!verifiedToken) {
          req.session.messages.push({
            text: 'Failed to change password!',
            type: 'danger',
          });
          return res.redirect('/auth/resetpassword');
        }
        const validationErrors = validation.validationResult(req);
        const errors = [];
        if (!validationErrors.isEmpty()) {
          validationErrors.errors.forEach((error) => {
            errors.push(error.param);
            req.session.messages.push({
              text: error.msg,
              type: 'danger',
            });
          });
        }

        if (errors.length) {
          // Render the page again and show the errors
          return res.render('auth/changepassword', {
            page: 'resetpassword',
            data: req.body,
            userId: req.params.userId,
            resetToken: req.params.resetToken,
            errors,
          });
        }

        /**
         * @todo: Change password, remove token and redirect to login
         */
        const user = await UserService.changePassword(
          req.params.userId,
          req.body.password
        );
        if (user) {
          await UserService.deletePasswordResetToken(req.params.resetToken);
          req.session.messages.push({
            text: 'Password changed successfully',
            type: 'success',
          });
        }
        return res.redirect('/auth/login');
      } catch (err) {
        return next(err);
      }
    }
  );

  return router;
};

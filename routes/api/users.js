const express = require("express");
const router = express.Router();
const gravatar = require("gravatar");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const keys = require("../../config/keys");

// Load User Model
const User = require("../../models/Users");

// Load Input Validation
const validateRegisterInput = require("../../validation/register");
const validateLoginInput = require("../../validation/login");

// @route   GET api/users/test
// @desc    Tests users route
// @access  Public
router.get("/test", (req, res) => res.json({ msg: "Users Works" }));

// @route   GET api/users/getUsers
// @desc    Tests the Users Present in DB.
// @access  Public
router.get("/getUsers", (req, res) => {
  // Retrieves the entries from the DB.
  User.find().then(users => {
    res.json({ users });
  });
});

// @route   POST api/users/register
// @desc    Registration User
// @access  Public
router.post("/register", (req, res) => {
  const { errors, isValid } = validateRegisterInput(req.body);

  // Check Validation
  if (!isValid) {
    return res.status(400).json(errors);
  }
  User.findOne({ email: req.body.email }).then(user => {
    if (user) {
      return res.status(400).json("Email : Email Exists");
    } else {
      // refer gravatar documentation.
      const avatar = gravatar.url(req.body.email, {
        s: "200", // Size
        r: "pg", // Rating
        d: "mm" // Default
      });

      const newUser = new User({
        name: req.body.name,
        email: req.body.email,
        avatar,
        password: req.body.password
      });

      // Generate a password hash.
      bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(newUser.password, salt, (err, hash) => {
          if (err) throw err;
          newUser.password = hash;
          newUser
            .save()
            .then(user => res.json(user))
            .catch(err => console.log(err));
        });
      });
    }
  });
});

// @route   POST api/users/login
// @desc    Login User/ Create JWT
// @access  Public
router.post("/login", (req, res) => {
  const { errors, isValid } = validateLoginInput(req.body);

  // Check Validation
  if (!isValid) {
    return res.status(400).json(errors);
  }

  const email = req.body.email;
  const password = req.body.password;

  // Find if the User is present.
  User.findOne({ email })
    .then(user => {
      if (!user) {
        return res.status(404).json({ email: "User Not Found" });
      }
      // Compare if the Password provided is same at the time when it is registered which is hashed.
      bcrypt.compare(password, user.password).then(isMatched => {
        if (isMatched) {
          // User Matched
          // Create JWT payload to send the information to the other protected routes.
          const payload = {
            id: user.id,
            name: user.name,
            avatar: user.avatar,
            email: user.email
          };

          // Sign Token
          jwt.sign(
            payload,
            keys.secretOrKey,
            { expiresIn: 3600 },
            (err, token) => {
              res.json({
                message: true,
                token: "Bearer " + token
              });
            }
          );
        } else {
          return res.status(404).json({ Password: "Password Incorrect" });
        }
      });
    })
    .catch(err => console.log(err));
});

// @route GET api/users/currentUser
// @desc Gets the current User
// @access Private
router.get(
  "/currentUser",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    res.json(req.user);
  }
);

module.exports = router;

var express = require("express");
var router = express.Router();
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const { body, validationResult } = require("express-validator");
const User = require("../models/Users");

router.get("/", (req, res, next) => {
  res.send("respond with a resource");
});

router.get("/register", (req, res, next) => {
  res.render("register");
});

/* Register account */
/*
router.post(
  "/register",
  body("email").isEmail().trim().escape(),
  body("password").isLength({ min: 8 }),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    User.findOne({ email: req.body.email }, (err, user) => {
      if (err) throw err;
      if (user) {
        return res.status(403).json({ username: "Email already in use!" });
      } else {
        bcrypt.genSalt(10, (err, salt) => {
          bcrypt.hash(req.body.password, salt, (err, hash) => {
            if (err) throw err;
            User.create(
              {
                email: req.body.email,
                password: hash
              },
              (err, ok) => {
                if (err) throw err;
                return res.redirect("/user/login");
              }
            );
          });
        });
      }
    });
  }
);*/

router.get("/login", (req, res, next) => {
  res.render("login");
});

module.exports = router;

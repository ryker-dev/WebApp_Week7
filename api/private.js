const express = require("express");
const router = express.Router();
const validateToken = require("../auth/validateToken.js");

router.get("/", validateToken, (req, res, next) => {
    res.json({email: req.email});
  });
  
module.exports = router;
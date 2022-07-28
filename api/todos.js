const express = require("express");
const router = express.Router();
const validateToken = require("../auth/validateToken.js");
const Todo = require("../models/Todo");

router.post("/", validateToken, (req, res, next) => {
  //console.log(req);
  Todo.findOne({ user: req.user.id }, (err, todo) => {
    if (err) throw err;
    //console.log(todo);
    // If the user hasn't posted before
    if (todo) {
        console.log(req.body.items);
        Todo.updateOne({ user: req.user.id }, {$addToSet: {items: { $each: req.body.items}}}, (err, todo) => {
            if (err) throw err;
            return res.json({ message: "Updated!" });
        });
    } else {
      Todo.create(
        {
          user: req.user.id,
          items: req.body.items,
        },
        (err, ok) => {
          if (err) throw err;
          return res.json({ message: "Created!" });
        }
      );
    }
  });
});

module.exports = router;

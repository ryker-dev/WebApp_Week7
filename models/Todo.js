const mongoose = require("mongoose");

const Schema = mongoose.Schema;

let todoSchema = new Schema ({
    user: {type: Schema.ObjectId},
    items: {type: Array}
})

module.exports = mongoose.model("todos", todoSchema);
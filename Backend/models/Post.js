
const mongoose = require("mongoose");

const postSchema = new mongoose.Schema({
    type: {
        type: String,
        required: true,
        enum: ["Lost Item", "Found Item"]
    },
    itemName: {
        type: String,
        required: true
    },
    category: {
        type: String,
        required: true
    },
    description: {
        type: String,
        required: true
    },
    location: {
        type: String,
        required: true
    },
    date: {
        type: String,
        required: true
    },
    photo: {
        type: String,
        default: ""
    },

    currentStatus: {
    type: String,
    default: ""
},
returnStatus: {
    type: String,
    default: "available"
},

    ownerEmail: {
        type: String,
        required: true
    },
    firstName: {
        type: String,
        required: true
    },
    lastName: {
        type: String,
        required: true
    },
    status: {
        type: String,
        default: "Available"
    }
}, {
    timestamps: true
});

module.exports = mongoose.model("Post", postSchema);

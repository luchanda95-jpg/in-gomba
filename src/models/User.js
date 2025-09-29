// models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    displayName: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true, // Emails must be unique
        lowercase: true,
    },
    password: {
        type: String,
        required: true, // This will be the hashed password
    },
});

module.exports = mongoose.model('User', userSchema);
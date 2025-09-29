// src/index.js  (or repo root index.js if you prefer)
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config(); // Load environment variables from .env file

const authRoutes = require('./routes/auth');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Health check route (useful for Render and diagnostics)
app.get('/', (req, res) => {
  res.json({ status: 'ok', env: process.env.NODE_ENV || 'development' });
});

// Connect to MongoDB
async function start() {
  try {
    const mongoUri = process.env.MONGO_URI;
    if (!mongoUri) {
      console.error('MONGO_URI is not set. Exiting.');
      process.exit(1);
    }
    await mongoose.connect(mongoUri, {
      // optional: useNewUrlParser: true, useUnifiedTopology: true (Mongoose 7+ handles defaults)
    });
    console.log('MongoDB connected successfully.');

    // Routes
    app.use('/api/auth', authRoutes);

    // Start the server
    const server = app.listen(PORT, () => {
      console.log(`Server is running on http://0.0.0.0:${PORT}`);
    });

    // Graceful shutdown
    const shutdown = async () => {
      console.log('Shutting down server...');
      server.close();
      await mongoose.disconnect();
      process.exit(0);
    };

    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);
  } catch (err) {
    console.error('Startup error:', err);
    process.exit(1);
  }
}

start();

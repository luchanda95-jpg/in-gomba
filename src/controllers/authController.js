// src/controllers/authController.js
const bcrypt = require('bcrypt');
const User = require('../models/User');
const { signAccessToken, signRefreshToken } = require('../utils/auth');

const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);

// Register
async function register(req, res) {
  const { email, password, name } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

  const exists = await User.findOne({ email: email.toLowerCase() });
  if (exists) return res.status(409).json({ message: 'Email already in use' });

  const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const user = await User.create({ email: email.toLowerCase(), passwordHash: hash, name: name || '' });

  const accessToken = signAccessToken({ sub: user._id, email: user.email });
  const refreshToken = signRefreshToken({ sub: user._id });

  user.refreshTokens.push({ token: refreshToken });
  await user.save();

  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 7
  });

  res.status(201).json({ accessToken, user: { id: user._id, email: user.email, name: user.name } });
}

// Login
async function login(req, res) {
  const { email, password } = req.body;
  const user = await User.findOne({ email: email.toLowerCase() });
  if (!user) return res.status(401).json({ message: 'Invalid email or password' });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ message: 'Invalid email or password' });

  const accessToken = signAccessToken({ sub: user._id, email: user.email });
  const refreshToken = signRefreshToken({ sub: user._id });

  user.refreshTokens.push({ token: refreshToken });
  await user.save();

  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 7
  });

  res.json({ accessToken, user: { id: user._id, email: user.email, name: user.name } });
}

// Refresh
async function refresh(req, res) {
  const token = req.cookies.refreshToken || req.body.refreshToken;
  if (!token) return res.status(401).json({ message: 'No refresh token' });

  try {
    const jwt = require('jsonwebtoken');
    const payload = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(payload.sub);
    if (!user) return res.status(401).json({ message: 'User not found' });

    const stored = user.refreshTokens.find(rt => rt.token === token);
    if (!stored) return res.status(401).json({ message: 'Refresh token revoked' });

    const accessToken = signAccessToken({ sub: user._id, email: user.email });
    res.json({ accessToken });
  } catch (err) {
    return res.status(401).json({ message: 'Invalid refresh token' });
  }
}

// Logout
async function logout(req, res) {
  try {
    const token = req.cookies.refreshToken || req.body.refreshToken;
    if (token && req.userId) {
      await User.updateOne({ _id: req.userId }, { $pull: { refreshTokens: { token } } });
    }
    res.clearCookie('refreshToken');
    res.json({ message: 'Logged out' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
}

// Me
async function me(req, res) {
  const UserModel = require('../models/User');
  const user = await UserModel.findById(req.userId).select('-passwordHash -refreshTokens');
  if (!user) return res.status(404).json({ message: 'User not found' });
  res.json({ user });
}

module.exports = { register, login, refresh, logout, me };

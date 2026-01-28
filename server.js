const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Environment variables
const JWT_SECRET = process.env.JWT_SECRET;
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const FRONTEND_URL = process.env.FRONTEND_URL;
const PORT = process.env.PORT || 3000;

// Initialize Supabase
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// Discount codes
const DISCOUNT_CODES = {
  'DX9Q-7M2A-K8P4': { name: 'DX9Q-7M2A-K8P4', standard: 700000, standardOnly: true },
  'R5TQ-Z91L-A7XK': { name: 'R5TQ-Z91L-A7XK', standard: 700000, standardOnly: true },
  'MP8A-QX47-L9TZ': { name: 'MP8A-QX47-L9TZ', pro: 1100000, proOnly: true },
  'K2Z9-PAX6-M7QF': { name: 'K2Z9-PAX6-M7QF', pro: 1100000, proOnly: true }
};

// Base prices (in kobo - Paystack uses kobo)
const BASE_PRICES = {
  standard_monthly: 1600000,
  standard_yearly: 17280000,
  pro_monthly: 2200000,
  pro_yearly: 23760000
};

// Plan details
const PLANS = [
  {
    id: 'standard_monthly',
    name: 'Standard',
    interval: 'monthly',
    price: 16000,
    features: ['Unlimited Downloads', 'All Premium Content', 'Email Support', 'No Ads', 'Cancel Anytime']
  },
  {
    id: 'standard_yearly',
    name: 'Standard',
    interval: 'yearly',
    price: 172800,
    features: ['Unlimited Downloads', 'All Premium Content', 'Email Support', 'No Ads', 'Cancel Anytime']
  },
  {
    id: 'pro_monthly',
    name: 'Pro',
    interval: 'monthly',
    price: 22000,
    features: ['Everything in Standard', 'Priority Support 24/7', 'Early Access Features', 'Exclusive Pro Content', 'Pro Tools & Resources']
  },
  {
    id: 'pro_yearly',
    name: 'Pro',
    interval: 'yearly',
    price: 237600,
    features: ['Everything in Standard', 'Priority Support 24/7', 'Early Access Features', 'Exclusive Pro Content', 'Pro Tools & Resources']
  }
];

// Validation functions
function validatePassword(password) {
  if (!password || password.length < 10) {
    return { valid: false, message: 'Password must be at least 10 characters long' };
  }
  const hasLetter = /[a-zA-Z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  if (!hasLetter || !hasNumber) {
    return { valid: false, message: 'Password must contain both letters and numbers' };
  }
  return { valid: true };
}

function validateEmail(email) {
  const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return regex.test(email);
}

function validateFullName(name) {
  return name && name.trim().length >= 2;
}

// Authentication middleware
function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// ============================================
// AUTHENTICATION ENDPOINTS
// ============================================

// Register
app.post('/auth/register', async (req, res) => {
  try {
    const { fullName, email, password } = req.body;

    // Validate inputs
    if (!validateFullName(fullName)) {
      return res.status(400).json({ success: false, message: 'Full name must be at least 2 characters' });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ success: false, message: 'Invalid email address' });
    }

    const passwordCheck = validatePassword(password);
    if (!passwordCheck.valid) {
      return res.status(400).json({ success: false, message: passwordCheck.message });
    }

    // Check existing user
    const { data: existing } = await supabase
      .from('users')
      .select('id')
      .eq('email', email.toLowerCase().trim())
      .single();

    if (existing) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const { data: user, error } = await supabase
      .from('users')
      .insert([{
        full_name: fullName.trim(),
        email: email.toLowerCase().trim(),
        password: hashedPassword,
        is_subscribed: false
      }])
      .select()
      .single();

    if (error) {
      console.error('Registration error:', error);
      return res.status(500).json({ success: false, message: 'Registration failed' });
    }

    // Generate token
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });

    res.status(201).json({
      success: true,
      message: 'Registration successful',
      token,
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        isSubscribed: user.is_subscribed
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ success: false, message: 'Registration failed' });
  }
});

// Login
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!validateEmail(email)) {
      return res.status(400).json({ success: false, message: 'Invalid email address' });
    }

    if (!password) {
      return res.status(400).json({ success: false, message: 'Password is required' });
    }

    // Find user
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email.toLowerCase().trim())
      .single();

    if (error || !user) {
      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }

    // Generate token
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        isSubscribed: user.is_subscribed
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Login failed' });
  }
});

// Get current user
app.get('/auth/me', authenticate, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('id, full_name, email, is_subscribed')
      .eq('id', req.user.id)
      .single();

    if (error || !user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.json({
      success: true,
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        isSubscribed: user.is_subscribed
      }
    });

  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ success: false, message: 'Failed to get user' });
  }
});

// ============================================
// PAYMENT ENDPOINTS
// ============================================

// Initialize payment
app.post('/payment/initialize', authenticate, async (req, res) => {
  try {
    const { plan, discountCode } = req.body;
    const userId = req.user.id;

    // Get user
    const { data: user, error: userError } = await supabase
      .from('users')
      .select('*')
      .eq('id', userId)
      .single();

    if (userError || !user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Get plan key
    const planKey = plan.replace('_discounted', '');

    if (!BASE_PRICES[planKey]) {
      return res.status(400).json({ success: false, message: 'Invalid plan' });
    }

    // Calculate amount
    let amount = BASE_PRICES[planKey];
    let appliedDiscount = null;

    // Apply discount
    if (discountCode) {
      const code = discountCode.toUpperCase();
      const discount = DISCOUNT_CODES[code];

      if (discount) {
        if (plan.includes('standard') && discount.standardOnly) {
          amount = discount.standard;
          if (plan.includes('yearly')) amount = Math.round(amount * 10.8);
          appliedDiscount = code;
        } else if (plan.includes('pro') && discount.proOnly) {
          amount = discount.pro;
          if (plan.includes('yearly')) amount = Math.round(amount * 10.8);
          appliedDiscount = code;
        }
      }
    }

    // Initialize Paystack
    const response = await axios.post(
      'https://api.paystack.co/transaction/initialize',
      {
        email: user.email,
        amount: amount,
        currency: 'NGN',
        metadata: {
          userId: user.id,
          fullName: user.full_name,
          plan: plan,
          discountCode: appliedDiscount,
          originalAmount: BASE_PRICES[planKey],
          finalAmount: amount
        },
        callback_url: `${FRONTEND_URL}/dashboard.html`
      },
      {
        headers: {
          Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );

    if (response.data && response.data.status) {
      res.json({
        success: true,
        authorization_url: response.data.data.authorization_url,
        access_code: response.data.data.access_code,
        reference: response.data.data.reference
      });
    } else {
      res.status(500).json({ success: false, message: 'Payment initialization failed' });
    }

  } catch (error) {
    console.error('Payment init error:', error.response?.data || error);
    res.status(500).json({ success: false, message: 'Payment initialization failed' });
  }
});

// Verify payment
app.get('/payment/verify/:reference', authenticate, async (req, res) => {
  try {
    const { reference } = req.params;

    // Verify with Paystack
    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` }
      }
    );

    if (response.data && response.data.data.status === 'success') {
      const data = response.data.data;
      const metadata = data.metadata;

      // Update user
      await supabase
        .from('users')
        .update({ is_subscribed: true })
        .eq('id', metadata.userId);

      // Calculate end date
      const endDate = new Date();
      if (metadata.plan.includes('yearly')) {
        endDate.setFullYear(endDate.getFullYear() + 1);
      } else {
        endDate.setMonth(endDate.getMonth() + 1);
      }

      // Save subscription
      await supabase
        .from('subscriptions')
        .insert([{
          user_id: metadata.userId,
          plan: metadata.plan,
          amount: data.amount,
          reference: reference,
          discount_code: metadata.discountCode,
          status: 'active',
          start_date: new Date().toISOString(),
          end_date: endDate.toISOString()
        }]);

      res.json({
        success: true,
        message: 'Payment verified',
        subscription: {
          plan: metadata.plan,
          status: 'active',
          endDate: endDate
        }
      });

    } else {
      res.status(400).json({ success: false, message: 'Payment verification failed' });
    }

  } catch (error) {
    console.error('Verify error:', error.response?.data || error);
    res.status(500).json({ success: false, message: 'Verification failed' });
  }
});

// Webhook
app.post('/payment/webhook', async (req, res) => {
  try {
    const event = req.body;

    if (event.event === 'charge.success') {
      const data = event.data;
      const metadata = data.metadata;

      // Update user
      await supabase
        .from('users')
        .update({ is_subscribed: true })
        .eq('id', metadata.userId);

      // Calculate end date
      const endDate = new Date();
      if (metadata.plan.includes('yearly')) {
        endDate.setFullYear(endDate.getFullYear() + 1);
      } else {
        endDate.setMonth(endDate.getMonth() + 1);
      }

      // Save subscription
      await supabase
        .from('subscriptions')
        .insert([{
          user_id: metadata.userId,
          plan: metadata.plan,
          amount: data.amount,
          reference: data.reference,
          discount_code: metadata.discountCode,
          status: 'active',
          start_date: new Date().toISOString(),
          end_date: endDate.toISOString()
        }]);
    }

    res.status(200).send('OK');

  } catch (error) {
    console.error('Webhook error:', error);
    res.status(500).send('Error');
  }
});

// ============================================
// OTHER ENDPOINTS
// ============================================

// Get plans
app.get('/plans', (req, res) => {
  res.json({
    success: true,
    plans: PLANS
  });
});

// Get user profile
app.get('/user/profile', authenticate, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', req.user.id)
      .single();

    if (error || !user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Get active subscription
    const { data: subs } = await supabase
      .from('subscriptions')
      .select('*')
      .eq('user_id', user.id)
      .eq('status', 'active')
      .gte('end_date', new Date().toISOString())
      .order('created_at', { ascending: false })
      .limit(1);

    res.json({
      success: true,
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        isSubscribed: user.is_subscribed,
        subscription: subs && subs.length > 0 ? {
          plan: subs[0].plan,
          status: subs[0].status,
          endDate: subs[0].end_date
        } : null
      }
    });

  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ success: false, message: 'Failed to get profile' });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'MZone backend running',
    timestamp: new Date(),
    database: SUPABASE_URL ? 'Connected' : 'Not configured',
    paystack: PAYSTACK_SECRET_KEY ? 'Configured' : 'Not configured'
  });
});

// Root
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'MZone API',
    version: '1.0.0',
    endpoints: {
      auth: ['POST /auth/register', 'POST /auth/login', 'GET /auth/me'],
      payment: ['POST /payment/initialize', 'GET /payment/verify/:reference', 'POST /payment/webhook'],
      user: ['GET /user/profile'],
      other: ['GET /plans', 'GET /health']
    }
  });
});

// 404
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Endpoint not found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🔐 JWT: ${JWT_SECRET ? '✓' : '✗'}`);
  console.log(`💳 Paystack: ${PAYSTACK_SECRET_KEY ? '✓' : '✗'}`);
  console.log(`🗄️  Supabase: ${SUPABASE_URL ? '✓' : '✗'}`);
});

module.exports = app;

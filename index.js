const express = require("express");
const cors = require("cors");
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8080;
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// Middleware
app.use(cors({ origin: process.env.ALLOWED_ORIGIN }));
app.use(express.json());

app.post('/payment-sheet', async (req, res) => {
  try {
    const { amount } = req.body;
    
    if (!amount || isNaN(amount)) {
      return res.status(400).json({ error: "Valid amount required" });
    }

    const customer = await stripe.customers.create();
    const ephemeralKey = await stripe.ephemeralKeys.create(
      { customer: customer.id },
      { apiVersion: "2025-02-24.acacia" }
    );

    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(amount), // Ensure integer value
      currency: 'usd',
      customer: customer.id,
      automatic_payment_methods: { enabled: true },
    });

    res.json({
      paymentIntent: paymentIntent.client_secret,
      ephemeralKey: ephemeralKey.secret,
      customer: customer.id,
      publishableKey: process.env.STRIPE_PUBLISHABLE_KEY
    });

  } catch (err) {
    console.error("Payment error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
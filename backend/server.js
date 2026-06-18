const express = require('express');
const cors = require('cors');
const networkRoutes = require('./routes/network');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Enable cross-origin requests for your frontend
app.use(cors());
app.use(express.json());

// Routes
app.use(networkRoutes);

app.listen(PORT, () => {
  console.log(`Samaritan Server online on core port ${PORT}`);
});
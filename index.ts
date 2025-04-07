import dotenv from 'dotenv';
dotenv.config();
import express from 'express';
import authRoutes from './routes/auth';

// Add this to index.ts temporarily
import pool from './config/database';
pool.query('SELECT NOW()', (err, res) => {
  if (err) console.error('Database connection error:', err);
  else console.log('Database connected at:', res.rows[0].now);
});

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());

// Routes
app.use('/api/auth', authRoutes);

// Test route
app.get('/', (req, res) => {
  res.send('Medical Imaging Backend (TypeScript)');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
// src/app.ts
import 'reflect-metadata';
import express from 'express';
import * as dotenv from 'dotenv';
dotenv.config();
import cors from 'cors';

import { AppDataSource } from './config/data-source';
import authRouter from './routes/auth';
import superAdminRouter from './routes/superAdmin';
import adminRouter from './routes/admin';
import doctorRouter from './routes/doctor';
import patientRouter from './routes/patient';
import { setupSwagger } from './utils/swagger';

const app = express();
app.use(express.json());
app.use(cors());

// Initialize database
AppDataSource.initialize()
  .then(() => console.log('Database connected'))
  .catch((error) => console.error('Database error:', error));

// Routes
app.use('/auth', authRouter);
app.use('/super-admin', superAdminRouter);
app.use('/admin', adminRouter);
app.use('/doctor', doctorRouter);
app.use('/patients', patientRouter);

// Swagger documentation
setupSwagger(app);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

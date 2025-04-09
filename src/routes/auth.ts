// src/routes/auth.ts
import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { AppDataSource } from '../config/data-source';
import { User } from '../entities/User';

const router = express.Router();

// Async error handler wrapper
function asyncHandler(
  fn: (req: express.Request, res: express.Response, next: express.NextFunction) => Promise<any>
) {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

/**
 * @swagger
 * tags:
 *   name: Authentication
 *   description: User authentication endpoints
 */

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Authenticate user and get JWT token
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: superadmin@hospital.com
 *               password:
 *                 type: string
 *                 format: password
 *                 example: superadmin123
 *     responses:
 *       200:
 *         description: Successfully authenticated
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: JWT access token
 *       401:
 *         description: Invalid credentials
 */
router.post(
    '/login',
    asyncHandler(async (req, res) => {
      const { email, password } = req.body;
      // Convert email to lowercase before querying
      const normalizedEmail = email.toLowerCase();
      const user = await AppDataSource.getRepository(User).findOne({ 
        where: { email: normalizedEmail } // Use normalized email
      });
  
      if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
  
      const token = jwt.sign(
        { id: user.id, role: user.role }, 
        process.env.JWT_SECRET!,
        { expiresIn: '1h' } // Add token expiration
      );
      res.json({ token });
    })
  );

export default router;
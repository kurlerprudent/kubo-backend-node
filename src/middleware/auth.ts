// middleware/auth.ts
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { User, UserRole } from '../entities/User';
import { AppDataSource } from '../config/data-source';

declare global {
  namespace Express {
    interface Request {
      user?: Partial<User>; // Keep using Partial<User> or define a specific type like { id: string; role: UserRole }
    }
  }
}

export const authenticateJWT = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const authHeader = req.header('Authorization');
  const token = authHeader?.startsWith('Bearer ') ? authHeader.split(' ')[1] : null; // Safer extraction

  if (!token) {
    // No token provided
    res.status(401).json({ error: 'Unauthorized - Token required' });
    return; // Stop execution
  }

  try {
    // 1. Verify token
    // Ensure JWT_SECRET is defined, handle potential error if not
    if (!process.env.JWT_SECRET) {
        console.error("FATAL ERROR: JWT_SECRET environment variable is not defined.");
        res.status(500).json({ error: 'Internal server configuration error' });
        return; // Stop execution
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET) as { id: string };

    // 2. Fetch user from database
    const user = await AppDataSource.getRepository(User).findOne({
      where: { id: decoded.id },
      select: ['id', 'role'], // Only fetch needed fields
    });

    if (!user) {
      // User ID from token doesn't exist in DB (token might be old/invalid)
      console.error('AUTH: User not found in DB for ID:', decoded.id);
      res.status(403).json({ error: 'Forbidden - Invalid user session' }); // Changed message slightly
      return; // Stop execution
    }

    // 3. Attach user info to request and proceed
    console.log('AUTH: User fetched:', { id: user.id, role: user.role });
    req.user = { id: user.id, role: user.role };
    next(); // <-- Call next() ONLY ONCE on success

    // !!! REMOVED THE DUPLICATE BLOCK THAT WAS HERE !!!

  } catch (err) {
    // Handle JWT errors (expired, malformed, invalid signature etc.)
    const errorMsg = err instanceof Error ? err.message : err;
    console.error('AUTH: JWT verification failed:', errorMsg); // Log specific error
    res.status(403).json({ error: 'Forbidden - Invalid or expired token' }); // Changed message slightly
    return; // Stop execution - Added explicit return
  }
};

// allowRoles function remains the same as it looked correct
export const allowRoles = (roles: UserRole[]) => (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  console.log('ALLOWROLES: Checking access. Required roles:', roles);
  console.log('ALLOWROLES: User on request:', req.user);

  // Ensure req.user and req.user.role exist before checking includes
  if (!req.user?.role || !roles.includes(req.user.role)) {
    console.error('ALLOWROLES: Forbidden! User role:', req.user?.role, 'does not match required:', roles);
    res.status(403).json({ error: 'Forbidden - Insufficient permissions' }); // Changed message slightly
    return; // Stop execution
  }

  console.log('ALLOWROLES: Access granted.');
  next();
};
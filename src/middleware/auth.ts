import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

export const authenticateJWT = (req: Request, res: Response, next: NextFunction) => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Unauthorized' });

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET!) as { role: string };
    (req as any).user = payload;
    next();
  } catch (err) {
    res.status(403).json({ message: 'Invalid token' });
  }
};

export const allowRoles = (roles: string[]) => (req: Request, res: Response, next: NextFunction) => {
  const userRole = (req as any).user?.role;
  if (!roles.includes(userRole)) return res.status(403).json({ message: 'Forbidden' });
  next();
};
import { PoolClient, QueryResult } from 'pg';
import pool from '../config/database';
import bcrypt from 'bcrypt';

interface User {
  id: number;
  email: string;
  password: string;
  created_at: Date;
}

const UserModel = {
  async create({ email, password }: { email: string; password: string }): Promise<User> {
    const hashedPassword = await bcrypt.hash(password, 10);
    const { rows }: QueryResult<User> = await pool.query(
      'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email',
      [email, hashedPassword]
    );
    return rows[0];
  },

  async findByEmail(email: string): Promise<User | null> {
    const { rows }: QueryResult<User> = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    return rows[0] || null;
  },
};

export default UserModel;
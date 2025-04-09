//src/routes/superAdmin.ts
import express from 'express';
import { authenticateJWT, allowRoles } from '../middleware/auth';
import { User, UserRole } from '../entities/User';
import { AppDataSource } from '../config/data-source';
import bcrypt from 'bcrypt';

const router = express.Router();

/**
 * @swagger
 * tags:
 *   name: Super Admin
 *   description: Super admin operations
 */

/**
 * @swagger
 * /super-admin/admins:
 *   post:
 *     summary: Create admin account (Super Admin only)
 *     tags: [Super Admin]
 *     security:
 *       - bearerAuth: []
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
 *               password:
 *                 type: string
 *     responses:
 *       201:
 *         description: Admin created
 */
router.post('/admins', authenticateJWT, allowRoles([UserRole.SUPER_ADMIN]), async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const admin = new User();
  admin.email = email;
  admin.password = hashedPassword;
  admin.role = UserRole.ADMIN;

  await AppDataSource.manager.save(admin);
  void res.status(201).json({ id: admin.id });
});



// ... (existing imports and code)

/**
 * @swagger
 * /super-admin/admins:
 *   get:
 *     summary: List all Admins (Super Admin only)
 *     tags: [Super Admin]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of Admins
 */
router.get('/admins', authenticateJWT, allowRoles([UserRole.SUPER_ADMIN]), async (req, res) => {
  const admins = await AppDataSource.getRepository(User).find({
    where: { role: UserRole.ADMIN },
    select: ['id', 'email', 'role'] // Exclude password
  });
  void res.json(admins);
});

/**
 * @swagger
 * /super-admin/admins/{id}:
 *   get:
 *     summary: Get Admin by ID (Super Admin only)
 *     tags: [Super Admin]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         schema:
 *           type: string
 *         required: true
 *     responses:
 *       200:
 *         description: Admin details
 *       404:
 *         description: Admin not found
 */
router.get('/admins/:id', authenticateJWT, allowRoles([UserRole.SUPER_ADMIN]), async (req, res): Promise<void> => {
  const admin = await AppDataSource.getRepository(User).findOne({
    where: { id: req.params.id, role: UserRole.ADMIN },
    select: ['id', 'email', 'role']
  });
  if (!admin) {
    void res.status(404).json({ error: "Admin not found" });
    return;
  }
  void res.json(admin);
});

/**
 * @swagger
 * /super-admin/admins/{id}:
 *   put:
 *     summary: Update Admin (Super Admin only)
 *     tags: [Super Admin]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         schema:
 *           type: string
 *         required: true
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Admin updated
 *       404:
 *         description: Admin not found
 */
router.put('/admins/:id', authenticateJWT, allowRoles([UserRole.SUPER_ADMIN]), async (req, res): Promise<void> => {
  const { email, password } = req.body;
  const admin = await AppDataSource.getRepository(User).findOneBy({ 
    id: req.params.id, 
    role: UserRole.ADMIN 
  });

  if (!admin) {
    void res.status(404).json({ error: "Admin not found" });
    return;
  }

  if (email) admin.email = email;
  if (password) admin.password = await bcrypt.hash(password, 10);

  await AppDataSource.manager.save(admin);
  void res.json({ id: admin.id });
});

/**
 * @swagger
 * /super-admin/admins/{id}:
 *   delete:
 *     summary: Delete Admin (Super Admin only)
 *     tags: [Super Admin]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         schema:
 *           type: string
 *         required: true
 *     responses:
 *       204:
 *         description: Admin deleted
 *       404:
 *         description: Admin not found
 */
router.delete('/admins/:id', authenticateJWT, allowRoles([UserRole.SUPER_ADMIN]), async (req, res) => {
  const admin = await AppDataSource.getRepository(User).findOneBy({ 
    id: req.params.id, 
    role: UserRole.ADMIN 
  });

  if (!admin) {
    void res.status(404).json({ error: "Admin not found" });
    return;
  }

  await AppDataSource.manager.remove(admin);
  void res.status(204).send();
});

export default router;
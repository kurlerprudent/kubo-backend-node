// src/routes/patient.ts
import express, { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import { User, UserRole } from '../entities/User';
import { AppDataSource } from '../config/data-source';
import { authenticateJWT, allowRoles } from '../middleware/auth';

const router = express.Router();
const userRepository = AppDataSource.getRepository(User);

/**
 * @swagger
 * tags:
 *   name: Patient
 *   description: Patient self-service operations (CRUD)
 */

/**
 * @swagger
 * /patients/register:
 *   post:
 *     summary: Register a new patient account
 *     tags: [Patient]
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
 *               password:
 *                 type: string
 *                 minLength: 6
 *               doctorId:
 *                 type: string
 *                 format: uuid
 *                 description: Optional. If provided, assign the patient to the specified doctor.
 *     responses:
 *       201:
 *         description: Patient account created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: string
 *                 email:
 *                   type: string
 *                 role:
 *                   type: string
 *                 assignedDoctorId:
 *                   type: string
 *       400:
 *         description: Bad Request (missing fields or invalid data)
 *       409:
 *         description: Conflict (email already exists)
 *       500:
 *         description: Internal Server Error
 */
router.post('/register', async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password, doctorId } = req.body;
    if (!email || !password) {
      res.status(400).json({ message: 'Email and password are required' });
      return;
    }
    const lowerCaseEmail = email.toLowerCase();
    const existingUser = await userRepository.findOneBy({ email: lowerCaseEmail });
    if (existingUser) {
      res.status(409).json({ message: 'Email address already in use' });
      return;
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const patient = new User();
    patient.email = lowerCaseEmail;
    patient.password = hashedPassword;
    patient.role = UserRole.PATIENT;
    
    // If doctorId is provided, verify a DOCTOR exists.
    if (doctorId) {
      const doctor = await userRepository.findOneBy({ id: doctorId, role: UserRole.DOCTOR });
      if (!doctor) {
        res.status(400).json({ message: 'Invalid doctorId. No doctor found with the provided ID.' });
        return;
      }
      patient.assignedDoctorId = doctorId;
    }
    
    await userRepository.save(patient);
    res.status(201).json({
      id: patient.id,
      email: patient.email,
      role: patient.role,
      assignedDoctorId: patient.assignedDoctorId || null,
    });
    return;
  } catch (error: any) {
    console.error('Error registering patient:', error);
    if (error.code === '23505') {
      res.status(409).json({ message: 'Email address already in use (DB constraint)' });
      return;
    }
    res.status(500).json({ message: 'Internal server error registering patient' });
    return;
  }
});

/**
 * @swagger
 * /patients/me:
 *   get:
 *     summary: Get the logged-in patient's profile
 *     tags: [Patient]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Patient profile retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: string
 *                 email:
 *                   type: string
 *                 role:
 *                   type: string
 *                 assignedDoctorId:
 *                   type: string
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Internal Server Error
 */
router.get(
  '/me',
  authenticateJWT,
  // Allowed roles include patient self-service and administrators/doctors who might have elevated permissions.
  allowRoles([UserRole.PATIENT, UserRole.ADMIN, UserRole.DOCTOR, UserRole.SUPER_ADMIN]),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const userId = req.user?.id;
      if (!userId) {
        res.status(401).json({ message: 'Unauthorized' });
        return;
      }
      const patient = await userRepository.findOne({
        where: { id: userId },
        select: ['id', 'email', 'role', 'assignedDoctorId'],
      });
      if (!patient) {
        res.status(404).json({ message: 'Patient not found' });
        return;
      }
      res.json(patient);
      return;
    } catch (error) {
      console.error('Error fetching patient profile:', error);
      res.status(500).json({ message: 'Internal server error fetching patient profile' });
      return;
    }
  }
);

/**
 * @swagger
 * /patients/me:
 *   put:
 *     summary: Update the logged-in patient's profile
 *     tags: [Patient]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 minLength: 6
 *               doctorId:
 *                 type: string
 *                 format: uuid
 *                 description: Optional. If provided, reassign the patient to the specified doctor.
 *     responses:
 *       200:
 *         description: Patient profile updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: string
 *                 email:
 *                   type: string
 *                 role:
 *                   type: string
 *                 assignedDoctorId:
 *                   type: string
 *       400:
 *         description: Bad Request (invalid data)
 *       401:
 *         description: Unauthorized
 *       409:
 *         description: Conflict (email already in use)
 *       500:
 *         description: Internal Server Error
 */
router.put(
  '/me',
  authenticateJWT,
  allowRoles([UserRole.PATIENT, UserRole.ADMIN, UserRole.DOCTOR, UserRole.SUPER_ADMIN]),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const userId = req.user?.id;
      if (!userId) {
        res.status(401).json({ message: 'Unauthorized' });
        return;
      }
      const { email, password, doctorId } = req.body;
      const patient = await userRepository.findOneBy({ id: userId });
      if (!patient) {
        res.status(404).json({ message: 'Patient not found' });
        return;
      }
      if (email) {
        const lowerCaseEmail = email.toLowerCase();
        // Check if the new email is already taken.
        const existingUser = await userRepository.findOneBy({ email: lowerCaseEmail });
        if (existingUser && existingUser.id !== patient.id) {
          res.status(409).json({ message: 'Email address already in use' });
          return;
        }
        patient.email = lowerCaseEmail;
      }
      if (password) {
        patient.password = await bcrypt.hash(password, 10);
      }
      if (doctorId) {
        // Verify that the provided doctor exists and has the DOCTOR role.
        const doctor = await userRepository.findOneBy({ id: doctorId, role: UserRole.DOCTOR });
        if (!doctor) {
          res.status(400).json({ message: 'Invalid doctorId. No doctor found with the provided ID.' });
          return;
        }
        patient.assignedDoctorId = doctorId;
      }
      await userRepository.save(patient);
      res.json({
        id: patient.id,
        email: patient.email,
        role: patient.role,
        assignedDoctorId: patient.assignedDoctorId || null,
      });
      return;
    } catch (error: any) {
      console.error('Error updating patient profile:', error);
      if (error.code === '23505') {
        res.status(409).json({ message: 'Email address already in use (DB constraint)' });
        return;
      }
      res.status(500).json({ message: 'Internal server error updating patient profile' });
      return;
    }
  }
);

/**
 * @swagger
 * /patients/me:
 *   delete:
 *     summary: Delete the logged-in patient's account
 *     tags: [Patient]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       204:
 *         description: Patient account deleted successfully (No Content)
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Patient not found
 *       500:
 *         description: Internal Server Error
 */
router.delete(
  '/me',
  authenticateJWT,
  allowRoles([UserRole.PATIENT, UserRole.ADMIN, UserRole.DOCTOR, UserRole.SUPER_ADMIN]),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const userId = req.user?.id;
      if (!userId) {
        res.status(401).json({ message: 'Unauthorized' });
        return;
      }
      const patient = await userRepository.findOneBy({ id: userId });
      if (!patient) {
        res.status(404).json({ message: 'Patient not found' });
        return;
      }
      await userRepository.remove(patient);
      res.status(204).send();
      return;
    } catch (error) {
      console.error('Error deleting patient account:', error);
      res.status(500).json({ message: 'Internal server error deleting patient account' });
      return;
    }
  }
);

export default router;

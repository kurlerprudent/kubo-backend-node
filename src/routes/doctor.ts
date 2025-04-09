// src/routes/doctor.ts

import express, { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { User, UserRole } from '../entities/User';
import { AppDataSource } from '../config/data-source';
import { authenticateJWT, allowRoles } from '../middleware/auth';

const router = express.Router();
const userRepository = AppDataSource.getRepository(User);

// ------------------------------------------------
// In-memory storage for reports (for demonstration)
interface Report {
  id: string;
  doctorId: string;
  patientId: string;
  reportContent: string;
  createdAt: Date;
}

const reports: Report[] = [];

/**
 * @swagger
 * tags:
 *   name: Doctor
 *   description: Doctor-specific operations including profile management, patient registration, and report generation
 */

/**
 * @swagger
 * /doctor/register-patient:
 *   post:
 *     summary: Doctor registers a new patient (automatically assigned to the doctor)
 *     tags: [Doctor]
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
 *                 format: email
 *               password:
 *                 type: string
 *                 minLength: 6
 *               firstName:
 *                 type: string
 *               lastName:
 *                 type: string
 *               dateOfBirth:
 *                 type: string
 *                 format: date
 *               gender:
 *                 type: string
 *               phone:
 *                 type: string
 *               address:
 *                 type: string
 *     responses:
 *       201:
 *         description: Patient created successfully and automatically assigned to the doctor
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
 *       401:
 *         description: Unauthorized
 *       409:
 *         description: Conflict (email already exists)
 *       500:
 *         description: Internal Server Error
 */
router.post(
  '/register-patient',
  authenticateJWT,
  allowRoles([UserRole.DOCTOR]),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const doctorId = req.user?.id;
      if (!doctorId) {
        res.status(401).json({ message: 'Unauthorized' });
        return;
      }

      const { email, password, firstName, lastName, dateOfBirth, gender, phone, address } = req.body;
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
      
      // Set common profile fields
      patient.firstName = firstName;
      patient.lastName = lastName;
      patient.dateOfBirth = dateOfBirth;
      patient.gender = gender;
      patient.phone = phone;
      patient.address = address;

      // Automatically assign the logged in doctor as the patient's doctor
      patient.assignedDoctorId = doctorId;
      const doctor = await userRepository.findOneBy({ id: doctorId, role: UserRole.DOCTOR });
      if (doctor) {
        patient.assignedDoctor = doctor;
      }

      await userRepository.save(patient);
      res.status(201).json({
        id: patient.id,
        email: patient.email,
        role: patient.role,
        assignedDoctorId: patient.assignedDoctorId
      });
      return;
    } catch (error: any) {
      console.error('Error creating patient by doctor:', error);
      if (error.code === '23505') {
        res.status(409).json({ message: 'Email address already in use (DB constraint)' });
        return;
      }
      res.status(500).json({ message: 'Internal server error creating patient' });
      return;
    }
  }
);

// ------------------------------
// Existing Doctor Profile and Report Endpoints (unchanged) ------------------------------

// Get Doctor Profile
router.get(
  '/me',
  authenticateJWT,
  allowRoles([UserRole.DOCTOR, UserRole.ADMIN, UserRole.SUPER_ADMIN]),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const doctorId = req.user?.id;
      if (!doctorId) {
        res.status(401).json({ message: 'Unauthorized' });
        return;
      }
      const doctor = await userRepository.findOne({
        where: { id: doctorId, role: UserRole.DOCTOR },
        select: ['id', 'email', 'firstName', 'lastName', 'specialization', 'qualifications', 'bio', 'yearsOfExperience', 'profilePhotoUrl']
      });
      if (!doctor) {
        res.status(404).json({ message: 'Doctor not found' });
        return;
      }
      res.json(doctor);
      return;
    } catch (error) {
      console.error('Error fetching doctor profile:', error);
      res.status(500).json({ message: 'Internal server error fetching doctor profile' });
      return;
    }
  }
);

// Update Doctor Profile
router.put(
  '/me',
  authenticateJWT,
  allowRoles([UserRole.DOCTOR, UserRole.ADMIN, UserRole.SUPER_ADMIN]),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const doctorId = req.user?.id;
      if (!doctorId) {
        res.status(401).json({ message: 'Unauthorized' });
        return;
      }
      const { email, password, firstName, lastName, specialization, qualifications, bio, yearsOfExperience, profilePhotoUrl } = req.body;
      const doctor = await userRepository.findOneBy({ id: doctorId });
      if (!doctor) {
        res.status(404).json({ message: 'Doctor not found' });
        return;
      }
      if (email) {
        const lowerCaseEmail = email.toLowerCase();
        const existingUser = await userRepository.findOneBy({ email: lowerCaseEmail });
        if (existingUser && existingUser.id !== doctor.id) {
          res.status(409).json({ message: 'Email address already in use' });
          return;
        }
        doctor.email = lowerCaseEmail;
      }
      if (password) {
        doctor.password = await bcrypt.hash(password, 10);
      }
      if (firstName) doctor.firstName = firstName;
      if (lastName) doctor.lastName = lastName;
      if (specialization) doctor.specialization = specialization;
      if (qualifications) doctor.qualifications = qualifications;
      if (bio) doctor.bio = bio;
      if (yearsOfExperience) doctor.yearsOfExperience = yearsOfExperience;
      if (profilePhotoUrl) doctor.profilePhotoUrl = profilePhotoUrl;
      await userRepository.save(doctor);
      res.json({
        id: doctor.id,
        email: doctor.email,
        firstName: doctor.firstName,
        lastName: doctor.lastName,
        specialization: doctor.specialization,
        qualifications: doctor.qualifications,
        bio: doctor.bio,
        yearsOfExperience: doctor.yearsOfExperience,
        profilePhotoUrl: doctor.profilePhotoUrl
      });
      return;
    } catch (error: any) {
      console.error('Error updating doctor profile:', error);
      if (error.code === '23505') {
        res.status(409).json({ message: 'Email address already in use (DB constraint)' });
        return;
      }
      res.status(500).json({ message: 'Internal server error updating doctor profile' });
      return;
    }
  }
);

// Delete Doctor Profile
router.delete(
  '/me',
  authenticateJWT,
  allowRoles([UserRole.DOCTOR, UserRole.ADMIN, UserRole.SUPER_ADMIN]),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const doctorId = req.user?.id;
      if (!doctorId) {
        res.status(401).json({ message: 'Unauthorized' });
        return;
      }
      const doctor = await userRepository.findOneBy({ id: doctorId, role: UserRole.DOCTOR });
      if (!doctor) {
        res.status(404).json({ message: 'Doctor not found' });
        return;
      }
      await userRepository.remove(doctor);
      res.status(204).send();
      return;
    } catch (error) {
      console.error('Error deleting doctor account:', error);
      res.status(500).json({ message: 'Internal server error deleting doctor account' });
      return;
    }
  }
);

// ------------------------------
// Report Endpoints (unchanged) ------------------------------
/**
 * @swagger
 * /doctor/reports:
 *   post:
 *     summary: Generate a new report for a patient (Doctor only)
 *     tags: [Doctor]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - patientId
 *               - imagingData
 *             properties:
 *               patientId:
 *                 type: string
 *                 format: uuid
 *                 description: ID of the patient for whom the report is generated
 *               imagingData:
 *                 type: string
 *                 description: Textual summary or data from the imaging analysis
 *     responses:
 *       201:
 *         description: Report generated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: string
 *                 doctorId:
 *                   type: string
 *                 patientId:
 *                   type: string
 *                 reportContent:
 *                   type: string
 *                 createdAt:
 *                   type: string
 *                   format: date-time
 *       400:
 *         description: Bad Request
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Internal server error
 */
router.post(
  '/reports',
  authenticateJWT,
  allowRoles([UserRole.DOCTOR]),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const doctorId = req.user?.id;
      if (!doctorId) {
        res.status(401).json({ message: 'Unauthorized' });
        return;
      }
      const { patientId, imagingData } = req.body;
      if (!patientId || !imagingData) {
        res.status(400).json({ message: 'PatientId and imagingData are required' });
        return;
      }
      const reportContent = `Report for patient ${patientId}: Findings summarized - ${imagingData}`;
      const newReport: Report = {
        id: uuidv4(),
        doctorId,
        patientId,
        reportContent,
        createdAt: new Date()
      };
      reports.push(newReport);
      res.status(201).json(newReport);
      return;
    } catch (error: any) {
      console.error('Error generating report:', error);
      res.status(500).json({ message: 'Internal server error generating report' });
      return;
    }
  }
);

/**
 * @swagger
 * /doctor/reports:
 *   get:
 *     summary: Retrieve all reports generated by the logged-in doctor
 *     tags: [Doctor]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of reports
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: string
 *                   doctorId:
 *                     type: string
 *                   patientId:
 *                     type: string
 *                   reportContent:
 *                     type: string
 *                   createdAt:
 *                     type: string
 *                     format: date-time
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Internal server error
 */
router.get(
  '/reports',
  authenticateJWT,
  allowRoles([UserRole.DOCTOR]),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const doctorId = req.user?.id;
      if (!doctorId) {
        res.status(401).json({ message: 'Unauthorized' });
        return;
      }
      const doctorReports = reports.filter((report) => report.doctorId === doctorId);
      res.json(doctorReports);
      return;
    } catch (error: any) {
      console.error('Error fetching reports:', error);
      res.status(500).json({ message: 'Internal server error fetching reports' });
      return;
    }
  }
);

export default router;

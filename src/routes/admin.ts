// src/routes/admin.ts

import express, { Request, Response } from 'express';
import { authenticateJWT, allowRoles } from '../middleware/auth';
import { User, UserRole } from '../entities/User';
import { AppDataSource } from '../config/data-source';
import bcrypt from 'bcrypt';
import { QueryFailedError } from 'typeorm';
import { validate as validateUUID } from 'uuid';

const router = express.Router();
const userRepository = AppDataSource.getRepository(User);

/**
 * @swagger
 * tags:
 *   - name: Admin - Doctor Management
 *     description: Admin operations for managing Doctor accounts
 */

/**
 * @swagger
 * /admin/doctors:
 *   post:
 *     summary: Create Doctor account (Admin only)
 *     tags: [Admin - Doctor Management]
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
 *               - firstName
 *               - lastName
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 description: Doctor's email address
 *               password:
 *                 type: string
 *                 format: password
 *                 minLength: 6
 *                 description: Doctor's initial password
 *               firstName:
 *                 type: string
 *                 description: Doctor's first name
 *               lastName:
 *                 type: string
 *                 description: Doctor's last name
 *               phone:
 *                 type: string
 *                 nullable: true
 *                 description: Doctor's contact phone number
 *               address:
 *                 type: string
 *                 nullable: true
 *                 description: Doctor's address
 *               specialization:
 *                 type: string
 *                 nullable: true
 *                 description: Doctor's medical specialization
 *               qualifications:
 *                 type: string
 *                 nullable: true
 *                 description: Doctor's qualifications or certifications
 *               bio:
 *                 type: string
 *                 nullable: true
 *                 description: Short biography for the doctor
 *               yearsOfExperience:
 *                 type: number
 *                 nullable: true
 *                 description: Doctor's years of experience
 *               profilePhotoUrl:
 *                 type: string
 *                 format: url
 *                 nullable: true
 *                 description: URL to the doctor's profile photo
 *     responses:
 *       '201':
 *         description: Doctor created successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/DoctorProfileResponse'
 *       '400':
 *         description: Bad Request (e.g., missing fields, invalid email)
 *       '401':
 *         description: Unauthorized
 *       '403':
 *         description: Forbidden (User is not an Admin)
 *       '409':
 *         description: Conflict (Email already exists)
 *       '500':
 *         description: Internal Server Error
 */
router.post(
  '/doctors',
  authenticateJWT,
  allowRoles([UserRole.ADMIN, UserRole.SUPER_ADMIN]),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const {
        email, password, firstName, lastName, phone, address,
        specialization, qualifications, bio, yearsOfExperience, profilePhotoUrl
      } = req.body;

      if (!email || !password || !firstName || !lastName) {
        res.status(400).json({ message: 'Email, password, firstName, and lastName are required' });
        return;
      }

      const lowerCaseEmail = email.toLowerCase();
      const existingUser = await userRepository.findOneBy({ email: lowerCaseEmail });
      if (existingUser) {
        res.status(409).json({ message: 'Email address already in use' });
        return;
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const doctor = userRepository.create({
        email: lowerCaseEmail,
        password: hashedPassword,
        role: UserRole.DOCTOR,
        firstName,
        lastName,
        phone: phone ?? null,
        address: address ?? null,
        specialization: specialization ?? null,
        qualifications: qualifications ?? null,
        bio: bio ?? null,
        yearsOfExperience: yearsOfExperience ?? null,
        profilePhotoUrl: profilePhotoUrl ?? null
      });

      await userRepository.save(doctor);
      const { password: _, ...responseData } = doctor;
      res.status(201).json(responseData);
    } catch (error: any) {
      console.error('Error creating doctor:', error);
      if (error instanceof QueryFailedError && error.driverError?.code === '23505') {
        res.status(409).json({ message: 'Email address already in use (DB constraint)' });
      } else {
        res.status(500).json({ message: 'Internal server error creating doctor' });
      }
    }
  }
);

/**
 * @swagger
 * /admin/doctors:
 *   get:
 *     summary: List all Doctors (Admin only)
 *     tags: [Admin - Doctor Management]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: A list of Doctor accounts
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/DoctorProfileResponse'
 *       '500':
 *         description: Internal Server Error
 */
router.get(
  '/doctors',
  authenticateJWT,
  allowRoles([UserRole.ADMIN, UserRole.SUPER_ADMIN]),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const doctors = await userRepository.find({
        where: { role: UserRole.DOCTOR },
        select: [
          'id', 'email', 'role', 'firstName', 'lastName', 'phone', 'address',
          'specialization', 'qualifications', 'bio', 'yearsOfExperience', 'profilePhotoUrl'
        ]
      });
      res.json(doctors);
    } catch (error) {
      console.error('Error fetching doctors:', error);
      res.status(500).json({ message: 'Internal server error fetching doctors' });
    }
  }
);

/**
 * @swagger
 * /admin/doctors/{id}:
 *   get:
 *     summary: Get Doctor by ID (Admin only)
 *     tags: [Admin - Doctor Management]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/UserId'
 *     responses:
 *       '200':
 *         description: Doctor details retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/DoctorProfileResponse'
 *       '400':
 *         description: Invalid ID format
 *       '404':
 *         description: Doctor not found
 *       '500':
 *         description: Internal Server Error
 */
router.get(
  '/doctors/:id',
  authenticateJWT,
  allowRoles([UserRole.ADMIN, UserRole.SUPER_ADMIN]),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const doctorId = req.params.id;
      if (!validateUUID(doctorId)) {
        res.status(400).json({ message: 'Invalid ID format' });
        return;
      }
      const doctor = await userRepository.findOne({
        where: { id: doctorId, role: UserRole.DOCTOR },
        select: [
          'id', 'email', 'role', 'firstName', 'lastName', 'phone', 'address',
          'specialization', 'qualifications', 'bio', 'yearsOfExperience', 'profilePhotoUrl'
        ]
      });
      if (!doctor) {
        res.status(404).json({ message: 'Doctor not found' });
        return;
      }
      res.json(doctor);
    } catch (error: any) {
      console.error('Error fetching doctor by ID:', error);
      res.status(500).json({ message: 'Internal server error fetching doctor' });
    }
  }
);

/**
 * @swagger
 * /admin/doctors/{id}:
 *   put:
 *     summary: Update Doctor details (Admin only)
 *     tags: [Admin - Doctor Management]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/UserId'
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
 *               firstName:
 *                 type: string
 *               lastName:
 *                 type: string
 *               phone:
 *                 type: string
 *               address:
 *                 type: string
 *               specialization:
 *                 type: string
 *               qualifications:
 *                 type: string
 *               bio:
 *                 type: string
 *               yearsOfExperience:
 *                 type: number
 *               profilePhotoUrl:
 *                 type: string
 *                 format: url
 *     responses:
 *       '200':
 *         description: Doctor updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/DoctorProfileResponse'
 *       '400':
 *         description: Bad Request (e.g., invalid ID or no valid fields provided)
 *       '401':
 *         description: Unauthorized
 *       '404':
 *         description: Doctor not found
 *       '409':
 *         description: Conflict (Email already in use)
 *       '500':
 *         description: Internal Server Error
 */
router.put(
  '/doctors/:id',
  authenticateJWT,
  allowRoles([UserRole.ADMIN, UserRole.SUPER_ADMIN]),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const doctorId = req.params.id;
      if (!validateUUID(doctorId)) {
        res.status(400).json({ message: 'Invalid ID format' });
        return;
      }

      const updateData = req.body;
      const validFields = [
        'email', 'password', 'firstName', 'lastName', 'phone', 'address',
        'specialization', 'qualifications', 'bio', 'yearsOfExperience', 'profilePhotoUrl'
      ];
      const fieldsToUpdate = Object.keys(updateData).filter(key => validFields.includes(key) && updateData[key] !== undefined);

      if (fieldsToUpdate.length === 0) {
        res.status(400).json({ message: 'No valid update fields provided' });
        return;
      }

      const doctor = await userRepository.findOneBy({ id: doctorId, role: UserRole.DOCTOR });
      if (!doctor) {
        res.status(404).json({ message: 'Doctor not found' });
        return;
      }

      let needsSave = false;
      if (updateData.email !== undefined) {
        const lowerCaseEmail = updateData.email.toLowerCase();
        if (lowerCaseEmail !== doctor.email) {
          const existingUser = await userRepository.findOneBy({ email: lowerCaseEmail });
          if (existingUser && existingUser.id !== doctorId) {
            res.status(409).json({ message: 'New email address already in use' });
            return;
          }
          doctor.email = lowerCaseEmail;
          needsSave = true;
        }
      }
      if (updateData.password) {
        doctor.password = await bcrypt.hash(updateData.password, 10);
        needsSave = true;
      }
      if (updateData.firstName !== undefined) { doctor.firstName = updateData.firstName; needsSave = true; }
      if (updateData.lastName !== undefined) { doctor.lastName = updateData.lastName; needsSave = true; }
      if (updateData.phone !== undefined) { doctor.phone = updateData.phone; needsSave = true; }
      if (updateData.address !== undefined) { doctor.address = updateData.address; needsSave = true; }
      if (updateData.specialization !== undefined) { doctor.specialization = updateData.specialization; needsSave = true; }
      if (updateData.qualifications !== undefined) { doctor.qualifications = updateData.qualifications; needsSave = true; }
      if (updateData.bio !== undefined) { doctor.bio = updateData.bio; needsSave = true; }
      if (updateData.yearsOfExperience !== undefined) { doctor.yearsOfExperience = updateData.yearsOfExperience; needsSave = true; }
      if (updateData.profilePhotoUrl !== undefined) { doctor.profilePhotoUrl = updateData.profilePhotoUrl; needsSave = true; }

      if (needsSave) {
        await userRepository.save(doctor);
      }

      const updatedDoctor = await userRepository.findOne({ 
        where: { id: doctorId },
        select: [
          'id', 'email', 'role', 'firstName', 'lastName', 'phone', 'address',
          'specialization', 'qualifications', 'bio', 'yearsOfExperience', 'profilePhotoUrl'
        ]
      });
      res.json(updatedDoctor);
    } catch (error: any) {
      console.error('Error updating doctor:', error);
      if (error instanceof QueryFailedError && error.driverError?.code === '23505') {
        res.status(409).json({ message: 'Email address already in use (DB constraint)' });
      } else {
        res.status(500).json({ message: 'Internal server error updating doctor' });
      }
    }
  }
);

/**
 * @swagger
 * /admin/doctors/{id}:
 *   delete:
 *     summary: Delete a Doctor account (Admin only)
 *     tags: [Admin - Doctor Management]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/UserId'
 *     responses:
 *       '204':
 *         description: Doctor deleted successfully (No Content)
 *       '400':
 *         description: Invalid ID format
 *       '404':
 *         description: Doctor not found
 *       '409':
 *         description: Conflict (Doctor has assigned patients)
 *       '500':
 *         description: Internal Server Error
 */
router.delete(
  '/doctors/:id',
  authenticateJWT,
  allowRoles([UserRole.ADMIN, UserRole.SUPER_ADMIN]),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const doctorId = req.params.id;
      if (!validateUUID(doctorId)) {
        res.status(400).json({ message: 'Invalid ID format' });
        return;
      }
      const doctor = await userRepository.findOneBy({ id: doctorId, role: UserRole.DOCTOR });
      if (!doctor) {
        res.status(404).json({ message: 'Doctor not found' });
        return;
      }
      const patientCount = await userRepository.count({ where: { assignedDoctorId: doctorId } });
      if (patientCount > 0) {
        res.status(409).json({ message: `Cannot delete doctor. ${patientCount} patient(s) are currently assigned.` });
        return;
      }
      await userRepository.remove(doctor);
      res.status(204).send();
    } catch (error: any) {
      console.error('Error deleting doctor:', error);
      if (error instanceof QueryFailedError && error.driverError?.code === '23503') {
        res.status(409).json({ message: 'Cannot delete doctor, possibly referenced elsewhere' });
      } else {
        res.status(500).json({ message: 'Internal server error deleting doctor' });
      }
    }
  }
);

/**
 * @swagger
 * tags:
 *   - name: Admin - Patient Management
 *     description: Admin operations for managing Patient accounts
 */

/**
 * @swagger
 * /admin/patients:
 *   post:
 *     summary: Create Patient account and assign a Doctor (Admin only)
 *     tags: [Admin - Patient Management]
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
 *               - firstName
 *               - lastName
 *               - assignedDoctorId
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 format: password
 *                 minLength: 6
 *               firstName:
 *                 type: string
 *               lastName:
 *                 type: string
 *               phone:
 *                 type: string
 *                 nullable: true
 *               address:
 *                 type: string
 *                 nullable: true
 *               dateOfBirth:
 *                 type: string
 *                 format: date
 *                 nullable: true
 *               gender:
 *                 type: string
 *                 nullable: true
 *               assignedDoctorId:
 *                 type: string
 *                 format: uuid
 *                 description: The ID of the Doctor to assign to this patient
 *     responses:
 *       '201':
 *         description: Patient created successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/PatientProfileResponse'
 *       '400':
 *         description: Bad Request (missing fields, invalid format)
 *       '401':
 *         description: Unauthorized
 *       '403':
 *         description: Forbidden (User is not an Admin)
 *       '404':
 *         description: Assigned Doctor not found or not a Doctor
 *       '409':
 *         description: Conflict (Patient email already exists)
 *       '500':
 *         description: Internal Server Error
 */
router.post(
  '/patients',
  authenticateJWT,
  allowRoles([UserRole.ADMIN, UserRole.SUPER_ADMIN]),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const {
        email, password, firstName, lastName, phone, address,
        dateOfBirth, gender, assignedDoctorId
      } = req.body;

      if (!email || !password || !firstName || !lastName || !assignedDoctorId) {
        res.status(400).json({ message: 'Email, password, firstName, lastName, and assignedDoctorId are required' });
        return;
      }
      if (!validateUUID(assignedDoctorId)) {
        res.status(400).json({ message: 'Invalid assignedDoctorId format' });
        return;
      }
      const lowerCaseEmail = email.toLowerCase();
      const existingUser = await userRepository.findOneBy({ email: lowerCaseEmail });
      if (existingUser) {
        res.status(409).json({ message: 'Email address already in use' });
        return;
      }

      const assignedDoctor = await userRepository.findOneBy({ id: assignedDoctorId, role: UserRole.DOCTOR });
      if (!assignedDoctor) {
        res.status(404).json({ message: `Doctor with ID ${assignedDoctorId} not found or is not a Doctor.` });
        return;
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const patient = userRepository.create({
        email: lowerCaseEmail,
        password: hashedPassword,
        role: UserRole.PATIENT,
        firstName,
        lastName,
        phone: phone ?? null,
        address: address ?? null,
        dateOfBirth: dateOfBirth ?? null,
        gender: gender ?? null,
        assignedDoctorId: assignedDoctor.id
      });
      await userRepository.save(patient);
      const { password: _, ...responseData } = patient;
      res.status(201).json(responseData);
    } catch (error: any) {
      console.error('Error creating patient:', error);
      if (error instanceof QueryFailedError && error.driverError?.code === '23505') {
        res.status(409).json({ message: 'Email address already in use (DB constraint)' });
      } else {
        res.status(500).json({ message: 'Internal server error creating patient' });
      }
    }
  }
);

/**
 * @swagger
 * /admin/patients:
 *   get:
 *     summary: List all Patient accounts (Admin only)
 *     tags: [Admin - Patient Management]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: A list of Patient accounts
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/PatientProfileResponse'
 *       '500':
 *         description: Internal Server Error
 */
router.get(
  '/patients',
  authenticateJWT,
  allowRoles([UserRole.ADMIN, UserRole.SUPER_ADMIN]),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const patients = await userRepository.find({
        where: { role: UserRole.PATIENT },
        select: [
          'id', 'email', 'role', 'firstName', 'lastName', 'phone', 'address',
          'dateOfBirth', 'gender', 'assignedDoctorId'
        ],
        relations: { assignedDoctor: true }
      });
      res.json(patients);
    } catch (error) {
      console.error('Error fetching patients:', error);
      res.status(500).json({ message: 'Internal server error fetching patients' });
    }
  }
);

/**
 * @swagger
 * /admin/patients/{id}:
 *   get:
 *     summary: Get a Patient account by ID (Admin only)
 *     tags: [Admin - Patient Management]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/UserId'
 *     responses:
 *       '200':
 *         description: Patient details retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/PatientProfileResponse'
 *       '400':
 *         description: Invalid ID format
 *       '404':
 *         description: Patient not found
 *       '500':
 *         description: Internal Server Error
 */
router.get(
  '/patients/:id',
  authenticateJWT,
  allowRoles([UserRole.ADMIN, UserRole.SUPER_ADMIN]),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const patientId = req.params.id;
      if (!validateUUID(patientId)) {
        res.status(400).json({ message: 'Invalid ID format' });
        return;
      }
      const patient = await userRepository.findOne({
        where: { id: patientId, role: UserRole.PATIENT },
        select: [
          'id', 'email', 'role', 'firstName', 'lastName', 'phone', 'address',
          'dateOfBirth', 'gender', 'assignedDoctorId'
        ],
        relations: { assignedDoctor: true }
      });
      if (!patient) {
        res.status(404).json({ message: 'Patient not found' });
        return;
      }
      const { password, assignedDoctor, ...patientData } = patient;
      const responseData = {
        ...patientData,
        assignedDoctor: assignedDoctor
          ? {
              id: assignedDoctor.id,
              firstName: assignedDoctor.firstName,
              lastName: assignedDoctor.lastName,
              specialization: assignedDoctor.specialization
            }
          : null
      };
      res.json(responseData);
    } catch (error: any) {
      console.error('Error fetching patient by ID:', error);
      res.status(500).json({ message: 'Internal server error fetching patient' });
    }
  }
);

/**
 * @swagger
 * /admin/patients/{id}:
 *   put:
 *     summary: Update a Patient account (Admin only)
 *     tags: [Admin - Patient Management]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/UserId'
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
 *               firstName:
 *                 type: string
 *               lastName:
 *                 type: string
 *               phone:
 *                 type: string
 *               address:
 *                 type: string
 *               dateOfBirth:
 *                 type: string
 *                 format: date
 *               gender:
 *                 type: string
 *               assignedDoctorId:
 *                 type: string
 *                 format: uuid
 *                 description: New doctor ID if reassigning
 *     responses:
 *       '200':
 *         description: Patient updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/PatientProfileResponse'
 *       '400':
 *         description: Bad Request (e.g., invalid ID or fields)
 *       '401':
 *         description: Unauthorized
 *       '404':
 *         description: Patient not found
 *       '409':
 *         description: Conflict (Email already in use)
 *       '500':
 *         description: Internal Server Error
 */
router.put(
  '/patients/:id',
  authenticateJWT,
  allowRoles([UserRole.ADMIN, UserRole.SUPER_ADMIN]),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const patientId = req.params.id;
      if (!validateUUID(patientId)) {
        res.status(400).json({ message: 'Invalid ID format' });
        return;
      }
      const updateData = req.body;
      const validFields = [
        'email', 'password', 'firstName', 'lastName', 'phone', 'address',
        'dateOfBirth', 'gender', 'assignedDoctorId'
      ];
      const fieldsToUpdate = Object.keys(updateData).filter(key => validFields.includes(key) && updateData[key] !== undefined);

      if (fieldsToUpdate.length === 0) {
        res.status(400).json({ message: 'No valid update fields provided' });
        return;
      }

      const patient = await userRepository.findOneBy({ id: patientId, role: UserRole.PATIENT });
      if (!patient) {
        res.status(404).json({ message: 'Patient not found' });
        return;
      }

      let needsSave = false;
      if (updateData.email !== undefined) {
        const lowerCaseEmail = updateData.email.toLowerCase();
        if (lowerCaseEmail !== patient.email) {
          const existingUser = await userRepository.findOneBy({ email: lowerCaseEmail });
          if (existingUser && existingUser.id !== patientId) {
            res.status(409).json({ message: 'New email address already in use' });
            return;
          }
          patient.email = lowerCaseEmail;
          needsSave = true;
        }
      }
      if (updateData.password) {
        patient.password = await bcrypt.hash(updateData.password, 10);
        needsSave = true;
      }
      if (updateData.firstName !== undefined) { patient.firstName = updateData.firstName; needsSave = true; }
      if (updateData.lastName !== undefined) { patient.lastName = updateData.lastName; needsSave = true; }
      if (updateData.phone !== undefined) { patient.phone = updateData.phone; needsSave = true; }
      if (updateData.address !== undefined) { patient.address = updateData.address; needsSave = true; }
      if (updateData.dateOfBirth !== undefined) { patient.dateOfBirth = updateData.dateOfBirth; needsSave = true; }
      if (updateData.gender !== undefined) { patient.gender = updateData.gender; needsSave = true; }
      if (updateData.assignedDoctorId !== undefined) {
        if (updateData.assignedDoctorId === null) {
          if (patient.assignedDoctorId !== null) { patient.assignedDoctorId = null; needsSave = true; }
        } else {
          if (!validateUUID(updateData.assignedDoctorId)) {
            res.status(400).json({ message: 'Invalid assignedDoctorId format' });
            return;
          }
          if (updateData.assignedDoctorId !== patient.assignedDoctorId) {
            const newDoctor = await userRepository.findOneBy({ id: updateData.assignedDoctorId, role: UserRole.DOCTOR });
            if (!newDoctor) {
              res.status(404).json({ message: `New assigned doctor with ID ${updateData.assignedDoctorId} not found or is not a Doctor.` });
              return;
            }
            patient.assignedDoctorId = newDoctor.id;
            needsSave = true;
          }
        }
      }

      if (needsSave) {
        await userRepository.save(patient);
      }
      const updatedPatient = await userRepository.findOne({
        where: { id: patientId },
        select: [
          'id', 'email', 'role', 'firstName', 'lastName', 'phone', 'address',
          'dateOfBirth', 'gender', 'assignedDoctorId'
        ]
      });
      res.json(updatedPatient);
    } catch (error: any) {
      console.error('Error updating patient:', error);
      if (error instanceof QueryFailedError && error.driverError?.code === '23505') {
        res.status(409).json({ message: 'Email address already in use (DB constraint)' });
      } else {
        res.status(500).json({ message: 'Internal server error updating patient' });
      }
    }
  }
);

/**
 * @swagger
 * /admin/patients/{id}:
 *   delete:
 *     summary: Delete a Patient account (Admin only)
 *     tags: [Admin - Patient Management]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/UserId'
 *     responses:
 *       '204':
 *         description: Patient deleted successfully (No Content)
 *       '400':
 *         description: Invalid ID format
 *       '404':
 *         description: Patient not found
 *       '500':
 *         description: Internal Server Error
 */
router.delete(
  '/patients/:id',
  authenticateJWT,
  allowRoles([UserRole.ADMIN, UserRole.SUPER_ADMIN]),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const patientId = req.params.id;
      if (!validateUUID(patientId)) {
        res.status(400).json({ message: 'Invalid ID format' });
        return;
      }
      const patient = await userRepository.findOneBy({ id: patientId, role: UserRole.PATIENT });
      if (!patient) {
        res.status(404).json({ message: 'Patient not found' });
        return;
      }
      await userRepository.remove(patient);
      res.status(204).send();
    } catch (error: any) {
      console.error('Error deleting patient:', error);
      if (error instanceof QueryFailedError && error.driverError?.code === '23503') {
        res.status(409).json({ message: 'Cannot delete patient, possibly referenced elsewhere' });
      } else {
        res.status(500).json({ message: 'Internal server error deleting patient' });
      }
    }
  }
);

/**
 * @swagger
 * components:
 *   parameters:
 *     UserId:
 *       in: path
 *       name: id
 *       required: true
 *       schema:
 *         type: string
 *         format: uuid
 *       description: The UUID of the user (Doctor or Patient)
 *   schemas:
 *     DoctorProfileResponse:
 *       type: object
 *       properties:
 *         id:
 *           type: string
 *           format: uuid
 *         email:
 *           type: string
 *           format: email
 *         role:
 *           type: string
 *           enum: [DOCTOR]
 *         firstName:
 *           type: string
 *           nullable: true
 *         lastName:
 *           type: string
 *           nullable: true
 *         phone:
 *           type: string
 *           nullable: true
 *         address:
 *           type: string
 *           nullable: true
 *         specialization:
 *           type: string
 *           nullable: true
 *         qualifications:
 *           type: string
 *           nullable: true
 *         bio:
 *           type: string
 *           nullable: true
 *         yearsOfExperience:
 *           type: number
 *           nullable: true
 *         profilePhotoUrl:
 *           type: string
 *           format: url
 *           nullable: true
 *         createdAt:
 *           type: string
 *           format: date-time
 *         updatedAt:
 *           type: string
 *           format: date-time
 *     PatientProfileResponse:
 *       type: object
 *       properties:
 *         id:
 *           type: string
 *           format: uuid
 *         email:
 *           type: string
 *           format: email
 *         role:
 *           type: string
 *           enum: [PATIENT]
 *         firstName:
 *           type: string
 *           nullable: true
 *         lastName:
 *           type: string
 *           nullable: true
 *         phone:
 *           type: string
 *           nullable: true
 *         address:
 *           type: string
 *           nullable: true
 *         dateOfBirth:
 *           type: string
 *           format: date
 *           nullable: true
 *         gender:
 *           type: string
 *           nullable: true
 *         assignedDoctorId:
 *           type: string
 *           format: uuid
 *           nullable: true
 *           description: ID of the doctor assigned to the patient
 *         createdAt:
 *           type: string
 *           format: date-time
 *         updatedAt:
 *           type: string
 *           format: date-time
 */
export default router;

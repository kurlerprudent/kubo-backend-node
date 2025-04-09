// src/entities/User.ts

import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, OneToMany, JoinColumn, CreateDateColumn, UpdateDateColumn } from 'typeorm'; // Added Create/UpdateDateColumn
import 'reflect-metadata';

export enum UserRole {
  SUPER_ADMIN = 'SUPER_ADMIN',
  ADMIN = 'ADMIN',
  DOCTOR = 'DOCTOR',
  PATIENT = 'PATIENT'
}

@Entity('user') // Explicit table name often good practice
export class User {
  @PrimaryGeneratedColumn('uuid')
  id!: string; // Use definite assignment '!' for non-nullable primary keys

  @Column({ unique: true })
  email!: string; // Assumed always present

  @Column()
  password!: string; // Assumed always present

  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.PATIENT
  })
  role!: UserRole; // Assumed always present (has default)

  // Common Profile Fields
  @Column({ nullable: true })
  firstName?: string; // Optional fields are fine with '?'

  @Column({ nullable: true })
  lastName?: string; // Optional fields are fine with '?'

  @Column({ nullable: true })
  phone?: string; // Optional fields are fine with '?'

  @Column({ nullable: true })
  address?: string; // Optional fields are fine with '?'

  // Patient-specific Fields
  @Column({ type: 'date', nullable: true })
  dateOfBirth?: string; // Optional fields are fine with '?'

  @Column({ nullable: true })
  gender?: string; // Optional fields are fine with '?'

  // --- FIX IS HERE ---
  @Column({ type: 'uuid', nullable: true })
  assignedDoctorId: string | null = null; // Initialize with null

  // A many-to-one relation: many patients can be assigned to one doctor.
  @ManyToOne(() => User, user => user.patients, { nullable: true, onDelete: 'SET NULL' }) // Consider onDelete behavior
  @JoinColumn({ name: 'assignedDoctorId' })
  assignedDoctor?: User; // Keep relation optional

  // If the user is a doctor, they may have multiple patients.
  // Define the inverse side for clarity, TypeORM infers it but explicit is good
  @OneToMany(() => User, patient => patient.assignedDoctor)
  patients?: User[]; // Patients assigned TO this doctor

  // Doctor-specific Fields
  @Column({ nullable: true })
  specialization?: string;

  @Column({ nullable: true })
  qualifications?: string;

  @Column({ type: 'text', nullable: true })
  bio?: string;

  @Column({ type: 'int', nullable: true }) // Use 'int' for numbers if applicable
  yearsOfExperience?: number;

  @Column({ nullable: true })
  profilePhotoUrl?: string;

  // Admin-specific Fields
  @Column({ nullable: true })
  position?: string;

  @Column({ nullable: true })
  department?: string;

  // Timestamps (Optional but Recommended)
  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;

  // Note: You might add helper methods here if needed, e.g., for password hashing/checking,
  // but often that logic lives in services.
}


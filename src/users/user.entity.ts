import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, ManyToMany, JoinTable } from 'typeorm';
import { Role } from '../roles/role.entity';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column({ nullable: true })
  name: string;

  @Column()
  password_hash: string;

  @Column({ default: 'active' })
  status: string; // 'active' | 'inactive'

  @Column({ default: false })
  must_change_password: boolean;

  @Column({ default: false })
  mfa_enabled: boolean;

  @Column({ type: 'text', nullable: true })
  mfa_secret: string | null;

  @ManyToMany(() => Role, { eager: true })
  @JoinTable({ name: 'user_roles' })
  roles: Role[];

  @CreateDateColumn()
  created_at: Date;

  @UpdateDateColumn()
  updated_at: Date;
}

import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn } from 'typeorm';

@Entity('user_zone_assignments')
export class UserZoneAssignment {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  user_id: string;

  @Column()
  zone_id: string;

  @Column({ default: 'editor' })
  role: string; // 'editor' | 'admin'

  @CreateDateColumn()
  created_at: Date;
}

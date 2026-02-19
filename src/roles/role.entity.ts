import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity('roles')
export class Role {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  name: string; // 'admin', 'editor'

  @Column('simple-array', { nullable: true })
  permissions: string[]; // e.g. ['schedule:write', 'content:upload', 'device:manage']
}

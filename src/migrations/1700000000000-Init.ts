import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Real initial migration for auth_db.
 * Tables: roles, users, user_roles (junction), user_zone_assignments
 */
export class Init1700000000000 implements MigrationInterface {
  name = 'Init1700000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`,
    );

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "roles" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "name" character varying NOT NULL,
        "permissions" text,
        CONSTRAINT "PK_c1433d71a4838793a49dcad46ab" PRIMARY KEY ("id"),
        CONSTRAINT "UQ_648740db084f1136e9d8cec8c77" UNIQUE ("name")
      )
    `);

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "users" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "email" character varying NOT NULL,
        "password_hash" character varying NOT NULL,
        "mfa_enabled" boolean NOT NULL DEFAULT false,
        "mfa_secret" character varying,
        "created_at" TIMESTAMP NOT NULL DEFAULT now(),
        "updated_at" TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_a3ffb1c0c8416b9fc6f907b7433" PRIMARY KEY ("id"),
        CONSTRAINT "UQ_97672ac88f789774dd47f7c8be3" UNIQUE ("email")
      )
    `);

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "user_roles" (
        "usersId" uuid NOT NULL,
        "rolesId" uuid NOT NULL,
        CONSTRAINT "PK_user_roles" PRIMARY KEY ("usersId", "rolesId"),
        CONSTRAINT "FK_user_roles_users" FOREIGN KEY ("usersId")
          REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE,
        CONSTRAINT "FK_user_roles_roles" FOREIGN KEY ("rolesId")
          REFERENCES "roles"("id") ON DELETE CASCADE ON UPDATE CASCADE
      )
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_user_roles_usersId"
        ON "user_roles" ("usersId")
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_user_roles_rolesId"
        ON "user_roles" ("rolesId")
    `);

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "user_zone_assignments" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "user_id" character varying NOT NULL,
        "zone_id" character varying NOT NULL,
        "role" character varying NOT NULL DEFAULT 'editor',
        "created_at" TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_user_zone_assignments" PRIMARY KEY ("id")
      )
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS "user_zone_assignments"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "IDX_user_roles_rolesId"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "IDX_user_roles_usersId"`);
    await queryRunner.query(`DROP TABLE IF EXISTS "user_roles"`);
    await queryRunner.query(`DROP TABLE IF EXISTS "users"`);
    await queryRunner.query(`DROP TABLE IF EXISTS "roles"`);
  }
}

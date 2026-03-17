import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * IAM extensions: user fields (name, status, must_change_password),
 * system_settings table for init state tracking.
 */
export class IamExtensions1700000000001 implements MigrationInterface {
  name = 'IamExtensions1700000000001';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Add new columns to users table
    await queryRunner.query(`
      ALTER TABLE "users"
        ADD COLUMN IF NOT EXISTS "name" character varying,
        ADD COLUMN IF NOT EXISTS "status" character varying NOT NULL DEFAULT 'active',
        ADD COLUMN IF NOT EXISTS "must_change_password" boolean NOT NULL DEFAULT false
    `);

    // System settings table for init state
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "system_settings" (
        "key" character varying NOT NULL,
        "value" character varying NOT NULL,
        "created_at" TIMESTAMP NOT NULL DEFAULT now(),
        "updated_at" TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_system_settings" PRIMARY KEY ("key")
      )
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS "system_settings"`);
    await queryRunner.query(`
      ALTER TABLE "users"
        DROP COLUMN IF EXISTS "must_change_password",
        DROP COLUMN IF EXISTS "status",
        DROP COLUMN IF EXISTS "name"
    `);
  }
}

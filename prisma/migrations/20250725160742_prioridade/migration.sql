/*
  Warnings:

  - The values [MÉDIA] on the enum `Prioridade` will be removed. If these variants are still used in the database, this will fail.

*/
-- AlterEnum
BEGIN;
CREATE TYPE "Prioridade_new" AS ENUM ('BAIXA', 'MEDIA', 'ALTA');
ALTER TABLE "chamado_servico" ALTER COLUMN "prioridade" DROP DEFAULT;
ALTER TABLE "chamados" ALTER COLUMN "prioridade" DROP DEFAULT;
ALTER TABLE "chamados" ALTER COLUMN "prioridade" TYPE "Prioridade_new" USING ("prioridade"::text::"Prioridade_new");
ALTER TABLE "chamado_servico" ALTER COLUMN "prioridade" TYPE "Prioridade_new" USING ("prioridade"::text::"Prioridade_new");
ALTER TYPE "Prioridade" RENAME TO "Prioridade_old";
ALTER TYPE "Prioridade_new" RENAME TO "Prioridade";
DROP TYPE "Prioridade_old";
ALTER TABLE "chamado_servico" ALTER COLUMN "prioridade" SET DEFAULT 'BAIXA';
ALTER TABLE "chamados" ALTER COLUMN "prioridade" SET DEFAULT 'BAIXA';
COMMIT;

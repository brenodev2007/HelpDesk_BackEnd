-- CreateEnum
CREATE TYPE "CategoriaServico" AS ENUM ('SUPORTE', 'INSTALACAO', 'MANUTENCAO', 'CONSULTORIA');

-- AlterTable
ALTER TABLE "servicos" ADD COLUMN     "categoria" "CategoriaServico" NOT NULL DEFAULT 'SUPORTE';

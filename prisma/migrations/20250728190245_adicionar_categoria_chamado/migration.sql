/*
  Warnings:

  - You are about to drop the column `categoria` on the `servicos` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "chamados" ADD COLUMN     "categoria" "CategoriaServico" NOT NULL DEFAULT 'SUPORTE';

-- AlterTable
ALTER TABLE "servicos" DROP COLUMN "categoria";

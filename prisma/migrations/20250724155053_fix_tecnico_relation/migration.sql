-- AlterTable
ALTER TABLE "chamados" ADD COLUMN     "tecnico_id" TEXT;

-- AddForeignKey
ALTER TABLE "chamados" ADD CONSTRAINT "chamados_tecnico_id_fkey" FOREIGN KEY ("tecnico_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

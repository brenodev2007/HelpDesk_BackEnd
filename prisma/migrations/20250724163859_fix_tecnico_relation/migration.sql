-- AlterTable
ALTER TABLE "chamado_servico" ADD COLUMN     "user_id" TEXT;

-- AddForeignKey
ALTER TABLE "chamado_servico" ADD CONSTRAINT "chamado_servico_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

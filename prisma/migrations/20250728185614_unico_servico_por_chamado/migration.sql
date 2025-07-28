/*
  Warnings:

  - A unique constraint covering the columns `[servico_id]` on the table `chamado_servico` will be added. If there are existing duplicate values, this will fail.

*/
-- CreateIndex
CREATE UNIQUE INDEX "chamado_servico_servico_id_key" ON "chamado_servico"("servico_id");

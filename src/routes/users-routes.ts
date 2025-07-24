import { Router } from "express";
import { UserController } from "../controller/UserController";
import { ensureRole } from "@/middlewares/ensureRole";
import multer from "multer";
import { UserRole } from "@prisma/client";
import { ensureAuthenticated } from "@/middlewares/ensureAuthenticated.ts";
import { upload } from "@/middlewares/upload";

export const Userroutes = Router();
const userController = new UserController();

Userroutes.post("/register", userController.cadastro);

Userroutes.delete(
  "/remover",
  ensureRole([UserRole.ADMIN, UserRole.USER]),
  userController.removerConta.bind(userController)
);

Userroutes.post("/login", userController.login);

Userroutes.get(
  "/chamados",
  ensureAuthenticated,
  userController.listarChamadoCliente
);

Userroutes.get("/:id", ensureAuthenticated, userController.verPerfil);

Userroutes.patch(
  "/uploadPerfil",
  ensureRole(["USER", "TECNICO", "ADMIN"]),
  upload.single("file"),
  userController.uploadDePerfil
);

Userroutes.post(
  "/criar-chamado",
  ensureRole(["USER", "ADMIN"]),
  userController.criarChamado
);

//Rotas do ADMIN

Userroutes.post(
  "/criar-tecnico",
  ensureRole(["ADMIN"]),
  userController.criarTecnico
);

Userroutes.post(
  "/criar-servico",
  ensureRole(["ADMIN"]),
  userController.criarServico
);

Userroutes.get(
  "/listar-clientes",
  ensureRole(["ADMIN"]),
  userController.listarClientes
);

Userroutes.get(
  "/listar-servicos-admin",
  ensureRole(["ADMIN"]),
  userController.listarServicosAdmin
);

//Rotas TECNICO
Userroutes.patch(
  "/pegar-chamado",
  ensureRole(["TECNICO", "ADMIN"]),
  userController.pegarChamado
);

Userroutes.post(
  "/adicionar-servicos",
  ensureRole(["TECNICO", "ADMIN"]),
  userController.adicionarServicosAoChamado
);

Userroutes.patch(
  "/editar-status",
  ensureRole(["TECNICO", "ADMIN"]),
  userController.editarStatusServico
);

Userroutes.get(
  "/meus-chamados-tecnico",
  ensureRole(["TECNICO", "ADMIN"]),
  userController.listarChamadosDoTecnico
);

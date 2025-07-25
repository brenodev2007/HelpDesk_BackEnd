import { Router } from "express";
import { UserController } from "../controller/UserController";
import { ensureRole } from "@/middlewares/ensureRole";
import multer from "multer";
import { UserRole } from "@prisma/client";
import { ensureAuthenticated } from "@/middlewares/ensureAuthenticated.ts";

export const Userroutes = Router();
const userController = new UserController();

// Autenticação
Userroutes.post("/register", userController.cadastro);
Userroutes.post("/login", userController.login);
Userroutes.delete(
  "/remover",
  ensureAuthenticated,
  ensureRole([UserRole.ADMIN, UserRole.USER]),
  userController.removerConta
);

// Cliente
Userroutes.get(
  "/chamados",
  ensureAuthenticated,
  ensureRole(["USER"]),
  userController.listarChamadoCliente
);
Userroutes.post(
  "/criar-chamado",
  ensureAuthenticated,
  ensureRole(["USER", "ADMIN"]),
  userController.criarChamado
);
Userroutes.put(
  "/atualizar-email",
  ensureAuthenticated,
  userController.atualizarEmail
);

// Admin
Userroutes.post(
  "/criar-tecnico",
  ensureAuthenticated,
  ensureRole(["ADMIN"]),
  userController.criarTecnico
);
Userroutes.get(
  "/listar-todos-chamados",
  ensureAuthenticated,
  ensureRole(["ADMIN"]),
  userController.listarTodosChamados
);
Userroutes.get(
  "/listar-clientes",
  ensureAuthenticated,
  ensureRole(["ADMIN"]),
  userController.listarClientes
);
Userroutes.get(
  "/listar-tecnicos",
  ensureAuthenticated,
  ensureRole(["ADMIN"]),
  userController.listarTecnicos
);
Userroutes.post(
  "/criar-servico",
  ensureAuthenticated,
  ensureRole(["ADMIN"]),
  userController.criarServico
);
Userroutes.patch(
  "/atribuir-chamado-tecnico",
  ensureAuthenticated,
  ensureRole(["ADMIN"]),
  userController.atribuirChamadoTecnico
);

// Técnico/Admin
Userroutes.get(
  "/listar-servicos",
  ensureAuthenticated,
  ensureRole(["ADMIN", "TECNICO"]),
  userController.listarServicos
);
Userroutes.get(
  "/meus-chamados-tecnico",
  ensureAuthenticated,
  ensureRole(["TECNICO", "ADMIN"]),
  userController.listarChamadosDoTecnico
);
Userroutes.patch(
  "/pegar-chamado",
  ensureAuthenticated,
  ensureRole(["TECNICO", "ADMIN"]),
  userController.pegarChamado
);
Userroutes.post(
  "/adicionar-servicos",
  ensureAuthenticated,
  ensureRole(["TECNICO", "ADMIN"]),
  userController.adicionarServicosAoChamado
);
Userroutes.patch(
  "/editar-status",
  ensureAuthenticated,
  ensureRole(["TECNICO", "ADMIN"]),
  userController.editarStatusServico
);
Userroutes.patch(
  "/atualizar-chamadoServico",
  ensureAuthenticated,
  ensureRole(["TECNICO", "ADMIN"]),
  userController.atualizarStatusChamadoServico
);

// Perfil
Userroutes.get("/:id", ensureAuthenticated, userController.verPerfil);

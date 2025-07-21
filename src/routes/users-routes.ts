import { Router } from "express";
import { UserController } from "../controller/UserController";
import { ensureRole } from "@/middlewares/ensureRole";
import multer from "multer";
import { UserRole } from "@prisma/client";

const upload = multer({ dest: "./tmp/uploads" });

export const Userroutes = Router();
const userController = new UserController();

Userroutes.post("/cadastro", userController.cadastro);

Userroutes.delete(
  "/remover",
  ensureRole([UserRole.ADMIN, UserRole.USER]),
  userController.removerConta.bind(userController)
);

Userroutes.post("/login", userController.login);

Userroutes.patch(
  "/uploadPerfil",
  ensureRole(["USER", "TECNICO", "ADMIN"]),
  upload.single("file"),
  userController.uploadDePerfil
);

Userroutes.get(
  "/chamados",
  ensureRole(["USER", "ADMIN"]),
  userController.listarChamadoCliente
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

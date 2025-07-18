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

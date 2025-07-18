import { Router } from "express";
import { UserController } from "../controller/UserController";
import { ensureRole } from "@/middlewares/ensureRole";
import multer from "multer";

const upload = multer({ dest: "./tmp/uploads" });

export const Userroutes = Router();
const userController = new UserController();

Userroutes.post("/cadastro", userController.cadastro);

Userroutes.delete(
  "/remover",
  ensureRole(["USER"]),
  userController.removerConta.bind(userController)
);

Userroutes.post("/login", userController.login);

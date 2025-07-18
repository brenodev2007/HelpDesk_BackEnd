import { Router } from "express";
import { UserController } from "@/controller/UserController";
import { ensureRole } from "@/middlewares/ensureRole";
import multer from "multer";

const upload = multer({ dest: "./tmp/uploads" });

const router = Router();
const userController = new UserController();

router.post("/cliente/cadastro", userController.cadastro);

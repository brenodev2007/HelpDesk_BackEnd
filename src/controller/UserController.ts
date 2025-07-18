import { Request, Response } from "express";
import { prisma } from "@/database/prisma";
import bcrypt from "bcrypt";
import jwt, { SignOptions } from "jsonwebtoken";

import { authConfig } from "@/config/auth";
import { z } from "zod";
import { UserRole } from "@/generated/prisma";
import { AppError } from "@/utils/AppError";

export class UserController {
  // ========== CLIENTE ==========

  cadastro = async (req: Request, res: Response) => {
    const cadastroSchema = z.object({
      nome: z.string().min(3).max(50),
      email: z.string().email(),
      password: z.string().min(6),
      role: z
        .enum([UserRole.ADMIN, UserRole.USER, UserRole.TECNICO])
        .default(UserRole.USER),
    });

    try {
      const data = cadastroSchema.parse(req.body);

      const existingUser = await prisma.user.findUnique({
        where: { email: data.email },
      });

      if (existingUser) {
        throw new AppError("Email já cadastrado", 409);
      }

      const hashedPassword = await bcrypt.hash(data.password, 10);

      const user = await prisma.user.create({
        data: {
          email: data.email,
          password: hashedPassword,
          role: UserRole.USER,
        },
      });

      return res
        .status(201)
        .json({ message: "Usuário criado", userId: user.id });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "ops!" });
      }

      if (error instanceof AppError) {
        return res.status(error.statusCode).json({ error: error.message });
      }

      return res.status(500).json({ error: "Erro interno" });
    }
  };

  removerConta = async (req: Request, res: Response) => {
    const Bodyschema = z.object({
      id: z.string().cuid(),
    });

    try {
      const { id } = Bodyschema.parse(req.body);
      const requester = req.user; // dados do token

      if (!requester) {
        return res.status(401).json({ error: "Token inválido ou ausente" });
      }

      // Se não for admin, só pode deletar a própria conta
      if (requester.role !== UserRole.ADMIN && requester.id !== id) {
        return res
          .status(403)
          .json({ error: "Você só pode deletar sua própria conta" });
      }

      await prisma.user.delete({ where: { id } });

      return res.status(200).json({ message: "Conta removida com sucesso" });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Ops!" });
      }
      console.error(error);
      return res.status(500).json({ error: "Erro ao remover conta" });
    }
  };

  login = async (req: Request, res: Response) => {
    const loginSchema = z.object({
      email: z.string().email(),
      password: z.string().min(6),
    });

    try {
      const { email, password } = loginSchema.parse(req.body);
      const user = await prisma.user.findUnique({
        where: { email },
      });

      if (!user) {
        return res.status(401).json({ error: "Email ou senha inválidos" });
      }
      //vai comparar a senhas
      const passwordMatch = await bcrypt.compare(password, user.password);

      if (!passwordMatch) {
        return res.status(401).json({ error: "Email ou senha inválidos" });
      }

      const token = jwt.sign(
        {
          id: user.id,
          email: user.email,
          role: user.role,
        },
        authConfig.jwt.secret
      );
      return res.json({ token });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Ops!" });
      }
      console.error(error);
      return res.status(500).json({ error: "Erro interno" });
    }
  };

  uploadDePerfil = async (req: Request, res: Response) => {
    const userId = req.user.id;

    const Bodyschema = z.object({
      originalname: z.string().min(1, "Nome do arquivo ausente"),
      mimetype: z.union([
        z.literal("image/png"),
        z.literal("image/jpeg"),
        z.literal("image/jpg"),
      ]),
      filename: z.string().min(1),
    });

    try {
      if (!req.file) {
        return res.status(400).json({ error: "Arquivo de perfil não enviado" });
      }

      const fileData = Bodyschema.parse(req.file);

      const updatedUser = await prisma.user.update({
        where: { id: userId },
        data: {
          profileImage: fileData.filename,
        },
      });

      return res.status(200).json({
        message: "Imagem de perfil atualizada com sucesso",
        user: updatedUser,
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Ops!" });
      }

      console.error(error);
      return res.status(500).json({ error: "Erro ao atualizar perfil" });
    }
  };
}

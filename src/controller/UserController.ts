import { Request, Response } from "express";
import { prisma } from "@/database/prisma";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
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
        throw new AppError("Erro interno", 400);
      }
    }
  };
}

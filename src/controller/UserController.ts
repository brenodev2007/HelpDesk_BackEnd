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

  listarChamadoCliente = async (req: Request, res: Response) => {
    const userSchema = z.object({
      id: z.string().uuid(),
    });

    try {
      const { id: userId } = userSchema.parse(req.user);

      const chamados = await prisma.chamado.findMany({
        where: { userId }, // certifique-se que o campo no banco é userId mesmo
        include: {
          chamado_servico: {
            include: {
              servico: true,
            },
          },
        },
      });

      return res.json(chamados);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "ID do usuário inválido" });
      }

      console.error(error);
      return res.status(500).json({ error: "Erro ao listar chamados" });
    }
  };

  // ========== ADMIN ==========
  criarTecnico = async (req: Request, res: Response) => {
    const tecnicoSchema = z.object({
      email: z.string().email(),
      password: z.string().min(6),
      cargo: z.string().min(2).optional(),
    });

    try {
      const data = tecnicoSchema.parse(req.body);

      const existingUser = await prisma.user.findUnique({
        where: { email: data.email },
      });

      if (existingUser) {
        return res.status(409).json({ error: "Email já cadastrado" });
      }

      const hashedPassword = await bcrypt.hash(data.password, 10);

      const tecnico = await prisma.user.create({
        data: {
          email: data.email,
          password: hashedPassword,
          role: "TECNICO",
          cargo: data.cargo,
        },
      });

      return res
        .status(201)
        .json({ message: "Técnico criado", tecnicoId: tecnico.id });
    } catch (error) {
      if (error instanceof z.ZodError)
        return res.status(400).json({ message: "Dados inválidos" });

      console.error(error);
      return res.status(500).json({ error: "Erro interno" });
    }
  };

  criarServico = async (req: Request, res: Response) => {
    const servicoSchema = z.object({
      titulo: z.string().min(2),
      descricao: z.string().min(5),
      tecnicoId: z.string().cuid(), // ou uuid() se for UUID
    });

    try {
      const data = servicoSchema.parse(req.body);

      const tecnico = await prisma.user.findUnique({
        where: { id: data.tecnicoId },
      });

      if (!tecnico || tecnico.role !== "TECNICO") {
        return res.status(404).json({ error: "Técnico não encontrado" });
      }

      const servico = await prisma.servico.create({
        data: {
          titulo: data.titulo,
          descricao: data.descricao,
          tecnicoId: data.tecnicoId,
        },
      });

      return res.status(201).json(servico);
    } catch (err) {
      if (err instanceof z.ZodError)
        return res.status(400).json({ message: "Dados inválidos" });

      return res.status(500).json({ error: "Erro ao criar serviço" });
    }
  };

  listarClientes = async (req: Request, res: Response) => {
    const authSchema = z.object({
      id: z.string().cuid(),
      role: z.enum(["ADMIN", "USER", "TECNICO"]),
    });

    try {
      const userData = authSchema.parse(req.user); // valida o token decodificado

      if (userData.role !== "ADMIN") {
        return res.status(403).json({ error: "Acesso negado" });
      }

      const clientes = await prisma.user.findMany({
        where: { role: "USER" },
        select: { id: true, email: true, cargo: true },
      });

      return res.status(200).json(clientes);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res
          .status(400)
          .json({ error: "Token inválido ou mal formatado" });
      }
      return res.status(500).json({ error: "Erro ao listar clientes" });
    }
  };
}

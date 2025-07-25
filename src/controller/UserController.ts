import { Request, Response } from "express";
import { prisma } from "@/database/prisma";
import bcrypt from "bcrypt";
import jwt, { SignOptions } from "jsonwebtoken";
import { parseTokenUser } from "@/utils/validateUserFromToken";
import { authConfig } from "@/config/auth";
import { z } from "zod";
import { UserRole } from "@/generated/prisma";
import { AppError } from "@/utils/AppError";
import { ZodError } from "zod";

export class UserController {
  // ========== CLIENTE ==========

  cadastro = async (req: Request, res: Response) => {
    const cadastroSchema = z.object({
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
        return res.status(400).json({ error: error.message });
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

      const requester = parseTokenUser(req.user);

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
          email: user.email,
          role: user.role,
        },
        authConfig.jwt.secret,
        {
          subject: user.id, // ✅ ESSENCIAL
          expiresIn: "1d", // opcional
        }
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

  //Lógica JWT

  verPerfil = async (req: Request, res: Response) => {
    try {
      const requester = req.user;

      if (!requester) {
        return res.status(401).json({ error: "Usuário não autenticado" });
      }

      // Busca o próprio perfil do usuário autenticado
      const user = await prisma.user.findUnique({
        where: { id: requester.id },
        select: { id: true, email: true, role: true },
      });

      if (!user) {
        return res.status(404).json({ error: "Usuário não encontrado" });
      }

      return res.json(user);
    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: "Erro interno do servidor" });
    }
  };

  uploadDePerfil = async (req: Request, res: Response) => {
    try {
      console.log("Arquivo recebido:", req.file);
      if (!req.file) {
        return res.status(400).json({ error: "Arquivo de perfil não enviado" });
      }

      const Bodyschema = z
        .object({
          originalname: z.string().min(1, "Nome do arquivo ausente"),
          mimetype: z.union([z.literal("image/png"), z.literal("image/jpeg")]),
          filename: z.string().min(1),
        })
        .passthrough();

      const fileData = Bodyschema.parse(req.file);

      const userId = req.user?.id;
      if (!userId) {
        return res
          .status(400)
          .json({ error: "Usuário não autenticado corretamente" });
      }

      const fileNameToSave = fileData.filename;

      const updatedUser = await prisma.user.update({
        where: { id: userId },
        data: { profileImage: fileNameToSave },
      });

      return res.status(200).json({
        message: "Imagem de perfil atualizada com sucesso",
        user: updatedUser,
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        console.error("Erro de validação:", error.issues);
        return res.status(400).json({
          message: "Erro de validação dos dados do arquivo",
          issues: error.issues,
        });
      }

      console.error("Erro inesperado:", error);
      return res.status(500).json({ error: "Erro ao atualizar perfil" });
    }
  };

  criarChamado = async (req: Request, res: Response) => {
    console.log("req.user =", req.user);
    console.log("Body recebido:", req.body);

    const chamadoSchema = z.object({
      descricao: z
        .string()
        .min(10, "A descrição deve ter no mínimo 10 caracteres"),
      prioridade: z.enum(["BAIXA", "MÉDIA", "ALTA"]),
    });

    try {
      // Confirma que o middleware de autenticação populou o usuário
      if (!req.user) {
        return res.status(401).json({ error: "Usuário não autenticado" });
      }

      // Validação do usuário autenticado
      const userData = z
        .object({
          id: z.string(), // <- agora aceita qualquer string, não só cuid
          role: z.enum(["USER", "ADMIN", "TECNICO"]),
        })
        .parse(req.user);

      // Apenas usuários com perfil USER ou ADMIN podem criar chamados
      if (!["USER", "ADMIN"].includes(userData.role)) {
        return res
          .status(403)
          .json({ error: "Somente clientes podem criar chamados" });
      }

      // Validação do corpo da requisição
      const data = chamadoSchema.parse(req.body);

      // Criação do chamado no banco
      const chamado = await prisma.chamado.create({
        data: {
          descricao: data.descricao,
          prioridade: data.prioridade,
          userId: userData.id,
        },
      });

      return res.status(201).json({ message: "Chamado criado", chamado });
    } catch (error) {
      if (error instanceof z.ZodError) {
        // Retorna os erros detalhados do Zod para facilitar debug
        return res.status(400).json({
          error: "Dados inválidos",
        });
      }

      console.error("Erro ao criar chamado:", error);
      return res.status(500).json({ error: "Erro ao criar chamado" });
    }
  };

  listarChamadoCliente = async (req: Request, res: Response) => {
    try {
      const userId = req.user?.id;
      console.log("listando chamados para userId:", userId);

      if (!userId) {
        return res.status(400).json({ message: "ID do usuário ausente" });
      }

      // Consulta simplificada para testes (sem include)
      const chamados = await prisma.chamado.findMany({
        where: { userId },
        orderBy: { createdAt: "desc" },
      });

      console.log("Chamados encontrados:", chamados.length);

      return res.json(chamados);
    } catch (error) {
      console.error("Erro ao listar chamados:", error);
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

      const userData = parseTokenUser(req.user);

      if (userData.role !== UserRole.ADMIN) {
        return res
          .status(403)
          .json({ error: "Somente admins podem executar esta ação" });
      }

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

  listarServicos = async (req: Request, res: Response) => {
    try {
      // req.user já vem do middleware, não precisa buscar no banco nem parsear
      const userData = req.user as { id: string; role: string; email: string };

      if (userData.role !== "ADMIN" && userData.role !== "TECNICO") {
        return res.status(403).json({ error: "Acesso negado" });
      }

      const servicos = await prisma.servico.findMany({
        include: {
          tecnico: {
            select: { id: true, email: true, cargo: true },
          },
        },
      });

      return res.json(servicos);
    } catch (error) {
      console.error("Erro ao listar serviços:", error);
      return res.status(500).json({ error: "Erro ao listar serviços" });
    }
  };

  atribuirChamadoTecnico = async (req: Request, res: Response) => {
    const authSchema = z.object({
      id: z.string().cuid(),
      role: z.enum(["ADMIN", "USER", "TECNICO"]),
    });

    const bodySchema = z.object({
      chamadoId: z.string(),
      tecnicoId: z.string(),
    });

    try {
      const userData = authSchema.parse(req.user);

      if (userData.role !== "ADMIN") {
        return res.status(403).json({ error: "Acesso negado" });
      }

      const { chamadoId, tecnicoId } = bodySchema.parse(req.body);

      // Verifica se técnico existe e é técnico
      const tecnico = await prisma.user.findUnique({
        where: { id: tecnicoId },
      });

      if (!tecnico || tecnico.role !== "TECNICO") {
        return res.status(400).json({ error: "Técnico inválido" });
      }

      // Atualiza chamado atribuindo técnico (sem status)
      const chamadoAtualizado = await prisma.chamado.update({
        where: { id: chamadoId },
        data: {
          tecnicoId,
        },
      });

      return res.status(200).json({
        message: "Chamado atribuído com sucesso",
        chamado: chamadoAtualizado,
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: "Dados inválidos" });
      }
      console.error(error);
      return res.status(500).json({ error: "Erro ao atribuir chamado" });
    }
  };

  atualizarStatusChamadoServico = async (req: Request, res: Response) => {
    const authSchema = z.object({
      id: z.string(),
      role: z.enum(["ADMIN", "USER", "TECNICO"]),
    });

    const bodySchema = z.object({
      chamadoServicoId: z.string(),
      status: z.enum(["PENDING", "IN_PROGRESS", "DONE"]),
    });

    try {
      // Valida usuário autenticado
      const userData = authSchema.parse(req.user);

      // Apenas ADMIN e TECNICO podem atualizar status
      if (userData.role !== "ADMIN" && userData.role !== "TECNICO") {
        return res.status(403).json({ error: "Acesso negado" });
      }

      // Valida corpo da requisição
      const { chamadoServicoId, status } = bodySchema.parse(req.body);

      // Atualiza o status do ChamadoServico
      const chamadoServicoAtualizado = await prisma.chamadoServico.update({
        where: { id: chamadoServicoId },
        data: { status },
      });

      return res.status(200).json({
        message: "Status do serviço atualizado com sucesso",
        chamadoServico: chamadoServicoAtualizado,
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: "Dados inválidos" });
      }
      console.error(error);
      return res.status(500).json({ error: "Erro ao atualizar status" });
    }
  };

  listarTecnicos = async (req: Request, res: Response) => {
    try {
      const tecnicos = await prisma.user.findMany({
        where: { role: "TECNICO" },
        select: { id: true, email: true },
      });

      return res.status(200).json(tecnicos);
    } catch (error) {
      return res.status(500).json({ error: "Erro ao listar técnicos" });
    }
  };
  // ========== TÉCNICO ==========
  pegarChamado = async (req: Request, res: Response) => {
    const schema = z.object({
      chamadoId: z.string(),
    });

    try {
      const { chamadoId } = schema.parse(req.body);

      const userData = z
        .object({
          id: z.string(),
          role: z.enum(["TECNICO", "ADMIN", "USER"]),
        })
        .parse(req.user);

      if (userData.role !== "TECNICO" && userData.role !== "ADMIN") {
        return res
          .status(403)
          .json({ error: "Somente técnicos podem pegar chamados" });
      }

      const chamado = await prisma.chamado.update({
        where: { id: chamadoId },
        data: { userId: userData.id },
      });

      return res.json({ message: "Chamado atribuído ao técnico", chamado });
    } catch (error) {
      if (error instanceof z.ZodError)
        return res.status(400).json({ error: "Dados inválidos" });
      return res.status(500).json({ error: "Erro ao atribuir chamado" });
    }
  };

  adicionarServicosAoChamado = async (req: Request, res: Response) => {
    const schema = z.object({
      chamadoId: z.string().cuid(),
      servicosIds: z.array(z.string().cuid()).min(1),
    });

    try {
      const { chamadoId, servicosIds } = schema.parse(req.body);

      const userData = z
        .object({
          id: z.string().cuid(),
          role: z.enum(["TECNICO", "ADMIN", "USER"]),
        })
        .parse(req.user);

      if (userData.role !== "TECNICO" && userData.role !== "ADMIN") {
        return res
          .status(403)
          .json({ error: "Somente técnicos podem adicionar serviços" });
      }

      // Verifica se o chamado pertence ao técnico
      const chamado = await prisma.chamado.findUnique({
        where: { id: chamadoId },
      });

      const servicosDoTecnico = await prisma.servico.findMany({
        where: {
          id: { in: servicosIds },
          tecnicoId: userData.id,
        },
      });

      if (servicosDoTecnico.length !== servicosIds.length) {
        return res.status(403).json({
          error: "Você só pode adicionar serviços que você mesmo criou",
        });
      }

      if (!chamado || chamado.userId !== userData.id) {
        return res
          .status(403)
          .json({ error: "Você não pode modificar este chamado" });
      }

      const criado = await prisma.chamadoServico.createMany({
        data: servicosIds.map((servicoId) => ({
          chamadoId,
          servicoId,
          status: "PENDING",
          prioridade: "MÉDIA",
        })),
      });

      return res.json({
        message: "Serviços adicionados ao chamado",
        count: criado.count,
      });
    } catch (err) {
      if (err instanceof z.ZodError)
        return res.status(400).json({ error: "Dados inválidos" });
      return res.status(500).json({ error: "Erro ao adicionar serviços" });
    }
  };
  editarStatusServico = async (req: Request, res: Response) => {
    console.log("💡 Entrou no editarStatusServico");
    // Permitimos que o status venha em minúsculo e normalizamos
    const schemaBody = z.object({
      chamadoServicoId: z.string().min(5, "ID do chamado inválido"),
      novoStatus: z.string().min(3), // Validaremos manualmente depois
    });

    const schemaUser = z.object({
      id: z.string(),
      role: z.enum(["TECNICO", "ADMIN", "USER"]),
    });

    const statusValidos = ["PENDING", "IN_PROGRESS", "DONE"];

    try {
      console.log("Body recebido:", req.body);
      console.log("Usuário recebido:", req.user);
      const { chamadoServicoId, novoStatus } = schemaBody.parse(req.body);
      console.log("✅ Parse body funcionou:", chamadoServicoId, novoStatus);
      const userData = schemaUser.parse(req.user);
      console.log("✅ Parse user funcionou:", userData);

      const statusFormatado = novoStatus.toUpperCase();

      if (!statusValidos.includes(statusFormatado)) {
        return res.status(400).json({
          error: `Status inválido. Use: ${statusValidos.join(", ")}`,
        });
      }

      // Busca o chamado_servico com o técnico responsável
      const chamadoServico = await prisma.chamadoServico.findUnique({
        where: { id: chamadoServicoId },
        include: {
          servico: {
            select: { tecnicoId: true },
          },
        },
      });

      if (!chamadoServico) {
        return res
          .status(404)
          .json({ error: "Chamado/Serviço não encontrado" });
      }
      console.log("req.body recebido:", req.body);

      // Atualiza o status
      const atualizado = await prisma.chamadoServico.update({
        where: { id: chamadoServicoId },
        data: { status: statusFormatado as any },
      });

      return res.status(200).json({
        message: "Status atualizado com sucesso",
        atualizado,
      });
    } catch (err: any) {
      console.error("⚠️ ERRO CAPTURADO COMPLETO:");
      console.dir(err, { depth: null });

      return res.status(500).json({
        error: "Erro inesperado",
        detalhes: JSON.stringify(err, null, 2),
      });
    }
  };

  listarChamadosDoTecnico = async (req: Request, res: Response) => {
    const userId = req.user.id;

    // Ajuste para aceitar string genérica (não necessariamente cuid)
    const schema = z.object({
      id: z.string(),
    });

    try {
      schema.parse({ id: userId });

      console.log(`listando chamados para tecnicoId: ${userId}`);

      const chamados = await prisma.chamadoServico.findMany({
        where: {
          chamado: {
            tecnicoId: userId,
          },
        },
        include: {
          chamado: {
            include: {
              user: true,
            },
          },
          servico: true,
        },
      });

      console.log(`Chamados encontrados: ${chamados.length}`);

      return res.json({ chamados });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "ID do técnico inválido" });
      }
      console.error(error);
      return res
        .status(500)
        .json({ error: "Erro ao buscar chamados do técnico" });
    }
  };
}

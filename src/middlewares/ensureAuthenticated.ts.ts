import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { authConfig } from "../config/auth";

interface TokenPayload {
  sub: string;
  role: "USER" | "ADMIN" | "TECNICO";
  email: string;
  iat: number;
  exp: number;
}

export function ensureAuthenticated(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: "Token não fornecido" });
  }

  // Espera formato "Bearer token"
  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return res.status(401).json({ error: "Formato do token inválido" });
  }

  const token = parts[1];

  try {
    const decoded = jwt.verify(token, authConfig.jwt.secret) as any;

    console.log("Authorization header:", req.headers.authorization);

    req.user = {
      id: decoded.sub || decoded.id, // id vindo do sub
      role: decoded.role,
      email: decoded.email,
    };

    console.log("Middleware ensureAuthenticated - user:", req.user);

    next();
  } catch (error) {
    return res.status(401).json({ error: "Token inválido ou expirado" });
  }
}

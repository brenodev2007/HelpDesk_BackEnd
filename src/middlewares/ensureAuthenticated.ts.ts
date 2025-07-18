import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { authConfig } from "../config/auth";

interface TokenPayload {
  sub: string;
  role: string;
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

  const [, token] = authHeader.split(" ");

  try {
    const decoded = jwt.verify(token, authConfig.jwt.secret) as TokenPayload;

    req.user = {
      id: decoded.sub,
      role: decoded.role,
      email: decoded.email,
    };

    return next();
  } catch {
    return res.status(401).json({ error: "Token inválido ou expirado" });
  }
}

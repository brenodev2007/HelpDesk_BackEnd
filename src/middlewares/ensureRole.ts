import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { authConfig } from "@/config/auth";

interface TokenPayload {
  sub: string;
  email: string;
  role: "USER" | "ADMIN" | "TECNICO";
  iat: number;
  exp: number;
}

export function ensureRole(roles: TokenPayload["role"][]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Token missing" });

    const [, token] = authHeader.split(" ");

    try {
      const decoded = jwt.verify(token, authConfig.jwt.secret) as TokenPayload;

      if (!roles.includes(decoded.role)) {
        return res.status(403).json({ error: "Access denied" });
      }

      // Preenche req.user corretamente com o ID vindo de sub
      req.user = {
        id: decoded.sub,
        email: decoded.email,
        role: decoded.role,
      };

      return next();
    } catch {
      return res.status(401).json({ error: "Invalid token" });
    }
  };
}

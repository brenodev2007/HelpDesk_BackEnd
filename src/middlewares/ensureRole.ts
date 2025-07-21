import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { authConfig } from "@/config/auth";

interface AuthPayload {
  id: string;
  email: string;
  role: string;
}

export function ensureRole(roles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Token missing" });

    const [, token] = authHeader.split(" ");

    try {
      const decoded = jwt.verify(token, authConfig.jwt.secret) as AuthPayload;

      if (!roles.includes(decoded.role)) {
        return res.status(403).json({ error: "Access denied" });
      }

      req.user = decoded;
      return next();
    } catch {
      return res.status(401).json({ error: "Invalid token" });
    }
  };
}

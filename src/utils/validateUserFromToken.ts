// src/utils/validateUserFromToken.ts
import { z } from "zod";
import { UserRole } from "@prisma/client";

export const tokenUserSchema = z.object({
  id: z.string().cuid(),
  role: z.nativeEnum(UserRole),
});

export function parseTokenUser(data: unknown) {
  return tokenUserSchema.parse(data);
}

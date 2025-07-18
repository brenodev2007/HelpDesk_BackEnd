export const authConfig = {
  jwt: {
    secret: process.env.JWT_SECRET || "chave-secreta-dev",
    expiresIn: "1d",
  },
};

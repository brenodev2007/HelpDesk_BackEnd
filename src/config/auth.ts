interface AuthConfig {
  jwt: {
    secret: string;
    expiresIn: string | number;
  };
}

export const authConfig = {
  jwt: {
    secret: process.env.JWT_SECRET || "chave-secreta-dev",
    expiresIn: "1d",
  },
};

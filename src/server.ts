import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { routes } from "./routes";
import path from "path";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());
app.use(routes);

// Servir arquivos estáticos (imagens de perfil)
app.use("/uploads", express.static(path.resolve(__dirname, "..", "uploads")));
const PORT = process.env.PORT || 3333;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));

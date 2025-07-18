import { Router } from "express";

import { Userroutes } from "./users-routes";

export const routes = Router();

routes.use("/clientes", Userroutes);

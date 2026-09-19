import { NextFunction, Request, Response } from "express";
import { HttpStatus } from "../../core/types/http-statuses";
import { jwtService, usersRepository } from "../../core/composition/composition-root";


export const bearerAuthGuardMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const auth = req.headers.authorization;
  if (!auth) {
    return res.sendStatus(HttpStatus.Unauthorized);
  }
  const [authType, token] = auth.split(" ");

  if (authType !== "Bearer" || !token) return res.sendStatus(HttpStatus.Unauthorized);

  const payload = await jwtService.verifyAccessToken(token);
  if (!payload) {
    return res.sendStatus(HttpStatus.Unauthorized);
  }

  const user = await usersRepository.findUserById(payload.userId);
  if (!user) {
    return res.sendStatus(HttpStatus.Unauthorized);
  }

  req.user = {
    id: user.id,
    login: user.login,
    email: user.email,
  };
  next();
  return;
};

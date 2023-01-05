import express from "express";
import users from "./database";
import { hash } from "bcryptjs";
import { v4 as uuidv4 } from "uuid";
import jwt from "jsonwebtoken";
import { compare } from "bcryptjs";

const app = express();

app.use(express.json());

const port = 3000;

// SERVICES --------------------------------------------------------------------------------------------

const createUserService = async ({ name, email, password, isAdm }) => {
  const hashedPassword = await hash(password, 10);
  const newUser = {
    uuid: uuidv4(),
    createdOn: new Date(),
    updatedOn: new Date(),
    name,
    email,
    password: hashedPassword,
    isAdm,
  };

  const { password: removePass, ...user } = newUser;

  users.push(newUser);

  return [201, user];
};

const userLoginService = async (email, password) => {
  const user = users.find((el) => el.email === email);

  if (!user) {
    return [401, { message: "Email ou senha inválidos" }];
  }

  const passwordMatch = await compare(password, user.password);

  if (!passwordMatch) {
    return [401, { message: "Email ou senha inválidos" }];
  }

  const token = jwt.sign({ email }, "SECRET_KEY", {
    expiresIn: "24h",
    subject: user.uuid,
  });

  return [200, { token }];
};

const userProfileService = (authToken) => {
  const token = authToken.split(" ")[1];

  return jwt.verify(token, "SECRET_KEY", (error, decoded) => {
    if (error) {
      return res.send(error.message);
    }

    const user = users.find((user) => user.email === decoded.email);

    const { password: removePass, ...newUser } = user;

    return [200, newUser];
  });
};

const updateUserService = (dataUser, userId, authToken) => {
  const foundUser = users.find((user) => user.uuid === userId);

  foundUser.updatedOn = new Date();

  const token = authToken.split(" ")[1];

  return jwt.verify(token, "SECRET_KEY", (error, decoded) => {
    if (error) {
      return res.send(error.message);
    }

    const user = users.find((user) => user.email === decoded.email);

    // if (user.isAdm) {
    //   const editedUser = { ...foundUser, ...dataUser };

    //   const index = users.findIndex((user) => user.uuid === userId);

    //   users.splice(index, 1);

    //   users.push(editedUser);

    //   return [200, editedUser];
    // }

    if (userId === decoded.sub) {
      const editedUser = { ...foundUser, ...dataUser };

      const index = users.findIndex((user) => user.uuid === userId);

      users.splice(index, 1);

      users.push(editedUser);
      const { password: removePass, ...newUser } = editedUser;

      return [200, newUser];
    } else {
      return [403, { message: "missing admin permissions" }];
    }
  });
};

const deleteUserService = (id, authToken) => {
  const token = authToken.split(" ")[1];

  return jwt.verify(token, "SECRET_KEY", (error, decoded) => {
    if (error) {
      return res.send(error.message);
    }

    const user = users.find((user) => user.email === decoded.email);

    if (user.isAdm) {
      const index = users.findIndex((el) => el.uuid === id);

      users.splice(index, 1);

      return [204, {}];
    }

    if (id === decoded.sub) {
      const index = users.findIndex((el) => el.uuid === id);

      users.splice(index, 1);

      return [204, {}];
    } else {
      return [403, { message: "missing admin permissions" }];
    }
  });
};

// MIDDLEWARES -------------------------------------------------------------------------------------------------

const verifyAdmMiddleware = (req, res, next) => {
  const authToken = req.headers.authorization;

  const token = authToken.split(" ")[1];

  return jwt.verify(token, "SECRET_KEY", (error, decoded) => {
    if (error) {
      return res.send(error.message);
    }

    const user = users.find((user) => user.email === decoded.email);

    if (!user.isAdm) {
      return res.status(403).json({ message: "missing admin permissions" });
    }

    next();
  });
};

const verifyTokenMiddleware = (req, res, next) => {
  const authToken = req.headers.authorization;

  if (!authToken) {
    return res.status(401).json({ message: "Missing authorization headers" });
  }
  next();
};

// CONTROLLERS -------------------------------------------------------------------------------------------------

const createUserController = async (req, res) => {
  const [status, user] = await createUserService(req.body);

  return res.status(status).json(user);
};

const verifyUserExistsMiddleware = (req, res, next) => {
  const userAlreadyExists = users.find((user) => user.email === req.body.email);

  if (userAlreadyExists) {
    return res
      .status(409)
      .json({ message: "This email is already being used" });
  }
  return next();
};

const userLoginController = async (req, res) => {
  const { email, password } = req.body;

  const [status, token] = await userLoginService(email, password);

  return res.status(status).json(token);
};

const listUserController = (req, res) => {
  return res.status(200).json(users);
};

const userProfileControler = (req, res) => {
  const authToken = req.headers.authorization;

  const [status, user] = userProfileService(authToken);

  return res.status(status).json(user);
};

const editUserController = (req, res) => {
  const userId = req.params.uuid;
  const authToken = req.headers.authorization;

  const [status, user] = updateUserService(req.body, userId, authToken);

  return res.status(status).json(user);
};

const deleteUserControler = (req, res) => {
  const authToken = req.headers.authorization;
  const [status, data] = deleteUserService(req.params.id, authToken);
  return res.status(status).json(data);
};

// ROTAS -----------------------------------------------------------------------------------------------------

app.post("/users", verifyUserExistsMiddleware, createUserController);
app.post("/login", userLoginController);
app.get("/users/profile", verifyTokenMiddleware, userProfileControler);
app.patch("/users/:uuid", verifyTokenMiddleware, editUserController);
app.delete("/users/:id", verifyTokenMiddleware, deleteUserControler);
app.get(
  "/users",
  verifyTokenMiddleware,
  verifyAdmMiddleware,
  listUserController
);
app.get("/", (request, response) => {
  return response.send("Hello Word!");
});

app.listen(port, () => console.log(`App rodando na porta: ${port}.`));

export default app;

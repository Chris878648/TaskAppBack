const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const { initializeApp } = require("firebase/app");
const {
  getFirestore,
  collection,
  addDoc,
  getDocs,
  query,
  where,
  updateDoc,
  doc,
  getDoc,
} = require("firebase/firestore");

// Tu configuración de Firebase
const firebaseConfig = {
  apiKey: "AIzaSyDJ5TtjO5GI-wOza5dC2LLx4Cccu4PD1GM",
  authDomain: "taskapp-341af.firebaseapp.com",
  projectId: "taskapp-341af",
  storageBucket: "taskapp-341af.firebasestorage.app",
  messagingSenderId: "214913111245",
  appId: "1:214913111245:web:e408a4cfbf3f331fc28584",
  measurementId: "G-L59J1TQKW4",
};

const app = initializeApp(firebaseConfig);
const db = getFirestore(app);

// Crear un servidor Express
const Api = express();
const port = process.env.PORT;

Api.use(express.json());
Api.use(cors()); 


const SECRET_KEY = "HKAHS22SJX4223DXE";

// Middleware para verificar el token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

Api.get("/", (req, res) => {
  res.status(200).json({ message: "API is working!" });
});

Api.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  try {
    // Verificar si el correo electrónico o el nombre de usuario ya existen
    const emailQuery = query(collection(db, "Users"), where("email", "==", email));
    const usernameQuery = query(collection(db, "Users"), where("username", "==", username));
    
    const emailSnapshot = await getDocs(emailQuery);
    const usernameSnapshot = await getDocs(usernameQuery);

    if (!emailSnapshot.empty) {
      return res.status(400).json({ message: "Email already in use" });
    }

    if (!usernameSnapshot.empty) {
      return res.status(400).json({ message: "Username already in use" });
    }

    // Hashear la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    const docRef = await addDoc(collection(db, "Users"), {
      username,
      email,
      password: hashedPassword,
      last_login: "",
      type: 1,
    });

    const userId = docRef.id;

    res.status(200).json({ message: `User added with ID: ${userId}`, userId });
  } catch (error) {
    res.status(500).json({ message: "Error adding user: " + error.message });
  }
});

// Función para hacer login
Api.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const q = query(collection(db, "Users"), where("username", "==", username));
    const querySnapshot = await getDocs(q);

    if (querySnapshot.empty) {
      return res.status(400).json({ message: "Invalid username or password" });
    }

    const userDoc = querySnapshot.docs[0];
    const user = userDoc.data();
    const userId = userDoc.id;
    const type = user.type;

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid username or password" });
    }

    const token = jwt.sign({ userId, email: user.email }, SECRET_KEY, {
      expiresIn: "10m",
    });

    await updateDoc(doc(db, "Users", userDoc.id), {
      last_login: token,
    });

    res.status(200).json({ token, userId, email: user.email, type });
  } catch (error) {
    res.status(500).json({ message: "Error logging in: " + error.message });
  }
});

// Función para crear una tarea
Api.post("/tasks", authenticateToken, async (req, res) => {
  const { name, description, time, status, category } = req.body;
  try {
    const docRef = await addDoc(collection(db, "Tasks"), {
      name,
      description,
      time,
      status,
      category,
      email: req.user.email, // Asociar la tarea con el correo electrónico del usuario autenticado
      userId: req.user.userId, // Asociar la tarea con el ID del usuario autenticado
    });
    res.status(200).json({ message: `Task added with ID: ${docRef.id}` });
  } catch (error) {
    res.status(500).json({ message: "Error adding task: " + error.message });
  }
});

// Función para obtener todos los usuarios
Api.get("/get_users", authenticateToken, async (req, res) => {
  try {
    const querySnapshot = await getDocs(collection(db, "Users"));
    const users = querySnapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    }));
    res.status(200).json(users);
  } catch (error) {
    res.status(500).json({ message: "Error getting users: " + error.message });
  }
});

// Función para obtener todas las tareas del usuario autenticado
Api.get("/get_tasks", authenticateToken, async (req, res) => {
  try {
    const q = query(
      collection(db, "Tasks"),
      where("userId", "==", req.user.userId)
    );
    const querySnapshot = await getDocs(q);
    const tasks = querySnapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    }));
    res.status(200).json(tasks);
  } catch (error) {
    res.status(500).json({ message: "Error getting tasks: " + error.message });
  }
});

// Función para crear un grupo
Api.post("/groups", authenticateToken, async (req, res) => {
  const { name, userEmails } = req.body;
  try {
    const groupRef = await addDoc(collection(db, "Groups"), {
      name,
      ownerId: req.user.userId,
      userEmails,
    });
    res.status(200).json({ message: `Group created with ID: ${groupRef.id}` });
  } catch (error) {
    res.status(500).json({ message: "Error creating group: " + error.message });
  }
});

// Función para obtener todos los grupos del usuario autenticado
Api.get("/get_groups", authenticateToken, async (req, res) => {
  try {
    const q = query(
      collection(db, "Groups"),
      where("ownerId", "==", req.user.userId)
    );
    const querySnapshot = await getDocs(q);
    const groups = querySnapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    }));
    res.status(200).json(groups);
  } catch (error) {
    res.status(500).json({ message: "Error getting groups: " + error.message });
  }
});

// Función para crear una tarea en un grupo
Api.post("/groups/:groupId/tasks", authenticateToken, async (req, res) => {
  const { groupId } = req.params;
  const { name, description, time, status, category, assignedTo } = req.body;
  try {
    const groupDocRef = doc(db, "Groups", groupId);
    const groupDoc = await getDoc(groupDocRef);
    if (!groupDoc.exists()) {
      return res.status(404).json({ message: "Group not found" });
    }

    const group = groupDoc.data();
    if (group.ownerId !== req.user.userId) {
      return res
        .status(403)
        .json({ message: "Only the group owner can create tasks" });
    }

    const taskRef = await addDoc(collection(db, "Tasks"), {
      name,
      description,
      time,
      status,
      category,
      assignedTo,
      groupId,
    });
    res.status(200).json({ message: `Task created with ID: ${taskRef.id}` });
  } catch (error) {
    res.status(500).json({ message: "Error creating task: " + error.message });
  }
});

// Función para obtener todas las tareas de un grupo específico
Api.get("/groups/:groupId/tasks", authenticateToken, async (req, res) => {
  const { groupId } = req.params;
  try {
    const q = query(collection(db, "Tasks"), where("groupId", "==", groupId));
    const querySnapshot = await getDocs(q);
    const tasks = querySnapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    }));
    res.status(200).json(tasks);
  } catch (error) {
    res.status(500).json({ message: "Error getting tasks: " + error.message });
  }
});

// Función para obtener todos los grupos del usuario autenticado por correo electrónico
Api.get("/get_groups_byuser", authenticateToken, async (req, res) => {
  try {
    const userEmail = req.user.email; // Obtener el correo electrónico del usuario autenticado
    if (!userEmail) {
      return res.status(400).json({ message: "User email is undefined" });
    }
    const q = query(
      collection(db, "Groups"),
      where("userEmails", "array-contains", userEmail)
    );
    const querySnapshot = await getDocs(q);
    const groups = querySnapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    }));
    res.status(200).json(groups);
  } catch (error) {
    res.status(500).json({ message: "Error getting groups: " + error.message });
  }
});

// Función para obtener todas las tareas del usuario autenticado por correo electrónico
Api.get("/get_tasks_byuser", authenticateToken, async (req, res) => {
  try {
    const userEmail = req.user.email; // Obtener el correo electrónico del usuario autenticado
    if (!userEmail) {
      return res.status(400).json({ message: "User email is undefined" });
    }
    const q = query(
      collection(db, "Tasks"),
      where("assignedTo", "==", userEmail)
    );
    const querySnapshot = await getDocs(q);
    const tasks = querySnapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    }));
    res.status(200).json(tasks);
  } catch (error) {
    res.status(500).json({ message: "Error getting tasks: " + error.message });
  }
});

// Funcion para modificar el estatus de las actividaddes que te asignaron
Api.patch("/tasks/:taskId/status", authenticateToken, async (req, res) => {
  const { taskId } = req.params;
  const { status } = req.body;
  try {
    const taskDocRef = doc(db, "Tasks", taskId);
    const taskDoc = await getDoc(taskDocRef);
    if (!taskDoc.exists()) {
      return res.status(404).json({ message: "Task not found" });
    }

    const task = taskDoc.data();
    if (task.assignedTo !== req.user.email) {
      return res
        .status(403)
        .json({ message: "Only the assigned user can update the task status" });
    }

    await updateDoc(taskDocRef, { status });
    res.status(200).json({ message: "Task status updated successfully" });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error updating task status: " + error.message });
  }
});

// Función para modificar el estado de una tarea personal 
Api.patch("/tasks_personal/:taskId/status", authenticateToken, async (req, res) => {
  const { taskId } = req.params;
  const { status } = req.body;

  try {
    const taskDocRef = doc(db, "Tasks", taskId);
    const taskDoc = await getDoc(taskDocRef);

    if (!taskDoc.exists()) {
      return res.status(404).json({ message: "Task not found" });
    }

    const task = taskDoc.data();
    if (task.userId !== req.user.userId) {
      return res.status(403).json({ message: "You can only update your own tasks" });
    }

    await updateDoc(taskDocRef, { status });

    res.status(200).json({ message: "Task status updated successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error updating task status: " + error.message });
  }
});

// Función para hacer logout
Api.post("/logout", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    if (!userId) {
      return res.status(400).json({ message: "User ID is missing" });
    }

    const userDocRef = doc(db, "Users", userId);
    const userDoc = await getDoc(userDocRef);

    if (!userDoc.exists()) {
      return res.status(404).json({ message: "User not found" });
    }

    await updateDoc(userDocRef, { last_login: "" });

    res.status(200).json({ message: "Logout successful" });
  } catch (error) {
    res.status(500).json({ message: "Error logging out: " + error.message });
  }
});

// Función para actualizar la información del usuario
Api.patch("/update_user/:userId", authenticateToken, async (req, res) => {
  const { userId } = req.params;
  const { username, email, type } = req.body;

  try {
    const userDocRef = doc(db, "Users", userId);
    const userDoc = await getDoc(userDocRef);

    if (!userDoc.exists()) {
      return res.status(404).json({ message: "User not found" });
    }

    // Verificar si el username o email ya existen en otro usuario
    const usersCollection = collection(db, "Users");
    const q = query(usersCollection, 
      or(
        where("username", "==", username),
        where("email", "==", email)
      )
    );

    const querySnapshot = await getDocs(q);
    const existingUsers = querySnapshot.docs.filter(doc => doc.id !== userId);

    if (existingUsers.length > 0) {
      return res.status(400).json({ message: "Username or email already in use" });
    }

    const updates = {};
    if (username) updates.username = username;
    if (email) updates.email = email;
    if (type !== undefined) updates.type = type;

    await updateDoc(userDocRef, updates);

    res.status(200).json({ message: "User information updated successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error updating user information: " + error.message });
  }
});

// Iniciar el servidor
Api.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

module.exports = Api;

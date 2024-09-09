const express = require("express");
require("dotenv").config();
const cors = require("cors");
const { default: mongoose } = require("mongoose");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const nodemailer = require("nodemailer"); //mail//
const http = require("http");
const socketIo = require("socket.io");
const bcrypt = require("bcrypt"); //to protect user data//
const { connect } = require("./config/db");
const connection = require("./config/db");
const cookieParser = require("cookie-parser");

const { CallbackModel } = require("./models/UserModel/CallBackModel");
const { TransferModel } = require("./models/UserModel/TransferModel");
const { SaleModel } = require("./models/UserModel/SaleModel");
const { AttendanceModel } = require("./models/UserModel/Attendance");
const { ImageModel } = require("./models/UserModel/ImageModel");
const { MessageModel } = require("./models/UserModel/MessageModel");
const { ConcernModel } = require("./models/UserModel/concern");
const {
  RegisteradminModal,
} = require("./models/AdminModel/RegisterAdminModel");
const { RegisteruserModal } = require("./models/UserModel/RegisterUserModel");
const jwt = require("jsonwebtoken");
const { NotificationModel } = require("./models/AdminModel/NotificationModel");
const { MailModel } = require("./models/AdminModel/mailModal");
// const { DocumentsModel } = require("./models/AdminModel/DocumentsModel");
const { DocsModel } = require("./models/AdminModel/DocsModel");
const { ProjectsModel } = require("./models/AdminModel/ProjectsModel");
const { NotesModel } = require("./models/UserModel/Notepad");
const {
  NotifyMessageModel,
} = require("./models/AdminModel/NotifyMessageModel");
const adminAuth = require("./middleware/adminAuth");
const commonAuth = require("./middleware/commonAuth");
const userAuth = require("./middleware/userAuth");
const SessionsModel = require("./models/SessionsModel ");

const server = express();
//to avoid cors error//
server.use(
  cors({
    origin: [
      "https://digitalmitro.info",
      "http://localhost:5173",
      "http://localhost:3000",
      "https://admin.digitalmitro.info",
    ],
    credentials: true, // Allow credentials (cookies) to be sent
  })
);
server.use(express.json());
server.use(cookieParser());
connection();

const Port = process.env.port;
const secret_key = process.env.secret_key;
const expiry = process.env.expiry;

server.use((req, res, next) => {
  const allowedOrigins = [
    "https://digitalmitro.info",
    "http://localhost:5173",
    "http://localhost:3000",
    "https://admin.digitalmitro.info",
  ];
  // credentials: true,

  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin); // Set specific origin
    res.setHeader("Access-Control-Allow-Credentials", "true"); // Allow credentials
  }

  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, OPTIONS, PUT, PATCH, DELETE"
  );
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept"
  );

  // Handle preflight requests
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }

  next();
});
// Create an HTTP server instance

const httpServer = http.createServer(server);
// Integrate Socket.io with the HTTP server
const io = socketIo(httpServer, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
});

server.get("/", (req, res) => {
  res.send("welcome");
});
// Store connected users and their corresponding socket IDs
const users = {};
io.on("connection", (socket) => {
  console.log("New client connected");

  // Store the user's socket ID on connection
  socket.on("register", (userId) => {
    users[userId] = socket.id;
    console.log(`User ${userId} registered with socket ID ${socket.id}`);
  });

  // Handle sendMsg event
  socket.on("sendMsg", async (msg) => {
    try {
      // Save the message to the database
      const existingMessages = await MessageModel.findOne({
        user_id: msg.userId,
      });

      if (existingMessages) {
        existingMessages.messages.push({
          senderId: msg.senderId,
          receiverId: msg.receiverId,
          name: msg.name,
          email: msg.email,
          message: msg.message,
          time: msg.time,
          role: msg.role,
          status: msg.status,
        });
        console.log("existing messsage ", existingMessages.messages);
        await existingMessages.save();
      } else {
        const newMessage = new MessageModel({
          messages: [
            {
              senderId: msg.senderId,
              receiverId: msg.receiverId,
              name: msg.name,
              email: msg.email,
              message: msg.message,
              time: msg.time,
              role: msg.role,
              status: msg.status,
            },
          ],
          date: new Date().toLocaleDateString(),
          user_id: msg.userId,
        });
        await newMessage.save();
      }

      console.log("Message saved to the database");

      // Send the message to the specific user
      console.log(users);
      console.log(`Sender --> ${msg.senderId}`);
      console.log(`Receiver --> ${msg.receiverId}`);

      const recipientSocketId = users[msg.receiverId];
      console.log(recipientSocketId);
      if (recipientSocketId) {
        io.to(recipientSocketId).emit("chat message", msg);
      }
    } catch (err) {
      console.error("Error saving message to the database:", err);
    }
  });

  // Handle disconnection events
  socket.on("disconnect", () => {
    console.log("Client disconnected");
    // Remove the disconnected user's socket ID
    for (let userId in users) {
      if (users[userId] === socket.id) {
        delete users[userId];
        break;
      }
    }
  });
});

//welcome message

server.get("/nginx", (req, res) => {
  res.send("welcome to nginx");
});

// Create uploads directory if it doesn't exist
const uploadDir = path.join(__dirname, "uploads");

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

// Configure multer storage
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

// Configure multer file filter
const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif|mp4|mkv|pdf|doc|docs|txt/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(
      path.extname(file.originalname).toLowerCase()
    );

    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error("Only image, video, and PDF files are allowed!"));
    }
  },
});

// Serve uploads directory statically
server.use("/uploads", express.static(path.join(__dirname, "uploads")));

// //Email sent
server.post("/send-email", async (req, res) => {
  const { to, subject, html } = req.body;

  // Create a nodemailer transporter
  const transporter = nodemailer.createTransport({
    host: "smtp.office365.com",
    port: 587,
    secure: false,
    auth: {
      user: "sales@digitalmitro.com",
      pass: "iadnbcsmnfmumubt",
    },
  });

  // Define email options
  const mailOptions = {
    from: "sales@digitalmitro.com",
    to,
    subject,
    html,
    attachments: [
      {
        filename: subject,
        content:
          subject === "Digital Marketing Plan" ||
          subject === "SEO Plan" ||
          subject === "Social Media Marketing Plan"
            ? fs.createReadStream(
                "/root/CRM/Backend/Digital_Marketing_Plan.pdf"
              )
            : fs.createReadStream(
                "/root/CRM/Backend/Welcome_To_Digital_Mitro.pdf"
              ),
        contentType: "application/pdf",
      },
    ],
  };

  // Send the email
  try {
    // console.log(attachments);
    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: "Email sent successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error sending email" });
  }
});

// server.post("/send-email", async (req, res) => {
//   const { to, subject, html } = req.body;

//   // Create a nodemailer transporter
//   // let testAccount = await nodemailer.createTestAccount();

//   // connect with the smtp
//   let transporter =  nodemailer.createTransport({
//     host: "smtp.ethereal.email",
//     service: "gmail",
//     port: 587,
//     auth: {
//       user: "vernon.corwin@ethereal.email",
//       pass: "GdveCnJzJUufupdZ1S",
//     },
//     tls: {
//       rejectUnauthorized: false,
//     },
//   });

//   let info = await transporter.sendMail({
//     from: '"digital mitro" <sales@digitalmitro.com>',
//     to: to,
//     subject: subject,
//     text: "Hello YT Thapa",
//     html: html,
//   });

//   info.html = html;
//   info.text = "Hello YT Thapa";
//   console.log("Message sent: %s", "info", info);
//   res.json(info);
// })

// Gmail sent
// server.post("/send-email", async (req, res) => {
//   const { to, subject, text } = req.body;

//   // Create a nodemailer transporter
//   const transporter = nodemailer.createTransport({
//     service: "gmail",
//     auth: {
//       user: "tirtho.digitalmitro@gmail.com",
//       pass: "iyyq whed pthy yuhs",
//     },
//     tls: {
//       rejectUnauthorized: false,
//     },
//   });

//   // Define email options
//   const mailOptions = {
//     from: "tirtho.digitalmitro@gmail.com",
//     to,
//     subject,
//     text,
//   };

//   // Send the email
//   try {
//     await transporter.sendMail(mailOptions);
//     res.status(200).json({ message: "Subscribed" });
//   } catch (error) {
//     console.error(error);
//     res.status(500).json({ message: "Error sending email" });
//   }
// });

server.post("/mailData", async (req, res) => {
  try {
    const {
      BasicWebMailIntro,
      BasicWebMailMainBody,
      BasicWebMailList,
      BasicWebMailConclude,
      BasicWebMailLink,

      DmMailIntro,
      DmMailList,
      DmMailMainBody,
      DmMailConclude,
      DmMailLink,

      EcomMailIntro,
      EcomMailMainBody,
      EcmoMailList,
      EcomMailConclude,
      EcomMailLink,

      SeoMailIntro,
      SeoMailMainBody,
      SeoMailList,
      SeoMailConclude,
      SeoMailLink,

      SmoMailIntro,
      SmoMailMainBody,
      SmoMailList,
      SmoMailConclude,
      SmoMailLink,

      user_id,
    } = req.body;

    const updateData = {
      ...(BasicWebMailIntro && { BasicWebMailIntro }),
      ...(BasicWebMailMainBody && { BasicWebMailMainBody }),
      ...(BasicWebMailList && { BasicWebMailList }),
      ...(BasicWebMailConclude && { BasicWebMailConclude }),
      ...(BasicWebMailLink?.length !== 0 && { BasicWebMailLink }),
      ...(DmMailIntro && { DmMailIntro }),
      ...(DmMailList && { DmMailList }),
      ...(DmMailMainBody && { DmMailMainBody }),
      ...(DmMailConclude && { DmMailConclude }),
      ...(DmMailLink?.length !== 0 && { DmMailLink }),
      ...(EcomMailIntro && { EcomMailIntro }),
      ...(EcomMailMainBody && { EcomMailMainBody }),
      ...(EcmoMailList && { EcmoMailList }),
      ...(EcomMailConclude && { EcomMailConclude }),
      ...(EcomMailLink?.length !== 0 && { EcomMailLink }),
      ...(SeoMailIntro && { SeoMailIntro }),
      ...(SeoMailMainBody && { SeoMailMainBody }),
      ...(SeoMailList && { SeoMailList }),
      ...(SeoMailConclude && { SeoMailConclude }),
      ...(SeoMailLink?.length !== 0 && { SeoMailLink }),
      ...(SmoMailIntro && { SmoMailIntro }),
      ...(SmoMailMainBody && { SmoMailMainBody }),
      ...(SmoMailList && { SmoMailList }),
      ...(SmoMailConclude && { SmoMailConclude }),
      ...(SmoMailLink?.length !== 0 && { SmoMailLink }),
    };

    // Find the existing document or create a new one
    const mailData = await MailModel.findOneAndUpdate({}, updateData, {
      new: true,
      upsert: true,
      setDefaultsOnInsert: true, // Use default values if creating a new document
    });

    await RegisteradminModal.findByIdAndUpdate(
      user_id,
      { $push: { mail: mailData._id } },
      { new: true }
    );

    res.status(200).send(mailData);
  } catch (error) {
    console.error("Error updating mail data:", error);
    res.status(500).send({ error: "Internal server error" });
  }
});

server.get("/mailData", async (req, res) => {
  try {
    const mailModel = await MailModel.find();
    res.send(mailModel);
  } catch (error) {
    console.error(error);
    res.status(500).send("An error occurred while getting the mail template.");
  }
});
//ADMIN Section

// ADMIN  Register//
server.post("/registeradmin", async (req, res) => {
  const { name, email, phone, password } = req.body;

  try {
    // Check if the email already exists in the database
    const existingAdvisor = await RegisteradminModal.findOne();

    if (existingAdvisor) {
      // If email already exists, send an error response
      res.status(400).send("Admin Exists!");
    } else {
      // Hash the password
      bcrypt.hash(password, 5, async (err, hash) => {
        if (err) {
          console.log(err);
        } else {
          // Create a new instance of RegisteradvisorModal with the hashed password
          const newData = new RegisteradminModal({
            name,
            email,
            phone,
            password: hash,
          });

          // Save the advisor data to the database
          await newData.save();

          // Send a success response
          res.send("Registered");
        }
      });
    }
  } catch (error) {
    // Handle other errors, such as missing details in the request
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});


server.put("/updateadminpassword", adminAuth, async (req, res) => {
  const { email, oldPassword, newPassword } = req.body;

  try {
    // Check if the admin exists in the database
    const existingAdmin = await RegisteradminModal.findOne({ email });

    if (!existingAdmin) {
      // If the admin does not exist, send an error response
      return res.status(404).send("Admin not found");
    }

    // Check if the old password is provided
    if (!oldPassword || !newPassword) {
      return res.status(400).send("Old and new passwords are required");
    }

    // Compare the old password with the stored hashed password
    const isMatch = await bcrypt.compare(oldPassword, existingAdmin.password);
    if (!isMatch) {
      // If the old password does not match, send an error response
      return res.status(401).send("Old password is incorrect");
    }

    // Hash the new password
    const saltRounds = 5;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update the password in the database
    existingAdmin.password = hashedPassword;
    await existingAdmin.save();

    // Send a success response
    res.send("Password updated successfully");
  } catch (error) {
    // Handle other errors, such as missing details in the request
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});


//ADMIN Login
// server.post("/loginadmin", async (req, res) => {
//   const { email, password } = req.body;
//   try {
//     const user = await RegisteradminModal.findOne({ email });
//     if (user) {
//       bcrypt.compare(password, user.password, (err, result) => {
//         if (result) {
//           const accessToken = jwt.sign(
//             {
//               _id: user._id,
//               name: user.name,
//               email: user.email,
//               // phone: user.phone,
//             },
//             secret_key,
//             { expiresIn: expiry }
//           );
//           res.cookie('accessToken', accessToken, {
//             httpOnly:true,
//             // secure : true,
//             maxAge: 2 * 24 * 60 * 60 * 1000
//           })

//           res.json({
//             status: "login successful",
//             token: accessToken,
//             user: {
//               name: user.name,
//               email: user.email,
//               phone: user.phone,
//               _id: user._id,

//             },
//           });
//         } else {
//           res.status(401).json({ status: "wrong entry" });
//         }
//       });
//     } else {
//       res.status(404).json({ status: "user not found" });
//     }
//   } catch (error) {
//     console.error(error);
//     res.status(500).json({ status: "internal server error" });
//   }
// });

// NEW ADMIN LOGIN
server.post("/loginadmin",  async (req, res) => {
  try {
    const logEmail = req.body.email;
    const logPass = req.body.password;

    if (!logEmail || !logPass) {
      return res
        .status(422)
        .json({ message: "Please fill all the fields.", success: false });
    }

    const adminFound = await RegisteradminModal.findOne({ email: logEmail });

    if (adminFound) {
      const passCheck = await bcrypt.compare(logPass, adminFound.password);
      const token = await adminFound.generateAuthToken();

      if (passCheck) {
        res.status(200).json({
          status: "login successful",
          token: token,
          user: {
            name: adminFound.name,
            email: adminFound.email,
            phone: adminFound.phone,
            _id: adminFound._id,
          },

        });
        // const session = new SessionsModel({
        //   userId: adminFound._id,
        //   token: token
        // });
        // await session.save();
      } else {
        res
          .status(400)
          .json({ message: "Invalid login credentials", success: false });
      }
    } else {
      res.status(422).json({ message: "Admin Not Found !", success: false });
    }
  } catch (error) {
    res
      .status(500)
      .json({ message: "Invalid login credentials", success: false });
  }
});

server.post("/logout", async (req, res) => {
  try {
    await Session.deleteMany({ userId: req.user._id });
    res.status(200).json({ message: "Logged out" });
  } catch (error) {
    res.status(500).json({ message: "Error logging out", success: false });
  }
});
// Check Token API
server.get("/check-admin-token", adminAuth, async (req, res) => {
  try {
    // If the middleware passed, the token is valid
    res.status(200).json({ message: "Token is valid" });
  } catch (error) {
    res.status(500).json({ error: "Unable to verify token" });
  }
});

server.get("/check-user-token", userAuth, async (req, res) => {
  try {
    // If the middleware passed, the token is valid
    res.status(200).json({ message: "Token is valid" });
  } catch (error) {
    res.status(500).json({ error: "Unable to verify token" });
  }
});

//USER Section
// USER  Register//
server.post("/registeruser", adminAuth, async (req, res) => {
  const { name, email, phone, password, type, aliceName } = req.body;

  try {
    // Check if the email already exists in the database
    const existingAdvisor = await RegisteruserModal.findOne({ email });

    if (existingAdvisor) {
      // If email already exists, send an error response
      res.status(400).send("Email already exists");
    } else {
      // Hash the password
      bcrypt.hash(password, 5, async (err, hash) => {
        if (err) {
          console.log(err);
        } else {
          // Create a new instance of RegisteradvisorModal with the hashed password
          const newData = new RegisteruserModal({
            name,
            email,
            phone,
            password: hash,
            type,
            aliceName,
          });

          // Save the advisor data to the database
          await newData.save();

          // Send a success response
          res.send("User Registered");
        }
      });
    }
  } catch (error) {
    // Handle other errors, such as missing details in the request
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});
//USER Login
server.post("/loginuser", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(422)
        .json({ message: "Please fill all the fields.", success: false });
    }

    const adminFound = await RegisteruserModal.findOne({ email });

    if (adminFound) {
      const passCheck = await bcrypt.compare(password, adminFound.password);
      const token = await adminFound.generateAuthToken();

      if (passCheck) {
        res.status(200).json({
          status: "login successful",
          token: token,
          user: {
            name: adminFound.name,
            email: adminFound.email,
            phone: adminFound.phone,
            type: adminFound.type,
            aliceName: adminFound.aliceName,
            _id: adminFound._id,
          },
        });
      } else {
        res
          .status(401)
          .json({ message: "Invalid login credentials", success: false });
      }
    } else {
      res.status(404).json({ status: "user not found" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: "internal server error" });
  }
});

//Update User Detail
server.put("/updateuser", adminAuth, async (req, res) => {
  const { name, email, phone, password, type, user_id, aliceName } = req.body;

  try {
    // Hash the password
    bcrypt.hash(password, 10, async (err, hash) => {
      if (err) {
        console.log(err);
        return res.status(500).json({ error: "Error hashing password" });
      }

      try {
        // Update user with hashed password
        const updatedUser = await RegisteruserModal.findByIdAndUpdate(
          user_id,
          { name, aliceName, email, phone, password: hash, type },
          { new: true }
        );

        if (!updatedUser) {
          return res.status(404).json({ error: "User not found" });
        }

        // Optionally, you can return the updated user as JSON
        res.json("Updated user details successfully");
      } catch (error) {
        console.log(error);
        res.status(500).json({ error: "Server error" });
      }
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Server error" });
  }
});
// All user
server.get("/alluser",commonAuth, async (req, res) => {
  try {
    // Step 1: Fetch all users
    const users = await RegisteruserModal.find();
    const userIds = users.map((el) => el._id);

    // Step 2: Fetch callbacks, transfers, sales, messages, and attendances concurrently
    const [callbacks, transfers, sales, messages, attendances] =
      await Promise.all([
        CallbackModel.find({ user_id: { $in: userIds } }),
        TransferModel.find({ user_id: { $in: userIds } }),
        SaleModel.find({ user_id: { $in: userIds } }),
        MessageModel.find({ user_id: { $in: userIds } }),
        AttendanceModel.find({ user_id: { $in: userIds } }),
      ]);

    // Step 3: Map the fetched data to the respective users
    const userWithData = users.map((user) => {
      const userCallbacks = callbacks
        .filter((callback) => callback.user_id.equals(user._id))
        .map((callback) => callback._id);
      const userTransfers = transfers
        .filter((transfer) => transfer.user_id.equals(user._id))
        .map((transfer) => transfer._id);
      const userSales = sales
        .filter((sale) => sale.user_id.equals(user._id))
        .map((sale) => sale._id);
      const userMessages = messages
        .filter((message) => message.user_id.equals(user._id))
        .map((message) => message.message);
      const userAttendances = attendances
        .filter((attendance) => attendance.user_id.equals(user._id))
        .map((attendance) => attendance._id);

      return {
        ...user._doc, // Spread the original user data
        callback: userCallbacks,
        transfer: userTransfers,
        sale: userSales,
        message: userMessages,
        attendance: userAttendances,
      };
    });

    // Send the response with users and their respective data
    res.send(userWithData);
  } catch (error) {
    console.log(error);
    res.send(error);
  }
});

// 1 user
server.get("/alluser/:id", commonAuth, async (req, res) => {
  const ID = req.params.id;
  try {
    // Step 1: Fetch the user
    let user = await RegisteruserModal.findOne({ _id: ID });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Step 2: Fetch callbacks, transfers, sales, messages, and attendances concurrently
    const [callbacks, transfers, sales, messages, attendances] =
      await Promise.all([
        CallbackModel.find({ user_id: ID }),
        TransferModel.find({ user_id: ID }),
        SaleModel.find({ user_id: ID }),
        MessageModel.find({ user_id: ID }),
        AttendanceModel.find({ user_id: ID }),
      ]);

    // Step 3: Add the fetched data to the user object
    user = user.toObject(); // Convert Mongoose document to plain object
    user.callback = callbacks;
    user.transfer = transfers;
    user.sale = sales;
    user.message = messages;
    user.attendance = attendances;

    // Send the response with the user and their respective data
    res.status(200).json(user);
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

//1 delete
server.delete("/alluser/:id", adminAuth, async (req, res) => {
  const ID = req.params.id;
  try {
    const user = await RegisteruserModal.findByIdAndDelete(ID);
    if (!user) {
      return res.status(404).send({ message: "User not found" });
    }
    res.send({ message: "User deleted successfully" });
  } catch (error) {
    console.log(error);
    res.status(500).send({ message: "Internal Server Error" });
  }
});

//NOTIFICATION
server.post("/notification", async (req, res) => {
  try {
    const notification = req.body;
    // Save the notification in the database
    const savedNotification = await NotificationModel.create(notification);

    await savedNotification.save();
    // io.emit("new_notification", savedNotification);
    res.status(200).send("Notification sent successfully!");
  } catch (error) {
    console.log(error);
    res.status(500).send("An error occurred while sending the notification.");
  }
});

server.get("/notification", async (req, res) => {
  try {
    const notifications = await NotificationModel.find();
    res.send(notifications);
  } catch (error) {
    console.error(error);
    res.status(500).send("An error occurred while getting the notifications.");
  }
});

server.put("/notification/:id", async (req, res) => {
  const ID = req.params.id;
  const { Status } = req.body;
  try {
    const data = await NotificationModel.findByIdAndUpdate(
      ID,
      { Status },
      { new: true }
    );
    if (!data) {
      return res.status(404).send({ concern: "notification not found" });
    }
    res.send({ message: "Status updated successfully", data });
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});

server.post("/projects", adminAuth, async (req, res) => {
  try {
    const { projectName, tasks } = req.body;
    const project = new ProjectsModel({ projectName, tasks });
    await project.save();
    res.status(201).send(project);
  } catch (error) {
    res.status(500).send({ message: "Error creating project", error });
  }
});

// add tasks in particular project
server.post("/projects/:projectId", adminAuth, async (req, res) => {
  try {
    const { projectId } = req.params;
    const taskData = req.body;

    if (!taskData.assigneeName) {
      return res.status(400).send({ message: "assigneeName is required" });
    }
    if (!taskData.assigneeId) {
      return res.status(400).send({ message: "assigneeId is required" });
    }

    const project = await ProjectsModel.findById(projectId);
    if (!project) {
      return res.status(404).json({ message: "Project not found" });
    }

    project.tasks.push(taskData);
    await project.save();

    res.status(201).json(project);
  } catch (error) {
    res.status(500).json({ message: "Error adding task to project", error });
  }
});

server.get("/projects", async (req, res) => {
  try {
    const project = await ProjectsModel.find();
    if (!project) {
      return res.status(404).send({ message: "Project not found" });
    }
    res.status(200).send(project);
  } catch (error) {
    res.status(500).send({ message: "Error retrieving tasks", error });
  }
});

server.get("/projects/:projectId", async (req, res) => {
  try {
    const { projectId } = req.params;
    const project = await ProjectsModel.findById(projectId);

    if (!project) {
      return res.status(404).send({ message: "Project not found" });
    }

    res.status(200).send(project);
  } catch (error) {
    res.status(500).send({ message: "Error retrieving tasks", error });
  }
});

// Update a project by ID
server.put("/projects/:projectId", adminAuth, async (req, res) => {
  try {
    const { projectId } = req.params;
    const updateData = req.body;

    const project = await ProjectsModel.findByIdAndUpdate(
      projectId,
      { $set: updateData },
      { new: true }
    );

    if (!project) {
      return res.status(404).json({ message: "Project not found" });
    }

    res.status(200).json(project);
  } catch (error) {
    res.status(500).json({ message: "Error updating project", error });
  }
});

server.delete(
  "/projects/:projectId/tasks/:taskId",
  adminAuth,
  async (req, res) => {
    const { projectId, taskId } = req.params;
    console.log(req.params);
    try {
      // Find the project by ID
      const project = await ProjectsModel.findById(projectId);
      if (!project) {
        return res.status(404).send({ message: "Project not found" });
      }

      // Find the task within the project's tasks array by its ID and remove it
      const taskIndex = project.tasks.findIndex(
        (task) => task._id.toString() === taskId
      );
      if (taskIndex === -1) {
        return res.status(404).send({ message: "Task not found" });
      }

      // Remove the task from the tasks array
      project.tasks.splice(taskIndex, 1);

      // Save the updated project
      await project.save();

      res.send({ message: "Task deleted successfully" });
    } catch (error) {
      console.log(error);
      res.status(500).send({ message: "Internal Server Error" });
    }
  }
);

server.put("/tasks/:taskId", commonAuth, async (req, res) => {
  const taskId = req.params.taskId;

  // Destructure fields from req.body
  const {
    taskname,
    assigneeName,
    assigneeId,
    comments,
    deadline,
    status,
    priority,
  } = req.body;

  try {
    // Find the project that contains the task
    const project = await ProjectsModel.findOne({ "tasks._id": taskId });

    if (!project) {
      return res.status(404).send("Project or Task not found");
    }

    // Find the task within the project's tasks array
    const task = project.tasks.id(taskId);
    if (!task) {
      return res.status(404).send("Task not found in the project");
    }

    // Prepare the updates object
    const updates = {
      ...(taskname && { taskname }),
      ...(assigneeName && { assigneeName }),
      ...(assigneeId && { assigneeId }),
      ...(comments && { comments }),
      ...(deadline && { deadline }),
      ...(status && { status }),
      ...(priority && { priority }),
    };

    // Apply updates to the task
    Object.assign(task, updates);

    // Save the project back to the database
    await project.save();

    res.send("Task updated successfully");
  } catch (error) {
    console.error(error);
    res.status(500).send(error, "error ");
  }
});

// all projects with asignee names
server.get("/tasks/:assigneeId", async (req, res) => {
  try {
    const { assigneeId } = req.params;

    // Find projects with tasks assigned to the given assigneeId
    const projects = await ProjectsModel.find({
      "tasks.assigneeId": assigneeId,
    });

    // Extract tasks for the specific assignee
    // const assignedTasks = projects.reduce((tasks, project) => {
    //   const userTasks = project.tasks.filter(task => task.assigneeId === assigneeId);
    //   return tasks.concat(userTasks);
    // }, []);

    res.status(200).send(projects);
  } catch (error) {
    res
      .status(500)
      .send({ message: "Error retrieving tasks for assignee", error });
  }
});

//callBacks

// Create callBacks  populate
server.post("/callbacks", async (req, res) => {
  const {
    employeeName,
    employeeEmail,
    name,
    email,
    phone,

    domainName,
    address,
    country,

    comments,
    buget,
    calldate,
    createdDate,
    user_id,
  } = req.body;

  try {
    // Create a new instance of AdvisorpackageModel
    const newPackage = new CallbackModel({
      employeeName,
      employeeEmail,
      name,
      email,
      phone,

      domainName,
      address,
      country,

      comments,
      buget,
      calldate,
      createdDate,
      user_id,
    });

    // Save the package to the database
    await newPackage.save();

    // Update the user's packages array
    await RegisteruserModal.findByIdAndUpdate(
      user_id,
      { $push: { callback: newPackage._id } },
      { new: true }
    );

    // Send a success response
    res.send("callback Created and associated with user");
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});
//  callBacks Populate by user
server.get("/callback-user/:id", async (req, res) => {
  try {
    // const data = await RegisteruserModal.findById(ID).populate("callback");
    const ID = new mongoose.Types.ObjectId(req.params.id);

    let data = await RegisteruserModal.aggregate([
      {
        $match: {
          _id: ID,
        },
      },
      {
        $lookup: {
          from: "callbacks",
          localField: "_id",
          foreignField: "user_id",
          as: "callback",
        },
      },
    ]);
    data = data[0];
    res.status(200).json(data);
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});
//  all created callBacks
server.get("/allcallback", async (req, res) => {
  try {
    const data = await CallbackModel.find();
    res.send(data);
  } catch (error) {
    console.log(error);
    res.send(error);
  }
});
// 1 created callBacks
server.get("/callback-1/:id", async (req, res) => {
  const packageId = req.params.id;
  try {
    const package = await CallbackModel.findById(packageId);
    if (!package) {
      return res.status(404).send("Package not found");
    }
    res.send(package);
  } catch (error) {
    console.log(error);
    res.status(500).send(error);
  }
});
// 2. Update a document by ID
server.put("/callback-1/:id", async (req, res) => {
  const packageId = req.params.id;
  const {
    name,
    email,
    phone,

    domainName,
    address,
    country,

    comments,
    buget,
    calldate,
  } = req.body;
  try {
    const package = await CallbackModel.findByIdAndUpdate(
      packageId,
      {
        name,
        email,
        phone,

        domainName,
        address,
        country,

        comments,
        buget,
        calldate,
      },
      { new: true }
    );
    if (!package) {
      return res.status(404).send("Package not found");
    }
    res.send("Package updated successfully");
  } catch (error) {
    console.log(error);
    res.status(500).send(error);
  }
});
// 3. Delete a document by ID
server.delete("/callback-1/:id", async (req, res) => {
  const packageId = req.params.id;
  try {
    const package = await CallbackModel.findByIdAndDelete(packageId);
    if (!package) {
      return res.status(404).send("Package not found");
    }
    res.send("Package deleted successfully");
  } catch (error) {
    console.log(error);
    res.status(500).send(error);
  }
});
//transfer

// Create transfer  populate
server.post("/transfer", async (req, res) => {
  const {
    employeeName,
    employeeEmail,
    name,
    email,
    phone,
    transferTo,
    domainName,
    address,
    country,
    zipcode,
    comments,
    buget,
    calldate,
    createdDate,
    user_id,
  } = req.body;

  try {
    // Create a new instance of AdvisorpackageModel
    const newPackage = new TransferModel({
      employeeName,
      employeeEmail,
      name,
      email,
      phone,
      transferTo,
      domainName,
      address,
      country,
      zipcode,
      comments,
      buget,
      calldate,
      createdDate,
      user_id,
    });

    // Save the package to the database
    await newPackage.save();

    // Update the user's packages array
    await RegisteruserModal.findByIdAndUpdate(
      user_id,
      { $push: { transfer: newPackage._id } },
      { new: true }
    );

    // Send a success response
    res.send("transfer Created and associated with user");
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});
//  transfer Populate by user
server.get("/transfer-user/:id", async (req, res) => {
  const ID = req.params.id;
  try {
    const ID = new mongoose.Types.ObjectId(req.params.id);

    let data = await RegisteruserModal.aggregate([
      {
        $match: {
          _id: ID,
        },
      },
      {
        $lookup: {
          from: "transfers",
          localField: "_id",
          foreignField: "user_id",
          as: "transfer",
        },
      },
    ]);
    data = data[0];
    res.status(200).json(data);
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});
//  all created transfer
server.get("/alltransfer", async (req, res) => {
  try {
    const data = await TransferModel.find();
    res.send(data);
  } catch (error) {
    console.log(error);
    res.send(error);
  }
});
// 1 created transfer
server.get("/transfer-1/:id", async (req, res) => {
  const packageId = req.params.id;
  try {
    const package = await TransferModel.findById(packageId);
    if (!package) {
      return res.status(404).send("Package not found");
    }
    res.send(package);
  } catch (error) {
    console.log(error);
    res.status(500).send(error);
  }
});

// 2. Update a document by ID
server.put("/transfer-1/:id", async (req, res) => {
  const packageId = req.params.id;
  const {
    name,
    email,
    phone,

    domainName,
    address,
    country,

    comments,
    buget,
    calldate,
  } = req.body;
  try {
    const package = await TransferModel.findByIdAndUpdate(
      packageId,
      {
        name,
        email,
        phone,

        domainName,
        address,
        country,

        comments,
        buget,
        calldate,
      },
      { new: true }
    );
    if (!package) {
      return res.status(404).send("Package not found");
    }
    res.send("Package updated successfully");
  } catch (error) {
    console.log(error);
    res.status(500).send(error);
  }
});
// 2. Delete a document by ID
server.delete("/transfer-1/:id", async (req, res) => {
  const packageId = req.params.id;
  try {
    const package = await TransferModel.findByIdAndDelete(packageId);
    if (!package) {
      return res.status(404).send("Package not found");
    }
    res.send("Package deleted successfully");
  } catch (error) {
    console.log(error);
    res.status(500).send(error);
  }
});
//sale

// Create sale  populate
server.post("/sale", async (req, res) => {
  const {
    employeeName,
    employeeEmail,
    name,
    email,
    phone,
    transferTo,
    domainName,
    address,
    country,
    zipcode,
    comments,
    buget,
    calldate,
    createdDate,
    user_id,
  } = req.body;

  try {
    // Create a new instance of AdvisorpackageModel
    const newPackage = new SaleModel({
      employeeName,
      employeeEmail,
      name,
      email,
      phone,
      transferTo,
      domainName,
      address,
      country,
      zipcode,
      comments,
      buget,
      calldate,
      createdDate,
      user_id,
    });

    // Save the package to the database
    await newPackage.save();

    // Update the user's packages array
    await RegisteruserModal.findByIdAndUpdate(
      user_id,
      { $push: { sale: newPackage._id } },
      { new: true }
    );

    // Send a success response
    res.send("sale Created and associated with user");
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});
//  sale Populate by user
server.get("/sale-user/:id", async (req, res) => {
  const ID = req.params.id;
  try {
    const ID = new mongoose.Types.ObjectId(req.params.id);

    let data = await RegisteruserModal.aggregate([
      {
        $match: {
          _id: ID,
        },
      },
      {
        $lookup: {
          from: "sales",
          localField: "_id",
          foreignField: "user_id",
          as: "sale",
        },
      },
    ]);
    data = data[0];
    res.status(200).json(data);
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});

//  all created transfer
server.get("/allsale", async (req, res) => {
  try {
    const data = await SaleModel.find();
    res.send(data);
  } catch (error) {
    console.log(error);
    res.send(error);
  }
});

// 1 created sale

server.get("/sale-1/:id", async (req, res) => {
  const packageId = req.params.id;
  try {
    const package = await SaleModel.findById(packageId);
    if (!package) {
      return res.status(404).send("Package not found");
    }
    res.send(package);
  } catch (error) {
    console.log(error);
    res.status(500).send(error);
  }
});

// 2. Update a document by ID
server.put("/sale-1/:id", async (req, res) => {
  const packageId = req.params.id;
  const {
    name,
    email,
    phone,

    domainName,
    address,
    country,

    comments,
    buget,
    calldate,
  } = req.body;
  try {
    const package = await SaleModel.findByIdAndUpdate(
      packageId,
      {
        name,
        email,
        phone,

        domainName,
        address,
        country,

        comments,
        buget,
        calldate,
      },
      { new: true }
    );
    if (!package) {
      return res.status(404).send("Package not found");
    }
    res.send("Package updated successfully");
  } catch (error) {
    console.log(error);
    res.status(500).send(error);
  }
});
// 3. Delete a document by ID
server.delete("/sale-1/:id", async (req, res) => {
  const packageId = req.params.id;
  try {
    const package = await SaleModel.findByIdAndDelete(packageId);
    if (!package) {
      return res.status(404).send("Package not found");
    }
    res.send("Package deleted successfully");
  } catch (error) {
    console.log(error);
    res.status(500).send(error);
  }
});

// Create attendance  populate
// server.post("/attendance", async (req, res) => {
//   const {
//     userName,
//     userEmail,
//     currentDate,
//     punchin,
//     punchOut,
//     status,
//     time,
//     ip,
//     user_id,
//   } = req.body;
//   console.log(
//     "test",
//     userName,
//     userEmail,
//     currentDate,
//     punchin,
//     punchOut,
//     status,
//     time,
//     ip,
//     user_id
//   );
//   try {
//     // Create a new instance of AdvisorpackageModel
//     const newPackage = new AttendanceModel({
//       userName,
//       userEmail,
//       currentDate,
//       punchin,
//       punchOut,
//       status,
//       time,
//       ip,
//       user_id,
//     });

//     // Save the package to the database
//     await newPackage.save();

//     // Update the user's packages array
//     await RegisteruserModal.findByIdAndUpdate(
//       user_id,
//       { $push: { attendance: newPackage._id } },
//       { new: true }
//     );

//     // Send a success response
//     res.send("attendance stored");
//   } catch (error) {
//     console.log(error);
//     res.status(500).send("Internal Server Error");
//   }
// });

server.post("/attendance", async (req, res) => {
  try {
    const { userName, userEmail, currentDate, punches, shiftType, ip, status, user_id } = req.body;

    let startDate, endDate;
    // Determine the start and end dates based on shiftType

    if (shiftType === "Day") {
      startDate = new Date(new Date(currentDate).setHours(0, 0, 0, 0)); // 10:00 AM
      endDate = new Date(new Date(currentDate).setHours(23, 59, 59, 59));   // 8:00 PM
    } else if (shiftType === "Night") {
      startDate = new Date(new Date(currentDate).setHours(0, 0, 0, 0)); 
      endDate = new Date(new Date(currentDate).setDate(new Date(currentDate).getDate() + 1));
      endDate.setHours(23, 59, 59, 59); // 5:00 AM on the next day
    } else {
      return res.status(400).json({ message: "Invalid shift type" });
    }

    // Check if an attendance record exists for the same user_id within the shiftType time range
    const existingAttendance = await AttendanceModel.findOne({
      user_id,
      currentDate: {
        $gte: startDate,
        $lt: endDate
      }
    });
    if (existingAttendance) {
      // If attendance exists for the specified shiftType time range, update the punches array
      existingAttendance.punches.push(...punches);
      // existingAttendance.totalWorkingTime += punches.reduce((acc, punch) => acc + punch.workingTime, 0);
      // existingAttendance.workStatus = workStatus; 
      await existingAttendance.save();
      return res.status(200).json(existingAttendance);
    } else {
      // If no record exists, create a new attendance record
      // const totalWorkingTime = punches.reduce((acc, punch) => acc + punch.workingTime, 0);
      const newAttendance = new AttendanceModel({
        userName,
        userEmail,
        currentDate,
        punches,
        shiftType,
        ip,
        status,
        user_id
      });
      const savedAttendance = await newAttendance.save();
      return res.status(201).json(savedAttendance);
    }
  } catch (error) {
    console.error("Error creating or updating attendance record:", error);
    res.status(500).json({ message: "Failed to create or update attendance record" });
  }
});


server.get("/todays-attendence", async (req, res) => {
  try {
    const { user_id, currentDate } = req.query;

    if (!user_id || !currentDate) {
      return res.status(400).json({ message: "user_id and currentDate are required" });
    }

    // Convert currentDate to local time (IST)
    // const localCurrentDate = new Date(new Date(currentDate).toLocaleString("en-US", { timeZone: "Asia/Kolkata" }));
    const localCurrentDate = new Date(currentDate)
    
    // Determine the start and end of the day
    const startDate = new Date(localCurrentDate.setHours(0, 0, 0, 0)); 
    const endDate = new Date(localCurrentDate.setHours(23, 59, 59, 59));   
    

    // Find the attendance record for the specified user_id and currentDate within the day shift time range
    const attendance = await AttendanceModel.findOne({
      user_id,
      currentDate: {
        $gte: startDate,
        $lt: endDate
      }
    });

    if (!attendance) {
      return res.status(404).json({ message: "Attendance record not found for the specified date and shift" });
    }

    // Return the attendance record
    res.status(200).json(attendance);
  } catch (error) {
    console.error("Error retrieving attendance record:", error);
    res.status(500).json({ message: "Failed to retrieve attendance record" });
  }
});

const determineWorkStatus = (totalWorkingTime) => {
  const minutesWorked = totalWorkingTime; // Convert minutes to hours
  console.log("HOURS-->",minutesWorked)
  if (minutesWorked >= 420 && minutesWorked <= 600) return "Full Day";
  if (minutesWorked >= 200 && minutesWorked<=420) return "Half Day";
  if (minutesWorked <200 ) return "Absent";
  
  return "Over Time";
};


server.put("/punchout", async (req, res) => {
  try {
    const { user_id, currentDate, punchOut, shiftType } = req.body;
    const localCurrentDate = new Date(currentDate);
    let startDate, endDate;
    console.log("localCurrentDate", localCurrentDate);

    // Determine the start and end dates based on shiftType
    if (shiftType === "Day") {
      startDate = new Date(localCurrentDate.setHours(0, 0, 0, 0));
      endDate = new Date(localCurrentDate.setHours(23, 59, 59, 59));  
    } else if (shiftType === "Night") {
      startDate = new Date(localCurrentDate.setHours(0, 0, 0, 0)); 
      endDate = new Date(localCurrentDate.setDate(localCurrentDate.getDate() + 1));
      endDate.setHours(23, 59, 59, 59); 
    } else {
      return res.status(400).json({ message: "Invalid shift type" });
    }
    console.log("startDate", startDate, "endDate", endDate);

    // Find the attendance record for the specified user_id and currentDate within shiftType time range
    const attendance = await AttendanceModel.findOne({
      user_id,
      currentDate: {
        $gte: startDate,
        $lte: endDate
      }
    });

    if (!attendance) {
      return res.status(404).json({ message: "Attendance record not found for the specified date and shift" });
    }

    // Find the last punch-in object without a punch-out time
    const punches = attendance.punches;
    const lastPunchIn = punches[punches.length - 1]; // Get the last object in the array

    if (!lastPunchIn || lastPunchIn.punchOut) {
      return res.status(400).json({ message: "No valid punch-in record found without a corresponding punch-out" });
    }

    // Update the last punch-in object with punch-out time
    lastPunchIn.punchOut = new Date(punchOut);

    // Calculate working time in minutes
    const punchInTime = new Date(lastPunchIn.punchIn);
    const punchOutTime = new Date(lastPunchIn.punchOut);
    const workingTime = (punchOutTime - punchInTime) / (1000 * 60); // Convert milliseconds to minutes
    lastPunchIn.workingTime = workingTime;

    // Recalculate total working time
    attendance.totalWorkingTime = punches.reduce((total, punch) => total + (punch.workingTime || 0), 0);

    attendance.workStatus = determineWorkStatus(attendance.totalWorkingTime);
    console.log("attendance", attendance);

    // Update the attendance record
    await attendance.save();

    res.status(200).json(attendance);
  } catch (error) {
    console.error("Error updating punch-out record:", error);
    res.status(500).json({ message: "Failed to update punch-out record" });
  }
});

const checkIfLate = (punchInDate, shiftType) => {
  const momentPunchInDate = moment(punchInDate); // current punch-in time using moment

  if (shiftType === 'Day') {
    const lateStart = momentPunchInDate.startOf('day').hours(10).minutes(40).seconds(0); // 10:40 AM same day
    return momentPunchInDate.isAfter(lateStart);
  } else if (shiftType === 'Night') {
    const lateStart = momentPunchInDate.startOf('day').hours(20).minutes(40).seconds(0); // 8:40 PM same day
    const lateEnd = momentPunchInDate.add(1, 'day').startOf('day').hours(8).minutes(40).seconds(0); // 8:40 AM next day

    // Check if punchInDate falls between lateStart and lateEnd (spanning two days)
    return momentPunchInDate.isAfter(lateStart) || momentPunchInDate.isBefore(lateEnd);
  }

  return false;
};


server.put("/attendance-approval", async (req, res) => {
  try {
    const { user_id, concernDate, punchIn, punchOut, shiftType } = req.body;

    // Validate input
    if (!user_id || !concernDate || !punchIn || !punchOut || !shiftType) {
      return res.status(400).json({ message: "Invalid input" });
    }

    // Convert dates to UTC
    const punchInTime = new Date(punchIn);
    const punchOutTime = new Date(punchOut);

    if (isNaN(punchInTime) || isNaN(punchOutTime)) {
      return res.status(400).json({ message: "Invalid date format" });
    }

    // Determine the date range based on shiftType
    let startDate, endDate;
    const localconcernDate = new Date(concernDate);
    if (shiftType === "Day") {
      startDate = new Date(localconcernDate.setHours(0, 0, 0, 0)); // Start of the day
      endDate = new Date(localconcernDate.setHours(23, 59, 59, 999)); // End of the day
    } else if (shiftType === "Night") {
      startDate = new Date(localconcernDate.setHours(0, 0, 0, 0)); // Start of the day
      endDate = new Date(localconcernDate.setDate(localconcernDate.getDate() + 1)); // Next day
      endDate.setHours(19, 59, 59, 999); // End of the next day
    } else {
      return res.status(400).json({ message: "Invalid shift type" });
    }

    // Find the attendance record for the specified user_id and concernDate
    const attendance = await AttendanceModel.findOne({
      user_id,
      concernDate: {
        $gte: startDate,
        $lte: endDate
      }
    });

    if (!attendance) {
      return res.status(404).json({ message: "Attendance record not found" });
    }

    // Replace punches with the new punchIn and punchOut
    attendance.punches = [{
      punchIn: punchInTime,
      punchOut: punchOutTime,
      workingTime: (punchOutTime - punchInTime) / (1000 * 60) // Convert milliseconds to minutes
    }];

    // Calculate total working time
    attendance.totalWorkingTime = attendance.punches.reduce((total, punch) => {
      return total + (punch.workingTime || 0);
    }, 0);

    // Determine work status
    attendance.workStatus = determineWorkStatus(attendance.totalWorkingTime);

    // Determine if the punch-in time is late based on shiftType
    const isLate = checkIfLate(punchInTime, shiftType);
    attendance.status = isLate ? 'Late' : 'On Time';

    // Save the updated record
    await attendance.save();

    // Respond with the updated attendance record
    res.status(200).json(attendance);
  } catch (error) {
    console.error("Error updating punches:", error);
    res.status(500).json({ message: "Failed to update punches" });
  }
});

// server.put("/attendence-approval", async (req, res) => {
//   try {
//     const { user_id, currentDate, punchIn, punchOut } = req.body;

//     // Validate input
//     if (!user_id || !currentDate || !punchIn || !punchOut) {
//       return res.status(400).json({ message: "Invalid input" });
//     }

//     // Convert dates to UTC
//     const punchInTime = new Date(punchIn);
//     const punchOutTime = new Date(punchOut);

//     if (isNaN(punchInTime) || isNaN(punchOutTime)) {
//       return res.status(400).json({ message: "Invalid date format" });
//     }

//     const localCurrentDate = new Date(currentDate);
//     const startDate = new Date(localCurrentDate.setHours(0, 0, 0, 0));
//     const endDate = new Date(localCurrentDate.setHours(23, 59, 59, 999));

//     // Find the attendance record for the specified user_id and currentDate
//     const attendance = await AttendanceModel.findOne({
//       user_id,
//       currentDate: {
//         $gte: startDate,
//         $lte: endDate
//       }
//     });

//     if (!attendance) {
//       return res.status(404).json({ message: "Attendance record not found" });
//     }

//     // Replace punches with the new punchIn and punchOut
//     attendance.punches = [{
//       punchIn: punchInTime,
//       punchOut: punchOutTime,
//       workingTime: (punchOutTime - punchInTime) / (1000 * 60) // Convert milliseconds to minutes
//     }];

//     // Calculate total working time
//     attendance.totalWorkingTime = attendance.punches.reduce((total, punch) => {
//       return total + (punch.workingTime || 0);
//     }, 0);

//     // Update work status based on total working time
//     attendance.workStatus = determineWorkStatus(attendance.totalWorkingTime);

//     // Save the updated record
//     await attendance.save();

//     // Respond with the updated attendance record
//     res.status(200).json(attendance);
//   } catch (error) {
//     console.error("Error updating punches:", error);
//     res.status(500).json({ message: "Failed to update punches" });
//   }
// });

//  Attendace Populate by user
server.get("/attendance/:id", async (req, res) => {
  const ID = req.params.id;
  try {
    const data = await RegisteruserModal.findById(ID).populate("attendance");
    res.send(data);
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});


server.get("/attendancelist/:id", async (req, res) => {
  const ID = req.params.id;
  try {
    const data = await AttendanceModel.find({user_id: ID})
    if(data){
      res.status(200).json(
        {
          message:"data Collected Successuflly ",
          data: data
        }
      );
    }else{
      res.statua(404).json("no Data Found")
    }

  
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});
//  All Attendace
server.get("/attendance", async (req, res) => {
  try {
    const data = await AttendanceModel.find();
    res.send(data);
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});

// Create Image For User populate
server.post("/image", async (req, res) => {
  const { imageUrl, user_id } = req.body;

  try {
    // Find the existing homecms document for the given user_id
    const existingPackage = await ImageModel.findOne({ user_id });

    if (!existingPackage) {
      // If no existing document, create a new one
      const newPackage = new ImageModel({
        imageUrl,
        user_id,
      });

      // Save the new document to the database
      await newPackage.save();

      // Update the user's packages array
      await RegisteruserModal.findByIdAndUpdate(
        user_id,
        { $push: { image: newPackage._id } },
        { new: true }
      );
    } else {
      // If an existing document is found, update its fields
      await ImageModel.findOneAndUpdate(
        { user_id },
        { imageUrl },
        { new: true }
      );
    }

    // Send a success response
    res.send("Image Created/Updated");
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});
//  GET Image for user
server.get("/image/:id", async (req, res) => {
  const ID = req.params.id;
  try {
    const data = await RegisteruserModal.findById(ID).populate("image");
    res.send(data);
  } catch (error) {
    console.log(error);
    res.send(error);
  }
});

//  message All
server.get("/employees", async (req, res) => {
  try {
    const data = await RegisteruserModal.aggregate([
      // Lookup for messages
      {
        $lookup: {
          from: "messages",
          localField: "_id",
          foreignField: "user_id",
          as: "empMessages",
        },
      },
      {
        $unwind: {
          path: "$empMessages",
          preserveNullAndEmptyArrays: true,
        },
      },
      // Unwind the messages array to access individual messages
      {
        $unwind: {
          path: "$empMessages.messages",
          preserveNullAndEmptyArrays: true,
        },
      },
      // Sort by the message time in descending order to get the most recent message
      {
        $sort: {
          "empMessages.messages.time": -1,
        },
      },
      // Group by _id to get the most recent message
      {
        $group: {
          _id: "$_id",
          name: { $first: "$name" },
          email: { $first: "$email" },
          phone: { $first: "$phone" },
          image: { $first: "$image" },
          lastMessage: { $first: "$empMessages.messages.message" },
          lastMessageTime: { $first: "$empMessages.messages.time" },
          lastMessageSender: { $first: "$empMessages.messages.senderId" },
        },
      },
      // Perform the image lookup
      {
        $lookup: {
          from: "images",
          localField: "image",
          foreignField: "imageUrl",
          as: "empImg",
        },
      },
      {
        $unwind: {
          path: "$empImg",
          preserveNullAndEmptyArrays: true,
        },
      },
      // Final projection
      {
        $project: {
          name: 1,
          email: 1,
          phone: 1,
          image: { $ifNull: ["$empImg", null] },
          lastMessage: 1,
          lastMessageTime: 1,
          lastMessageSender: 1,
        },
      },
      // Final sort by lastMessageTime
      {
        $sort: { lastMessageTime: -1 },
      },
    ]);

    res.status(200).json(data);
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});

// // Create message populate
server.post("/concern", async (req, res) => {
  const { name, email,ConcernDate, ActualPunchIn, ActualPunchOut,message, currenDate, status, punchType,shiftType, user_id } = req.body;

  try {
    // Create a new instance of AdvisorpackageModel
    const newPackage = new ConcernModel({
      name, email,ConcernDate, ActualPunchIn, ActualPunchOut,message, currenDate, status, punchType,shiftType, user_id 
    });

    // Save the package to the database
    await newPackage.save();

    // Update the user's packages array
    await RegisteruserModal.findByIdAndUpdate(
      user_id,
      { $push: { concern: newPackage._id } },
      { new: true }
    );

    // Send a success response
    res.send("Concern Created and associated with Admin");
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});

server.get("/concern", async (req, res) => {
  try {
    const data = await ConcernModel.find();
    res.status(200).json(data);
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});

server.get("/concern/:id", async (req, res) => {
  const id = req.params.id;
  console.log("id", id);
  try {
    const data = await ConcernModel.find({ user_id: id });
    console.log("data", data);
    if (data) {
      res.status(200).json(data);
    } else {
      res.status(404).json("no data found");
    }
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});
server.get("/concernuser/:id", async (req, res) => {
  try {
    // const data = await RegisteruserModal.findById(ID).populate("callback");
    const ID = new mongoose.Types.ObjectId(req.params.id);
    console.log("id", ID);
    let data = await RegisteruserModal.aggregate([
      {
        $match: {
          _id: ID,
        },
      },
      {
        $lookup: {
          from: "concerns",
          localField: "_id",
          foreignField: "user_id",
          as: "concern",
        },
      },
    ]);
    console.log("data", data);
    // data = data[0];
    res.status(200).json(data);
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});
// Concern update by ID
server.put("/concern/:id", adminAuth, async (req, res) => {
  const ID = req.params.id;
  const { status } = req.body; // Corrected destructuring of status from req.body
  try {
    const data = await ConcernModel.findByIdAndUpdate(
      ID,
      { status },
      { new: true }
    );
    if (!data) {
      return res.status(404).send({ concern: "Concern not found" });
    }
    res.send({ concern: "Status updated successfully", data });
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});

server.put('/notifications-seen', async (req, res) => {
  try {
    // Update all notifications with Status=false to Status=true
    const updatedNotifications = await NotificationModel.updateMany(
      { Status: false }, // Find all notifications where Status is false
      { $set: { Status: true } } // Update the Status to true
    );

    res.status(200).json({ message: 'All notifications marked as seen', updatedNotifications });
  } catch (error) {
    console.error('Error updating notifications:', error);
    res.status(500).send('Internal Server Error');
  }
});
//  message All
server.get("/message", async (req, res) => {
  try {
    const data = await MessageModel.find();
    res.status(200).json(data);
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});

//  message by ID
server.get("/message/:id", async (req, res) => {
  const ID = req.params.id;
  try {
    const data = await MessageModel.findById(ID);
    res.send(data);
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});
//  message Populate by user
server.get("/message-user/:id", async (req, res) => {
  try {
    const ID = new mongoose.Types.ObjectId(req.params.id);
    const data = await MessageModel.aggregate([
      {
        $match: {
          user_id: ID,
        },
      },
    ]);
    res.status(200).json({
      message: "Chat retrieved",
      success: true,
      chatData: data,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});

// API to create or update a message
server.post("/message", async (req, res) => {
  const { name, email, message, time, senderId, date, status, user_id } =
    req.body;

  try {
    // Check if a message document with the same user_id already exists
    const existingMessage = await MessageModel.findOne({ user_id });

    if (existingMessage) {
      // Update the existing document's message array
      existingMessage.messages.push({
        senderId,
        message,
        status,
        time,
      });

      // Save the updated document
      await existingMessage.save();
      res.send("messaged successfully.");
    } else {
      // Create a new message document if it doesn't exist
      const newMessage = new MessageModel({
        name,
        email,
        message: [
          {
            userId: user_id,
            message: message,
            time: date,
          },
        ],
        date,
        status,
        user_id,
      });

      // Save the new document
      await newMessage.save();
      res.send("New message created successfully.");
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

server.post("/notifymessage", async (req, res) => {
  try {
    const { senderName, Date, status, message, senderId, receiverId } =
      req.body;
    // Save the notification in the database

    const isExist = await NotifyMessageModel.findOne({ senderId: senderId });
    if (isExist) {
    const messageData = isExist.message.push(
        message
      );
 await isExist.save()
      res.status(200)
        .json({ message: "Message Notification push to data" });
    } else {
      const savedNotification = new NotifyMessageModel({
        senderName,
        Date,
        status,
       message: [message],
        senderId,
        receiverId,
      });
      const docsData = await savedNotification.save();
      res.status(200).json({ mesage: "mesage Notified", data: docsData });
    }
  } catch (error) {
    console.log(error);
    res.status(500).send("An error occurred while sending the notification.");
  }
});

server.get('/notifymessage',async (req,res)=> {
  try{
    const data = await NotifyMessageModel.find()
    res.status(200).json({
      message:"data succesful",
      data:data
    })
  }catch(err){
    console.log(err)
    res.status(500).json(err)
  }
})


server.delete('/notifymessage', async (req, res) => {
  const { id, type } = req.query; // 'id' is the ID value, 'type' is either 'sender' or 'receiver'

  try {
    let isIdDeleted;
    if (type === 'sender') {
      isIdDeleted = await NotifyMessageModel.findOneAndDelete({ senderId: id });
    } else if (type === 'receiver') {
      isIdDeleted = await NotifyMessageModel.findOneAndDelete({ receiverId: id });
    } else {
      return res.status(400).json('Invalid type specified');
    }

    if (!isIdDeleted) {
      return res.status(404).json('Notification not found');
    }

    res.status(200).json({ message: 'Notification deleted successfully' });
  } catch (err) {
    console.log(err);
    res.status(500).json('An error occurred while deleting the notification');
  }
});


// server.delete('/notifymessage/:id', async (res, res)=> {
//   const { id } = req.params
//   try{
//    const isIdDeleted = await NotifyMessageModel.findOneAndDelete(id)
//    if(isIdDeleted) res.status(404).json('Id not found') 
//    await NotifyMessageModel.save()
//   }catch(Err){
//     console.log(Err)
//   }
// })
// API to get messages for a specific user_id
server.get("/message/:user_id", async (req, res) => {
  const { user_id } = req.params;

  try {
    // Find the message document by user_id
    const userMessages = await MessageModel.findOne({ user_id });

    if (userMessages) {
      // Return the found messages
      res.json(userMessages);
    } else {
      // If no document is found, send a 404 response
      res.status(404).send("Messages not found for this user.");
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

// notepad
server.post("/notepad", async (req, res) => {
  const { notes, user_id } = req.body;

  try {
    // Check if the user already has a notes document
    const existingNotes = await NotesModel.findOne({ user_id });

    if (!existingNotes) {
      // If no existing document, create a new one
      const newNotes = new NotesModel({
        notes,
        user_id,
      });

      // Save the new document to the database
      await newNotes.save();

      // Update the user's notes field with the new notes document ID
      await RegisteruserModal.findByIdAndUpdate(
        user_id,
        { notes: newNotes._id },
        { new: true }
      );
    } else {
      // If an existing document is found, update the notes
      existingNotes.notes = notes;
      await existingNotes.save();
    }

    // Send a success response
    res.send("Notes added/updated successfully");
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});

// Client GET account details
server.get("/notepad/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const data = await RegisteruserModal.findById(id).populate("notes");
    res.send(data);
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});

server.post(
  "/docs",
  upload.fields([
    { name: "docs", maxCount: 1 }, // { name: "Client2Photo", maxCount: 1 },
  ]),
  async (req, res) => {
    const { assigneeName, projectName, docsName } = req.body;
    console.log(req.files);
    // File paths for the uploaded files
    const docs =
      req.files["docs"] && `uploads/${req.files["docs"][0].filename}`;
    try {
      const newPackage = new DocsModel({
        assigneeName,
        projectName,
        docsName,
        docs,
        // user_id,
      });
      const docsData = await newPackage.save();

      res.send(docsData);
    } catch (error) {
      console.log(error);
      res.status(500).send("Internal Server Error");
    }
  }
);
server.get("/docs", async (req, res) => {
  try {
    const data = await DocsModel.find();
    res.send(data);
  } catch (error) {
    console.log(error);
    res.send(error);
  }
});





// count documents

server.get("/adminDashboardlength", async (req, res) => {
  try {
    const attendanceCount = await AttendanceModel.countDocuments();
    const callbackCount = await CallbackModel.countDocuments();
    const saleCount = await SaleModel.countDocuments();
    const transferCount = await TransferModel.countDocuments();
    const projectCount = await ProjectsModel.countDocuments();

    res.status(200).json({
      attendance: attendanceCount,
      callback: callbackCount,
      sale: saleCount,
      transfer: transferCount,
      project: projectCount, 
    });
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});


server.get("/employeesdashboard/:id", async (req, res) => {
  const userId = req.params.id;
  try {
    const attendanceCount = await AttendanceModel.countDocuments({ user_id: userId });
    const callbackCount = await CallbackModel.countDocuments({ user_id: userId });
    const saleCount = await SaleModel.countDocuments({ user_id: userId });
    const transferCount = await TransferModel.countDocuments({ user_id: userId });
    const projectsCount = await ProjectsModel.countDocuments({ assigneeId: userId });

    res.status(200).json({
      attendance: attendanceCount,
      callback: callbackCount,
      sale: saleCount,
      transfer: transferCount,
      project:projectsCount,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});

// SERVER
// server running

httpServer.listen(Port, async () => {
  try {
    console.log(`server running at port ${Port}`);
  } catch (error) {
    console.log(error);
  }
});

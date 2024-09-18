const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

async function sendMail(to, subject, body) {
  try {
    console.log("TO", to);
    const info = await transporter.sendMail({
      from: "Digital Mitro <digitalmitrous@gmail.com>",
      to,
      subject,
      html: body,
    });

    return info;
  } catch (err) {
    console.error(err);
    return false;
  }
}

module.exports = { transporter, sendMail };

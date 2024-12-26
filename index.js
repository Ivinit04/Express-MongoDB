require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const port = 6000;
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(cors({
  origin: '*',
  methods: '*',
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 200  // for preflight requests
}));

const key = process.env.SECRET_KEY;

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  mobile: Number,
  otpVerified: Boolean
});

const userModel = mongoose.model("User", userSchema);
const dbUrl = process.env.MONGO_URI;
mongoose.connect(dbUrl);

// Download the helper library from https://www.twilio.com/docs/node/install
// Set environment variables for your credentials
// Read more at http://twil.io/secure
const accountSid = process.env.ACCOUNT_SID;
const authToken = process.env.AUTH_TOKEN;
const verifySid = process.env.VERIFY_SID;
const client = require("twilio")(accountSid, authToken);


app.get("/", (req, res) => {
  res.send("hello");
})

app.post("/signup", async (req, res) => {
  const { name, email, password, mobile } = req.body;

  // console.log(req.body);

  try {

    const userExists = await userModel.findOne({ mobile: mobile });
    // console.log(userExists);

    if (!userExists) {

      const verification = await client.verify.v2.services(verifySid).verifications.create({
        to: `+91${mobile}`,
        channel: 'sms',
      });
      console.log(verification.status);

      const hashedPassword = await bcrypt.hash(password, 10);

      const user = new userModel({
        name: name,
        email: email,
        password: hashedPassword,
        mobile: mobile,
        otpVerified: false
      })
      user.save();

      res.status(200).json({ success: true });
    } else {
      res.status(409).json({ message: "User already exists, please login" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }

})

app.post('/verify', async (req, res) => {
  const { mobile, otp } = req.body;

  try {
    const verification_check = await client.verify.v2.services(verifySid).verificationChecks.create({
      to: `+91${mobile}`,
      code: otp
    });

    console.log(verification_check.status);

    if (verification_check.status === 'approved') {
      // OTP is valid
      await userModel.findOneAndUpdate({ mobile: mobile }, { $set: { otpVerified: true } });
      res.status(200).json({ success: true });
    } else {
      // Invalid OTP
      res.status(401).json({ error: 'Invalid OTP' });
    }
  } catch (error) {
    console.error(error);
    await userModel.findOneAndDelete({ mobile: mobile });
    res.status(500).json({ error: 'Failed to verify OTP' });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const userExists = await userModel.findOne({ email: email });

    if (!userExists) {
      res.status(401).json({ error: 'Invalid credentials' });
    }

    const passwordMatch = await bcrypt.compare(password, userExists.password);
    if (!passwordMatch) {
      res.status(401).json({ message: 'Incorrect password' });
    }

    const token = jwt.sign({ userId: userExists._id }, key);

    res.status(200).json({ token });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'User not found' });
  }
})

const verifyToken = async (req,res,next)=>{
  const token = req.headers.authorization.split(' ')[1];
  console.log(token);

  try {
    // Verify the token
    const payload = jwt.verify(token, key);

    // Attach the decoded payload to the request object 
    req.user = payload;
    next();
  } catch (error) {
    return res.status(403).json({ message: 'Failed to authenticate token' });
  }
}

app.post("/profile", verifyToken , async (req, res) => {
  console.log(req.user);
  
  const verifiedUser = await userModel.findOne({_id : req.user.userId});
  console.log(verifiedUser);

  res.status(200).json({ name: verifiedUser.name, email: verifiedUser.email, mobile: verifiedUser.mobile });
})

app.listen(port, () => {
  console.log(`server running on port ${port}`);
});
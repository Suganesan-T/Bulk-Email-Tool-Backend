const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require("bcryptjs");
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const multer = require('multer');
const csv = require('csv-parser');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const cookieParser = require('cookie-parser');


dotenv.config();

const app = express();
app.use(express.json());

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

app.use(cors({
    origin: 'https://mailware-bulk-email-tool.netlify.app',
    credentials: true
  }));

app.use(cookieParser());


mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log('Connected to MongoDB');
        // Start server
        app.listen(process.env.PORT || 3000, () => console.log(`Server running on port ${process.env.PORT || 3000}`));
    })
    .catch(err => {
        console.log('Error connecting to MongoDB', err);
    });

    const userSchema = new mongoose.Schema({
        email: { type: String, required: true, unique: true },
        password: { type: String, required: true },
        firstname: { type: String, required: true },
        lastname: { type: String, required: true },
        resetPasswordToken: { type: String, default: '' },
        resetPasswordExpires: { type: Date, default: Date.now },
        loginToken: { type: String, default: '' }
    });
const recipientSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true }
});

const campaignSchema = new mongoose.Schema({
    campaignName: { type: String, required: true, unique: true },
    emailsSent: { type: Number, default: 0 },
    emailsReceived: { type: Number, default: 0 }
});

const User = mongoose.model('User', userSchema);
const Recipient = mongoose.model('Recipient', recipientSchema);
const Campaign = mongoose.model('Campaign', campaignSchema);

const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: process.env.EMAIL,
        pass: process.env.PASSWORD
    }
});

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ storage: storage });

app.post('/upload', upload.single('file'), async (req, res) => {
    try {
        const { from, subject, text } = req.body;
        const recipients = [];

        fs.createReadStream(req.file.path)
            .pipe(csv())
            .on('data', (row) => {
                recipients.push(row.email);
            })
            .on('end', async () => {
                await sendBulkEmails(from, recipients, subject, text);
                await clearRecipients();
                res.status(200).send('Emails sent successfully and recipients cleared.');
            });
    } catch (error) {
        res.status(500).send('Error processing file');
    }
});


app.post('/signup', async (req, res) => {
    try {
        const { firstname, lastname, email, password } = req.body;

        console.log('Signup request received:', req.body);

        // Validate input
        if (!firstname || !lastname || !email || !password) {
            return res.status(400).send({ message: "Firstname, Lastname, Email, and Password are required" });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).send({ message: "User already exists, continue to login" });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        console.log('Hashed password:', hashedPassword);

        // Create user
        const user = new User({ firstname, lastname, email, password: hashedPassword });

        // Save user
        await user.save();
        console.log('User saved:', user);

        res.status(201).send({ message: "Registered Successfully" });
    } catch (error) {
        console.error('Error during signup:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/signin', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate input
        if (!email || !password) {
            return res.status(400).send({message:'Email and password are required'});
        }

        const user = await User.findOne({ email });
        if (!user) return res.status(400).send({message:'User not found'});

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).send({message:'Invalid password'});

        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '168h' });
        res.cookie("token", token, {
            httpOnly: true,
            secure: true,
            sameSite: "none",
            expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7) //set the cookie to expire in 7 days
        })

        //save token to database
        user.loginToken = token;
        await user.save();
        console.log('User saved:', user);


        res.status(200).send({ message: 'Login successful' });
    } catch (error) {
        console.error({message:'Error during signin:'}, error);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/forgetpassword', async (req, res) => {
    try {
        const { email } = req.body;

        // Validate input
        if (!email) {
            return res.status(400).send({message:'Email is required'});
        }

        const user = await User.findOne({ email });
        if (!user) return res.status(400).send({message:'User not found'});

        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
        await user.save();

        const mailOptions = {
            to: user.email,
            from: process.env.EMAIL,
            subject: 'Password Reset',
            text: `Please click on the following link to reset your password: https://bulk-email-tool-backend-moat.onrender.com/resetpassword/${token}`
        };

        await transporter.sendMail(mailOptions);
        res.status(200).send({message:'Reset Password link is sent to your email'});
    } catch (error) {
        console.error('Error during forget password:', error);
        res.status(500).send({message:'Internal Server Error'});
    }
});

app.post('/resetpassword/:token', async (req, res) => {
    try {
        const { token } = req.params;
        const { password } = req.body;

        // Validate input
        if (!password) {
            return res.status(400).send({message:'Password is required'});
        }

        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });
        if (!user) return res.status(400).send({message:'Invalid link or link has been expired'});

        const hashedPassword = await bcrypt.hash(password, 10);
        user.password = hashedPassword;
        user.resetPasswordToken = '';
        user.resetPasswordExpires = Date.now();
        await user.save();
        res.status(200).send({message:'Password reset successful'});
    } catch (error) {
        console.error({message:'Error during reset password:', error});
        res.status(500).send({message:'Internal Server Error'});
    }
});

app.get('/logout', async (req, res) => {
    try {
        const token = req.cookies.token;
        if (!token) return res.status(401).send({ message: 'Unauthorized1' });

        const user = await User.findOne({ loginToken: token });
        if (!user) return res.status(401).send({ message: 'Unauthorized2' });

        user.loginToken = '';
        await user.save();

        res.clearCookie('token');
        res.status(200).send({ message: 'Logged out successfully' });
    } catch (error) {
        console.error('Error during logout:', error);
        res.status(500).send({ message: 'Internal Server Error' });
    }
});
//get current user
app.get('/user', async (req, res) => {
    try {
        const token = req.cookies.token;
        if (!token) return res.status(401).send({ message: 'Unauthorized1' });

        const user = await User.findOne({ loginToken: token });
        if (!user) return res.status(401).send({ message: 'Unauthorized2' });

        res.status(200).send({ user });
    } catch (error) {
        console.error('Error getting current user:', error);
        res.status(500).send({ message: 'Internal Server Error' });
    }
});

const sendBulkEmails = async (from, emails, subject, text, attachments = []) => {
    const emailPromises = emails.map(email => {
        const mailOptions = {
            from,
            to: email,
            subject,
            text,
            html: text,
            attachments
        };
        return transporter.sendMail(mailOptions);
    });

    await Promise.all(emailPromises);
};

const clearRecipients = async () => {
    try {
        await Recipient.deleteMany({});
    } catch (error) {
        console.error('Error clearing recipients:', error);
    }
};

app.post('/send-emails', upload.fields([{ name: 'file' }, { name: 'attachments' }]), async (req, res) => {
    try {
        const { from, emails, subject, text } = req.body;
        const attachments = req.files.attachments ? req.files.attachments.map(file => ({
            filename: file.originalname,
            path: file.path
        })) : [];

        if (req.files.file) {
            // Handle CSV file upload
            const recipients = [];
            fs.createReadStream(req.files.file[0].path)
                .pipe(csv())
                .on('data', (row) => {
                    recipients.push(row.email);
                })
                .on('end', async () => {
                    await sendBulkEmails(from, recipients, subject, text, attachments);
                    await clearRecipients();
                    res.status(200).send({ message: 'Emails Sent Successfully' });
                });
        } else {
            // Handle direct email input
            const emailList = emails.split(',').map(email => email.trim());
            await sendBulkEmails(from, emailList, subject, text, attachments);
            res.status(200).send({ message: 'Emails Sent Successfully' });
        }
    } catch (error) {
        res.status(500).send({ message: 'Error Sending Emails' });
    }
});



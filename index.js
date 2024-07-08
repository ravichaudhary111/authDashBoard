const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const authRoutes = require('./route/auth.route');
const cookieParser= require("cookie-parser");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.use(express.urlencoded({extended:true}));
app.use(cookieParser())
app.use('/api/auth', authRoutes);

const DBURL = process.env.DBURL;

mongoose.connect(DBURL).then(() => {
    console.log('Connected to MongoDB');
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
}).catch(err => console.error('Error connecting to MongoDB', err));

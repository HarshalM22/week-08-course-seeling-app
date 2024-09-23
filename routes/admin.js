const { Router } = require("express");
const adminRouter = Router();
const { adminModel, courseModel } = require("../db");
const jwt = require("jsonwebtoken");
// brcypt, zod, jsonwebtoken
const  { JWT_ADMIN_PASSWORD } = require("../config");
const { adminMiddleware } = require("../middleware/admin");
const bcrypt = require('bcrypt');
const {z} = require('zod')

adminRouter.post("/signup", async function(req, res) {
    const requiredvalidation = z.object({
        email : z.string().min(5).max(40).email(),
        password : z.string().min(8).max(32) 
    })
    const { email, password, firstName, lastName } = req.body; // TODO: adding zod validation
    // TODO: hash the password so plaintext pw is not stored in the DB
    const hashedpassword = await bcrypt.hash(password,5);
    // TODO: Put inside a try catch block
    await adminModel.create({
        email: email,
        password: hashedpassword,
        firstName: firstName, 
        lastName: lastName
    })
    
    res.json({
        message: "Signup succeeded"
    })
})

adminRouter.post("/signin", async function(req, res) {
    const { email, password} = req.body;

    // TODO: ideally password should be hashed, and hence you cant compare the user provided password and the database password
    const admin = await adminModel.findOne({
        email: email
    });

   if(admin){
    const verifyAdmin = await bcrypt.compare(password,admin.password);
    if(verifyAdmin){
        const token = jwt.sign({
            id : admin._id.toString()
        },JWT_ADMIN_PASSWORD);

        res.json({
            token : token
        })
    }else{
        res.status(403).json({
            message :"password doesn't match with the email id you have entered"
        })
    }
   }else{
    res.status(403).json({
        message: "wrong credentials"
    })
   }
})

adminRouter.post("/course", adminMiddleware, async function(req, res) {
    const adminId = req.userId;

    const { title, description, imageUrl, price } = req.body;

   
    const course = await courseModel.create({
        title: title, 
        description: description, 
        imageUrl: imageUrl, 
        price: price, 
        creatorId: adminId
    })

    res.json({
        message: "Course created",
        courseId: course._id
    })
})

adminRouter.put("/course", adminMiddleware, async function(req, res) {
    const adminId = req.userId;

    const { title, description, imageUrl, price, courseId } = req.body;

    
    const course = await courseModel.findOne({
        _id: courseId, 
        creatorId: adminId 
    }, 
    {
        title: title, 
        description: description, 
        imageUrl: imageUrl, 
        price: price
    })
    res.json({
        message: "Course updated",
        courseId: courseId
    })
})

adminRouter.get("/course/bulk", adminMiddleware,async function(req, res) {
    const adminId = req.userId;

    const courses = await courseModel.find({
        creatorId: adminId 
    });

    res.json({
        message: "Course updated",
        courses
    })
})

module.exports = {
    adminRouter: adminRouter
}
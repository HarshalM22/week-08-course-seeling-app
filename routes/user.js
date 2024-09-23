const { Router } = require("express");
const { userModel, purchaseModel, courseModel } = require("../db");
const jwt = require("jsonwebtoken");
const { JWT_USER_PASSWORD } = require("../config");
const { userMiddleware } = require("../middleware/user");
const bcrypt = require("bcrypt");
const { z } = require('zod')

const userRouter = Router();

userRouter.post("/signup", async function (req, res) {
     // TODO: adding zod validation
    const requiredValidationForUser = z.object({
        email: z.string().min(5).max(40).email(),
        password: z.string().min(8).max(32)
    })

    const { email, password, firstName, lastName } = req.body;
    // TODO: hash the password so plaintext pw is not stored in the DB
    const hashedPassword = await bcrypt.hash(password, 5);
    // console.log(hashedPassword);

    // TODO: Put inside a try catch block
    try {
        await userModel.create({
            email: email,
            password: hashedPassword,
            firstName: firstName,
            lastName: lastName,
        });

        res.json({
            message: "Signup succeeded",
        });
    } catch (e) {
        console.error(e);
    }
})

userRouter.post("/signin", async function (req, res) {
    const { email, password } = req.body;

    // TODO: ideally password should be hashed, and hence you cant compare the user provided password and the database password
    const user = await userModel.findOne({
        email: email
    }); //[]

    if (user) {
        const verify = await bcrypt.compare(password, user.password);
        if (verify) {
            const token = jwt.sign(
                {
                    id: user._id.toString(),
                },
                JWT_USER_PASSWORD
            );
            // Do cookie logic

            res.json({
                token: token,
            });
        } else {
            res.status(403).json({
                message: "Incorrect credentials",
            });
        }
    } else {
        res.status(403).json({
            message: "Incorrect credentials",
        });
    }
});

userRouter.get("/purchases", userMiddleware, async function (req, res) {
    const userId = req.userId;

    const purchases = await purchaseModel.find({
        userId,
    });

    let purchasedCourseIds = [];

    for (let i = 0; i < purchases.length; i++) {
        purchasedCourseIds.push(purchases[i].courseId);
    }

    const coursesData = await courseModel.find({
        _id: { $in: purchasedCourseIds },
    });

    res.json({
        purchases,
        coursesData,
    });
});

module.exports = {
    userRouter: userRouter,
};

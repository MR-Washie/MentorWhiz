import User from "../models/user.model.js";
import bcrypt from "bcryptjs";  
import { generateToken } from "../lib/utilis.js";

export const signup = async (req, res) => {
    const {fullName, userName, email, password, confirmPassword } = req.body;
  try {
    if(password.length < 6) {
        return res.status(400).json({ message: "Password should be at least 6 characters long" });
    }
    if(!email || !fullName || !password || !userName || !confirmPassword) {
        return res.status(400).json({ message: "Please fill all the fields" });
    }

    const user = await User.findOne({ email,userName });
    if (user) {
      return res.status(400).json({ message: "User already exists" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(password,salt)

    const newUser = new User({
        fullName,
        userName,
        email,   
        password: hashPassword,
        confirmPassword: hashPassword,
    })

    if(newUser) {
        // generate jwt token
        generateToken(newUser._id, res);
        await newUser.save();

        res.status(201).json({
            _id: newUser._id,
            email: newUser.email,
            fullName: newUser.fullName,
            userName: newUser.userName,
        });
        
    } else {
        return res.status(400).json({ message: "Invalid user data" });
    }
    
  } catch (error) {
    console.log("Error in signup controller", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
};

export const login = async (req, res) => {
    const { email, password } = req.body;
    try {
      const user = await User.findOne({ email,userName });
  
      if (!user) {
        return res.status(400).json({ message: "User Not found" });
      }
  
      const isPasswordCorrect = await bcrypt.compare(password, user.password);
      if (!isPasswordCorrect) {
        return res.status(400).json({ message: "Password Incorrect" });
      }
  
      generateToken(user._id, res);
  
      res.status(200).json({
        _id: user._id,
        fullName: user.fullName,
        email: user.email,
      });

      
    } catch (error) {
      console.log("Error in login controller", error.message);
      res.status(500).json({ message: "Internal Server Error" });
    }
  };

export const logout = (req, res) => {
    try {
        res.cookie("jwt", "", {maxAge: 0});
        res.status(200).json({message: "Loggout out successfully!"});
    } catch (error) {
        console.log("Error in logout controller", error.message);
        res.status(500).json({ message: "Internal server error" });
        
    }
};





export const checkAuth = (req, res) => {
    try {
       res.status(200).json(req.user);
    } catch (error) {
        console.log("Error in checkAuth controller", error.message);
        res.status(500).json({ message: "Internal server error" });
    }
}
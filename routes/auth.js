const router=require('express').Router();
const User=require("../models/User");

const bcrypt = require('bcryptjs');

const jwt=require('jsonwebtoken');


//Register

router.post("/register", async (req,res)=>{
  

       const body=req.body

       if (!(body.email && body.password && body.username)) {

        return res.status(400).send({ error: "Data not formatted properly" });
      }
   
      const salt = await bcrypt.genSalt(10);

    const newUser=new User({


        username:body.username,
        email:req.body.email,
        password:await bcrypt.hash(body.password, salt),
    })


    try{
     const savedUser= await newUser.save()
   
        res.status(201).json(savedUser);

    }

    catch(err){

          res.status(500).json(err);


    }
})

//LOGIN

router.post('/login',async(req,res)=>{
            
     const body=req.body
    if (!(body.username && body.password)) {
        return res.status(400).send({ error: "Data not formatted properly" });
      }
        try{

            const user=await User.findOne({username:body.username});

             
  

      if (user) {

        // check user password with hashed password stored in the database

        const validPassword = await bcrypt.compare(body.password, user.password);
        
      
        if (validPassword) {

               const accessToken= jwt.sign({
                   
                 id:user._id,
                 isAdmin:user.isAdmin,


               },process.env.JWT_SECRET_KEY,

                 {expiresIn:"3d"}

               
               );


          const{password, ...others}=user._doc

          res.status(200).json({...others,accessToken});
        } 
        
        
        else {
          res.status(400).json({ error: "Invalid Password" });
        }
      } 
      
      
      else {
        res.status(401).json({ error: "User does not exist" });
      }
  

            

        }

        catch(err){
          
            res.status(500).json(err)
        }
})

module.exports=router
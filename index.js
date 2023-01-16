const express=require("express")
const cors=require("cors")
const app=express();

const mongoose=require("mongoose")

const dotenv=require("dotenv")

const userRoute=require("./routes/user")

const authRoute=require('./routes/auth')

const productsRoute=require("./routes/product")
const cartRoute=require("./routes/cart")
const orderRoute=require("./routes/order")
const stripeRoute=require("./routes/stripe")




 dotenv.config() 

mongoose.connect(process.env.MONGO_URL).then(()=>


console.log("DBCONNECTION Successfull!")).catch((err)=>

{

 console.log(err);
})


app.use(cors())
app.use(express.json());



//Routes
app.use("/api/auth",authRoute);

app.use("/api/user",userRoute);

app.use("/api/products",productsRoute);
app.use("/api/cart",cartRoute);
app.use("/api/order",orderRoute);
app.use("/api/checkout",stripeRoute);
app.listen(3003 ,()=>{

  
      console.log("backend server is running");
})
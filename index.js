import express from 'express';
import cors from 'cors';
import pg from 'pg';
import bcrypt from 'bcrypt';
import env from 'dotenv';
import passport from 'passport';
import session from 'express-session';
import { Strategy } from 'passport-local';

const app = express();
const port = 8081;
const saltRounds = 10;
env.config();

const db = new pg.Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT
});
db.connect();

app.use(express.json());
app.use(cors({
  origin: process.env.CORS_ORIGIN,
  methods: "GET,POST,PUT,DELETE",
  credentials: true
}));
  

app.use(session({
   secret:process.env.SESSION_SECRET,
   resave:false,
   saveUninitialized:true
}));

app.use(passport.initialize());
app.use(passport.session());

passport.use(
  new Strategy(
    { usernameField: "email", passwordField: "password" },
    
    async function verify(email,password,done) {
  
  try
  {
    const result = await db.query("SELECT * FROM users WHERE email = $1",[
      email
    ]);
    //console.log(result);
    //if the user not found in the database
    if(result.rows.length === 0){
      return done(null,false);
    }

    const user = result.rows[0];
    //console.log(user);
    const isMatch = await bcrypt.compare(password,user.password);

    //if user found in database, but password does not match
    if(!isMatch){
      return done(null,false);
    }

    //if user found in database and password match
    return done(null,user);

   }
   catch(err){
    return done(err);
   }
}
));

passport.serializeUser((user,done)=>{
  //console.log(user);
  done(null,user);
});

passport.deserializeUser((user,done) => {
  done(null,user);
});

app.post("/signup", async (req, res) => {
   console.log(req.body);
   const name = req.body.name;
   const email = req.body.email;
 
   try {
     const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
       email,
     ]);
 
     if (checkResult.rows.length > 0) 
      {
       res.json({Status:"Already a user"});
      } 
     else 
     {
       bcrypt.hash(req.body.password.toString(), saltRounds, async (err, hash) => {

         if (err) {
           return res.json({error:"Error in hashing the password"});
         } 

         else {
           const result = await db.query(
             "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *",
             [name, email, hash]
           );
           return res.json({Status:"Success"});
         }
       });
     }
   } catch (err) {
     return res.json({error:err.message});
   }
 });


app.post("/signin",passport.authenticate('local',{
  successRedirect:"/dash",
  failureRedirect:"/fail"
}));

app.get("/dash",(req,res) => {
    return res.json({message:"Login successful",datas:req.user});
});
app.get("/fail",(req,res) => {
    return res.json({message:"Login failed"});
});
 

app.get("/dashboard",(req,res) => {
  console.log("hi from dashoard");
  console.log(req.isAuthenticated());
  if(req.isAuthenticated()){
    res.json({message:"Authorised",user: req.user});
  }
  else{
    res.json({message:"Unauthorised"});
  }
})

app.get("/login/success",async(req,res)=>{
    if(req.user){
      res.json({message:"user logged in",user:req.user});
    }
    else{
      res.json({message: "Not authorised"});
    }
});

app.get("/profile",(req,res)=>{
  console.log("hello from profile");
  console.log(req.isAuthenticated());
   if(req.isAuthenticated()){
    res.json({message:"Authorised",datas:req.user});
   }
   else{
    res.json({message:"Unauthorised"});
   }
});

app.delete("/logout",(req,res) => {
    req.logOut((err) => {
      if(err){
        return res.json({message:"Logout failed"});
      }
      return res.json({message:"Logged out successfully"});
    });
});

app.listen(port, (req,res) => {
   console.log(`Server is running on port ${port}`);
});
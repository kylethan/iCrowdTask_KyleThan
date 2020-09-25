const express = require("express")
const mongoose = require("mongoose")
var bcrypt = require('bcrypt');
const saltRounds = 10;
const https = require("https")
const path = require("path");
const Register = require("./model/Register");
mongoose.connect("mongodb+srv://boykay110598:kylethan1105@cluster0.3fpxl.mongodb.net/iCrowdTask1?retryWrites=true&w=majority",
{useNewUrlParser: true, useUnifiedTopology: true });
const bodyParser = require("body-parser")
const app = express()
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const keys = require("./config/keys");
const session = require("express-session");
const cookieSession = require("cookie-session");
var crypto = require("crypto");
var LocalStrategy = require('passport-local').Strategy;
var nodemailer = require("nodemailer");
mongoose.set('useFindAndModify', false); 

const publicDirectoryPath = path.join(__dirname);
app.set("view engine", "hbs");
app.use(express.static(publicDirectoryPath));
app.use(
  session({
    resave: true,
    saveUninitialized: true,
    secret: "$$$DeakinSecret",
  })
);
app.use(passport.initialize());
app.use(passport.session());

passport.use(Register.createStrategy());

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  Register.findById(id, function (err, user) {
    done(err, user);
  });
});

passport.use(
    new GoogleStrategy(
        {
            clientID: keys.google.clientID,
            clientSecret: keys.google.clientSecret,
            callbackURL: "http://kyleicrowdtask.herokuapp.com/auth/google/redirect"
        }, (accessToken, refreshToken, profile, done) => {
            // passport callback function
            //check if user already exists in our db with the given profile ID
            Register.findOne({googleId: profile.id}).then((currentUser)=>{
              if(currentUser){
                //if we already have a record with the given profile ID
                done(null, currentUser);
              } else{
                   //if not, create a new user 
                  new Register({
                    googleId: profile.id,
                    countries: "Australia",
                    fname: profile.displayName,
                    lname: profile.displayName,
                    email: "name@example.com",
                    password: "hashPassword",
                    address: "address",
                    city: "Melbourne",
                    state: "state",
                    zip: "zip",
                    mobile: "0405693269",
                    password_token: null,
                  }).save().then((newUser) =>{
                    done(null, newUser);
                  });
               } 
            })
        }   
    )
);

passport.use(
  new LocalStrategy(
    { usernameField: "email", passwordField: "password" },
    (email, password, done) => {
      Register.findOne({ email: email }, async function (err, user) {
        if (err) {
          return done(err);
        }
        if (!user) {
          return done(null, false);
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
          return done(null, false);
        } else {
          return done(null, user);
        }
      });
    }
  )
);


app.use(bodyParser.urlencoded({extended:true}))
app.use(express.static("public"))
app.use(express.static(__dirname));

app.get("/auth/google", passport.authenticate("google", {
    scope: ["profile", "email"]
}));

app.get("/auth/google/redirect",passport.authenticate("google"),(req,res)=>{
    res.sendFile(__dirname + "/reqtask.html");
});
app.post(
  "/signin",
  passport.authenticate("local", {
    successRedirect: "/success",
    failureRedirect: "/",
  })
);
app.get("/success", (req, res) => {
  if (req.isAuthenticated()) {
    res.sendFile(__dirname + "/reqtask.html");
  } else {
    res.redirect("/");
  }
});

app.get('/', (req,res)=>{
    res.sendFile(__dirname + "/index.html")
})

app.get("/signin", (req, res) => {
    res.sendFile(__dirname + "/reqsignup.html");
});

app.get("/forget", (req, res) => {
    res.sendFile(__dirname + "/forget.html");
});

app.get("/reset/:token", (req, res) => {
    Register.findOne({ password_token: req.params.token }, (err, user) => {
      if (!user) {
        return res.send("Invalid link, we can not find the user");
      }
  
      res.render("reset", {
        token: req.params.token,
      });
    });
});

var transporter = nodemailer.createTransport({
    service: "gmail",
    port: 465,
    secure: true,
    auth: {
      user: "thantqkhai@gmail.com",
      pass: "kylethan1105",
    },
    tls: {
      // do not fail on invalid certs
      rejectUnauthorized: true,
    },
});

app.post("/forget", async function (req, res) {
    const email = req.body.email;
    Register.findOne({ email: email }, async (err, user) => {
      if (err) {
        return res.send("<h1>err</h1>");
      } else {
        if (user == null) {
          return res.redirect("/forget");
        }
        var token = crypto.randomBytes(20).toString("hex");
        Register.findOneAndUpdate(
          { email: email },
          { password_token: token },
          (err) => {
            if (err) {
              return res.send(err);
            }
            var mailOptions = {
              to: email,
              from: "thantqkhai@gmail.com",
              subject: "iCrowdTask Password Reset",
              text:
                "Follow the link to reset your password. \n \n" +
                "http://" +
                req.headers.host +
                "/reset/" +
                token,
            };
  
            transporter.sendMail(mailOptions, (error, info) => {
              if (error) {
                console.log(error);
                var k;
                // return res.sendFile(__dirname + "/404.html");
                return res.send(error);
              } else {
                console.log("Email sent: " + info.response);
                return res.send("Check you email to reset new password");
              }
            });
          }
        );
  
        console.log(token);
      }
    });
});
app.post("/reset", (req, res) => {
  const password = req.body.password;
  const cpassword = req.body.cpassword;
  const token = req.body.token;
  const hashPassword = bcrypt.hashSync(password, saltRounds);

  console.log(token);
  try {
    if (password != cpassword) {
      return res.send("<h3> password does not match </h3>");
    }

    Register.findOneAndUpdate(
      { password_token: token },
      { password: hashPassword },
      (err, user) => {
        if (err) {
          return res.send(err);
        }
        if (!user) {
          return res.send("Invalid users");
        }

        return res.redirect("/");
      }
    );
  } catch (error) {
    res.status(500).send(error);
  }
});



app.post('/signup', (req,res)=>{
    const countries = req.body.countries
    const firstname = req.body.firstname
    const lastname = req.body.lastname
    const email = req.body.email
    const password = req.body.password
    const cpassword = req.body.cpassword
    const passwordhash= bcrypt.hashSync(password, saltRounds);
    const cpasswordhash= bcrypt.hashSync(cpassword, saltRounds);
    const address = req.body.address1 + req.body.address2
    const city = req.body.city
    const state = req.body.state
    const zip = req.body.zip
    const phone = req.body.phone
    const data = {
        members:[{
            email_address: email,
            status : "subscribed",
            merge_fields: {
                FNAME: firstname,
                LNAME: lastname
        }
        }]
        
    }
    jsonData = JSON.stringify(data)
    const url ="https://us17.api.mailchimp.com/3.0/lists/9452615ce5"
    const options = {
        method:"POST",
        auth:"kyle:6880642d805d51a4db59c02b6b7791b8-us17"
    }

    const request = https.request(url, options, (response)=>{
        response.on("data", (data)=>{
            console.log(JSON.parse(data))
        })
    })

    const register = new Register({
        googleId: "empty",
        countries: countries,
        fname: firstname,
        lname: lastname,
        email: email,
        password: passwordhash,
        address: address,
        city: city,
        state: state,
        zip: zip,
        mobile: phone,
        password_token: null,
    })
    
    try {
        if (password != cpassword) {
          return res.send("<h2> Password does not match! Please try again!</h2>");
        }
        register
          .save()
          .then((register) => {
            if (res.statusCode === 200) {
                res.sendFile(__dirname + "/index.html")
                request.write(jsonData),
                request.end()
            } else {
                res.send('Register failed');
                
            }
          })
          .catch((err) => {
            res.send("<h3>" + err + "</h3>");
          });
    } catch (error) {
        res.statusCode(500).send(err);
    };
})

app
.route("/workers")
.post((req, res) => {
    const workers = Register(req.body);
    workers
        .save()
        .then(() => {
        res.send(workers);
        })
        .catch((err) => {
        res.status(400).send(err);
        });
    })
.get((req, res) => {
    Register.find((err, workers) => {
        if (!err) {
        res.send(workers);
        } else {
        res.send(err);
        }
    });
})

.delete((req, res) => {
    Register.deleteMany((err) => {
        if (err) {
        return res.send(err);
        }
        res.send("Deleted all workers");
    });
});

app
.route("/workers/:id")
.get((req, res) => {
    Register.findById(req.params.id)
        .then((worker) => {
        if (!worker) {
            return res.status(404).send();
        }
        res.send(worker);
        })
        .catch((e) => {
        res.send(e);
    });
})

.patch((req, res) => {
    Register.findByIdAndUpdate(
        req.params.id,{ address: req.body.address, mobile: req.body.mobile, password: req.body.password }, (err) => {
        if (err) {
            return res.send(err);
        } else {
            res.send("Successfully Updated address, mobile number and password");
        }
        }
    );
})

.put((req, res) => {
    Register.findByIdAndUpdate(req.params.id, req.body, (err) => {
        if (err) {
        return res.send(err);
        }
        res.send("Successfully Updated");
    });
})

.delete((req, res) => {
    Register.findByIdAndDelete(req.params.id, (err) => {
        if (err) {
        return res.send(err);
        }
        res.send("Deleted Successfully");
    });
});

let port = process.env.PORT;
if (port == null || port == "") {
  port = 8080;
}


app.listen(port, (req,res)=>{
    console.log("Server is running successfully")
}) 
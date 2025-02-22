import express from 'express'
import bodyParser from 'body-parser';
import axios from 'axios';
import { fileURLToPath } from 'url';
import { dirname,join } from 'path';
import path from 'path'
import pkg from 'pg'
import crypto from 'crypto'
import env from "dotenv";
// import cors from 'cors';
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import session from "express-session";
const { Pool } = pkg
const app=express();
const port=process.env.BD_PORT || 5000;
// console.log(port);


const saltRounds=process.env.SALT_ROUND || 20;
// console.log('The salt round is',saltRounds);

env.config();


const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);


app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
console.log(process.env.NODE_ENV)
if(process.env.NODE_ENV ==='production'){
    app.use(express.static(join(__dirname, '/dist')));
}



app.use(express.static('public'));
app.use(
    session({
        secret:"Bloggerlucky43",
        resave: false,
        saveUninitialized: true,
    })
)


// app.use(cors({
//     origin: '*',
//     methods: ['GET', 'POST','PATCH'],
//     credentials: true // If you're sending cookies or authentication headers
// }));


app.use(passport.initialize());
app.use(passport.session());


const pool=new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
      rejectUnauthorized: false, // Disable certificate verification (for testing)
    },
});


pool.connect((err) => {
    if (err) {
    console.error('Error connecting to PostgreSQL:', err.stack);
    } else {
    console.log('Connected to PostgreSQL');
    }
});



app.post('/register',async(req,res)=>{
    const email=req.body.email.trim().toLowerCase();
    const password=req.body.password.trim();
    const telephone=req.body.phoneNumber
    const fullname=req.body.fullName.trim().toLowerCase();
    const username=req.body.userName.trim().toLowerCase();
    const referrer=req.body.referrer
    console.log(referrer,'referrer code is');
    const referreeFunds=0;


        // console.log(email,fullname,password,username)
    try {
        const checkResult=await pool.query('SELECT * FROM users WHERE username=$1',[username]);
        console.log('Database queried successfully')
        if(checkResult.rows.length > 0){
            console.log('user is registered');
            return res.redirect('/login');
        }
        // console.log('Now at hashing the password')
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        // console.log('hashing the password')
      
     
        // console.log('The hashed password is',hashedPassword);

        if(referrer){
            const referrees=await pool.query('INSERT INTO referral (referrerusername,referreeusername,referreefunds) VALUES ($1,$2,$3) RETURNING *',[referrer,username,referreeFunds]);
            const referers=referrees.rows[0];
            // console.log(referers);
            
        }
        const result=await pool.query('INSERT INTO users (email,password,telephone,fullname,username) VALUES ($1,$2,$3,$4,$5) RETURNING *',[email,hashedPassword,telephone,fullname,username])
        const user = result.rows[0];
        // console.log(user)
        res.status(200).json({ user: user, message:'Successfully registered'})
    } catch (error) {
        console.error('Error querying database',error)
    }
});

app.post("/logout", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.json({ success: true, message: "Logged out successfully." });
  });
});


app.post('/login', (req, res, next) => {
    // console.log(req.body,'received to the backend');
  passport.authenticate('local', (err, user, info) => {
    // console.log('Inside passport.authenticate');
    if (err) {
      console.error('Error during authentication:', err);
      return res.status(500).json({ message: 'An error occurred during login' });
    }
    if (!user) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }
    req.logIn(user, (err) => {
      if (err) {
        console.error('Error logging in user:', err);
        return next(err);
      }
     
      // Successfully logged in
      return res.status(200).json({ message: 'Login successful', user });
    });
  })(req, res, next);
});


app.post('/topdata',async(req,res)=>{
  const {network,dataPlan,mobileNumber,userId}=req.body;
  console.log(req.body);
  if(!network || !dataPlan || !mobileNumber || !userId){
    return res.status(400).json({message:'All fields are required'})
  }

  try {
    const network_id=Number(network);
    if(isNaN(network_id)){
      return res.status(400).json({ error: 'Invalid Network Id'})
    }
    console.log(network_id);

    const dataType={
      network: network_id,
      mobile_number : mobileNumber,
      plan: dataPlan,
      Ported_number: true
    }
    // console.log(dataType);
    const api_key=process.env.SMOOTSELL_API_KEY
  
    
    const response=await axios.post(`https://smoothsell.com.ng/api/data/`,JSON.stringify(dataType),
    {
      headers:{
        Authorization: `Token ${api_key}`,
        "Content-Type": "application/json"
      }
    },
    );
    if(response.status !== 200){
      console.error("API request failed:", response.data)
      return res.status(500).json({ error: "Failed to process top-up request" });
    }

    
    try {
      const transactionReference = `REF-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
      var notePad= `${dataPlan} has been sent to ${mobileNumber}`
      console.log(notePad);
      
      await pool.query('INSERT INTO transactions (userid,note,transactionreference) VALUES($1,$2,$3)',[userId,notePad,transactionReference])
      
      console.log('Successful');
      return res.status(200).json({ message: 'Successful' });
      
    } catch (error) {
      console.error("Error:", error.response?.data || error.message);
      return res.status(500).json({ error: 'An error occurred during top-up' });
    }


  } catch (error) {
     res.status(500).json({error:'An error occured during top up'})
     console.error("Error Response:", error.response?.data || error.message)
  }
  
})


app.get('/get-balance/:userIDD',async(req,res)=>{
  const {userIDD}=req.params;
  const user_id = parseInt(userIDD, 10); // Convert userId to integer
  console.log(user_id,'The useridd at getbalance');
  
  try {
    const result=await pool.query('SELECT * FROM users WHERE id=$1',[user_id])
    if(result.rows.length > 0){
      res.status(200).json({balance:result.rows[0].wallet, accountReference: result.rows[0].accountreference})
      // console.log(result.rows[0].wallet,result.rows[0].accountreference);
      
    }else{
      res.status(404).json({message: 'User not found'})
    }
  } catch (error) {
    console.error('error querying database',error) 
  }
});

app.get('/get-summary/:userName',async(req,res)=>{
  const {userName}=req.params;
  // console.log(userName,'The username at getsummary');
  try {
    const response=await pool.query('SELECT * FROM summary WHERE username=$1',[userName])
    if(response.rows.length >0){
      res.status(200).json({summary:response.rows})
      // console.log(response.rows)
    }
  } catch (error) {
    console.error('Error getting the summary',error)
  }
  
})

app.get('/referrals/:userName', async (req, res) => {3
  const { userName } = req.params;
  // console.log(userName);
  
  try {
      const referrals = await pool.query(
          'SELECT referreeusername, referreeFunds FROM referral WHERE referrerusername=$1',
          [userName]
      );

      if (referrals.rows.length === 0) {
          return res.status(404).json({ message: "No referrals found" });
      }

      res.status(200).json({ referrals: referrals.rows });
      // console.log(referrals.rows);
      
  } catch (error) {
      console.error("Error fetching referrals", error);
      res.status(500).json({ message: "Server error" });
  }
});


app.post('/update', async (req, res) => {
    const { balance, userIDD } = req.body;
    console.log("Received balance update request:", req.body);

    if (!userIDD || balance === undefined || balance === null) {
        return res.status(400).json({ error: "Missing required fields" });
    }

    try {
        const result = await pool.query(
            "UPDATE users SET wallet = $1 WHERE id = $2 RETURNING wallet",
            [balance, userIDD]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "User not found" });
        }

        console.log("Updated wallet balance:", result.rows[0].wallet);
        return res.status(200).json({ balance: result.rows[0].wallet });

    } catch (error) {
        console.error("Error updating the database wallet balance:", error.message);
        return res.status(500).json({ error: "Internal server error" });
    }
});

app.post('/topairtime', async (req, res) => {
  const { network, airtimeType, mobileNumber, amount, topay, userId } = req.body;
  console.log("Received userId:", userId,network,airtimeType,mobileNumber,amount,topay);

  if (!network || !airtimeType || !mobileNumber || !amount || !topay || !userId) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const network_id = parseInt(network, 10); // Convert to integer
    const user_id = parseInt(userId, 10); // Convert userId to integer

    if (isNaN(user_id)) {
      throw new Error("Invalid user ID format. It must be an integer.");
    }

    const airtimeData = {
      network: network_id,
      amount: amount,
      mobile_number: mobileNumber,
      Ported_number: true,
      airtime_type: airtimeType
    };

    const api_key = process.env.SMOOTSELL_API_KEY;
    
    await axios.post(`https://smoothsell.com.ng/api/topup/`, JSON.stringify(airtimeData), {
      headers: {
        Authorization: `Token ${api_key}`,
        "Content-Type": "application/json",
      },
    });

    console.log("Airtime purchase successful");

    try {
      const transactionReference = `REF-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
      const notePad = `${amount} ${airtimeType} has been sent to ${mobileNumber}`;

      await pool.query(
        "INSERT INTO transactions (userid, note, transactionreference) VALUES ($1, $2, $3)",
        [user_id, notePad, transactionReference]
      );

      console.log("Transaction recorded successfully");
    } catch (error) {
      console.error("Database Insert Error:", error);
    }

    res.status(200).json({ message: "Successful" });
  } catch (error) {
    console.error("🚨 Top-up API:", error);
    res.status(500).json({ error: "Error occurred during top up" });
  }
});

app.post('/create', async (req, res) => {
  const { customerEmail, customerName, nin, userIDD } = req.body;

  if (!customerEmail || !customerName || !nin) {
    return res.status(400).json({
      error: 'Missing required fields: email, name, or NIN'
    });
  }

  const accountReference = `REF-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  const paymentApi = process.env.PAYMENT_API_KEY;
  const secretKey = process.env.PAYMENT_SECRET_KEY;
  const baseUrl = process.env.BASE_URL;
  const credentials = Buffer.from(`${paymentApi}:${secretKey}`).toString('base64');

  try {
    // Step 1: Get Access Token
    const response = await axios.post(`${baseUrl}/api/v1/auth/login`, {}, {
      headers: {
        Authorization: `Basic ${credentials}`,
        "Content-Type": 'application/json'
      }
    });

    const accesstoken = response.data.responseBody.accessToken;

    if (!accesstoken) {
      return res.status(401).json({ message: 'Failed to authenticate' });
    }

    // Step 2: Create Bank Transfer Reserved Account
    const requestBody = {
      accountReference,
      accountName: customerName,
      currencyCode: 'NGN',
      contractCode: "121231450768",
      customerEmail,
      nin,
      getAllAvailableBanks: true
    };

    const result = await axios.post(`${baseUrl}/api/v2/bank-transfer/reserved-accounts`, requestBody, {
      headers: {
        Authorization: `Bearer ${accesstoken}`,
        "Content-Type": "application/json"
      }
    });

    // Step 3: Update Database
    await pool.query("UPDATE users SET accountreference=$1 WHERE id=$2", [accountReference, userIDD]);

    res.status(200).json({
      message: 'Updated successfully',
      data: result.data
    });

  } catch (error) {
    console.error("Error:", error.response?.data || error.message);
    res.status(500).json({
      error: 'Internal server error',
      details: error.response?.data || error.message
    });
  }
});


app.get('/accountno/:userIDD', async (req, res) => {
  const { userIDD } = req.params;
  console.log(`Received user ID: ${userIDD}`);
  console.log('Processing request...');

  try {
    // Query the database for the account reference
    const result = await pool.query("SELECT accountreference FROM users WHERE id = $1", [userIDD]);

    // if (result.rows.length === 0) {
    //   return res.status(404).json({ error: 'User not found' });
    // }

    const merchantReference = result.rows[0].accountreference;
    console.log(`Merchant Reference: ${merchantReference}`);

    if (!merchantReference) {
      return res.status(400).json({ error: 'Account reference not available for this user' });
    }

    // Environment variables
    const paymentApi = process.env.PAYMENT_API_KEY;
    const secretKey = process.env.PAYMENT_SECRET_KEY;
    const baseUrl = process.env.BASE_URL;

    if (!paymentApi || !secretKey || !baseUrl) {
      return res.status(500).json({
        error: 'Missing environment variables. Contact admin.',
      });
    }

    // Encode credentials for Basic Auth
    const credentials = Buffer.from(`${paymentApi}:${secretKey}`).toString('base64');
    console.log(`Encoded Credentials: ${credentials}`);

    // Obtain access token
    const loginResponse = await axios.post(`${baseUrl}/api/v1/auth/login`, {}, {
      headers: {
        Authorization: `Basic ${credentials}`,
        "Content-Type": 'application/json',
      },
    });

    const accessToken = loginResponse.data.responseBody.accessToken;
    console.log(`Access Token: ${accessToken}`);

    // Fetch account details using merchant reference and access token
    const accountResponse = await axios.get(`${baseUrl}/api/v2/bank-transfer/reserved-accounts/${merchantReference}`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    console.log(accountResponse.data);

    const accountData = accountResponse.data;

    // Return account data to the client
    res.status(200).json({ account: accountData });

  } catch (error) {
    console.error('Error occurred:', error.response?.data || error.message);

    // Handle errors gracefully
    res.status(500).json({
      error: 'An error occurred while processing the request',
      details: error.response?.data || error.message,
    });
  }
});




const MONNIFY_SECRET_KEY = process.env.PAYMENT_SECRET_KEY;

app.post("/webhook/monnify", async (req, res) => {
 
  try {
    // console.log("Webhook received:", req.body);
    const requestBody = JSON.stringify(req.body);
    // console.log("The request body from Monnify is", requestBody);

    const transactionHash = req.headers["monnify-signature"]; // Hash sent by Monnify
    // console.log("Transaction hash sent by Monnify is", transactionHash);

    // Compute the expected hash
    const expectedHash = crypto.createHmac("sha512", MONNIFY_SECRET_KEY)
      .update(requestBody)
      .digest("hex");

    // Validate the transaction hash
    if (transactionHash !== expectedHash) {
      console.log("Invalid webhook signature!");
      return res.status(400).json({ message: "Invalid signature" });
    }
    //process webhook if signature is valid
    const {eventData,eventType}=req.body;
    const { transactionReference, paymentReference, amountPaid, paymentStatus, customer } = eventData;
 

    const customerEmail = customer.email; // Extract customer email

    if (paymentStatus === "PAID") {
      console.log(`Payment successful for ${customerEmail}. Amount: ${amountPaid} and transaction reference is ${transactionReference}`);
      const amountPaidNum = Number(amountPaid);
      const charges = Number((0.015 * amountPaidNum).toFixed(2));
      const depositAmount = amountPaidNum - charges;

      console.log("Amount deposited:", amountPaidNum);
      console.log("The charge for the recent deposit is:", charges);

      await updateTransaction(paymentReference, "Successful", customerEmail, amountPaid, depositAmount,charges);
    } else {
      console.log(`Payment failed or pending: ${paymentReference}`);
    }

    // Respond with a 200 OK to acknowledge receipt
    res.status(200).json({ message: "Webhook received successfully" });
  } catch (error) {
    console.error("Error processing webhook:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

async function updateTransaction(transactionReference, status, customerEmail, amountPaid, depositAmount, charges) {
  // console.log(`Updating transaction ${transactionReference} with status: ${status}`);

  try {
    const response = await pool.query("SELECT * FROM users WHERE email=$1", [customerEmail]);

    if (response.rows.length > 0) {
      const customerUsername = response.rows[0].username;
      const initialBalance = Number(response.rows[0].wallet);
      const newBalance = depositAmount + initialBalance;

      console.log(`Customer Username: ${customerUsername}`);
      console.log(`Initial Balance: ${initialBalance}, New Balance: ${newBalance}`);

      try {
        // Update wallet balance
        await pool.query("UPDATE users SET wallet=$2 WHERE username=$1", [customerUsername, newBalance]);

        // Insert summary record
        await pool.query(
          "INSERT INTO summary (username,depositamount,transactionreference) VALUES($1,$2,$3)",
          [customerUsername,depositAmount,transactionReference]
        )
        console.log('Wallet funded succesfully')
        console.log(`Transaction updated successfully for ${customerUsername}`);
      } catch (error) {
        console.error("Error updating user balance:", error);
      }
    } else {
      console.error(`User with email ${customerEmail} not found.`);
    }
  } catch (error) {
    console.error("Error fetching user data:", error);
  }
}

passport.use(
    new LocalStrategy({usernameField:"userName", passwordField:'password'},
        async (userName, password, done)=>{
        // console.log(userName,password);
        // console.log(`Attempting to log in ${userName}`);
        
        try {
            const result= await pool.query('SELECT * FROM users WHERE username=$1',[userName]);
            // console.log(result);
            
            if(result.rows.length === 0){
                console.log('User not found');
                
                return done(null,false,{message:'User not found'})
            }
            const user=result.rows[0]
                // console.log(user);
                const storedHashedPassword=user.password;
                // console.log(storedHashedPassword);
                const valid=await bcrypt.compare(password,storedHashedPassword);
                if(valid){
                    return done(null,user);
                }else{
                    return done (null,false,{message: 'Incorrect password'});
                }
        } catch (error) {
            console.log('Error querying database',error)
            return done(error);
        }
    })
);

passport.serializeUser((user,done)=>{
  done(null,user.id);//serialize user by id
})
 
passport.deserializeUser(async (id, done) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    if (result.rows.length > 0) {
      return done(null, result.rows[0]); // Deserialize user
    } else {
      return done(new Error('User not found'));
    }
  } catch (error) {
    console.error('Error deserializing user:', error);
    return done(error);
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '/dist', 'index.html'));
});


// Start the server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

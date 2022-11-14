# A--Fullstack-Auth-Intro

# Fullstack Auth Part 1 - Server Implementation

## Overview
- For this assignment, we will be creating server routes to register a user, login a user and respond with data specific to a user's level of authorization.
- We will be implementing the basic functionality of the bcryptjs and JSONWebToken NPM libraries. 
- Bcryptjs is a Javascript library that will allow us to securely encrypt a user's password. Bcrypt also provides us with functionality to take an input password and compare it to the encrypted password to see if it matches. In this way, we will be able to register a user with an encrypted password and then login that user without having to decrypt the password server-side.
- JSONWebToken is a Javascript library that will allow us to encode a JSON Web Token or JWT. JWT's are used in web development to store a user's credentials client-side after they have been authenticated by the server. The JWT is how we will identify what particular user is sending a request to our server. 
- As we implement the user authentication routes, we will use Postman to simulate the basic user auth process of registering with our application, logging in to our application and then requesting a resource specific to the user's level of access with our application. 

## Instructions

### 1) Project Setup
- Create two new repos for server and client: 
	- fullstack-auth-client for the client code 
	- fullstack-auth-server for the server code
		- This repository should be initialized with node .gitignore
- Create a new local folder called fullstack-auth and clone both repositories into this folder.
- Add the two repository git links to populi.

### 2) Server Setup
- Initialize the project using express-generator
	- ```npx express-generator -e```
- NPM Install dotenv, mongodb, uuidv4, cors, nodemon, bcryptjs, jsonwebtoken
	- ```npm i dotenv mongodb uuidv4 cors nodemon bcryptjs jsonwebtoken```
- Update npm start script in the server package.json to use nodemon instead of node
	- ``` "start": "nodemon ./bin/www" ```
- Create a .env file in the project root
- Change express server port to 4000 using the .env file
	- ```PORT=4000```
- Add Mongo Connection env vars to .env file
	- _Note_: For this project we will use our blogs database (MONGO_DATABASE = blogDB)
- Create the mongo.js file in the project root and add the mongo connection code
	- 
```
const { MongoClient } = require("mongodb");

let database;

async function mongoConnect() {
	// Connection URI
	const uri = process.env.MONGO_URI;
	// Create a new MongoClient
	const client = new MongoClient(uri);
	try {
		// Connect the client to the server
		await client.connect();
		database = await client.db(process.env.MONGO_DATABASE);
		// Establish and verify connection
		console.log("db connected");
	} catch (error) {
		throw Error("Could not connect to MongoDB. " + error);
	}
}
function db() {
	return database;
}
module.exports = {
	mongoConnect,
	db,
};
```
- Add the boilerplate code for dotenv, mongo and cors to app.js
	- 
```
const cors = require("cors");
require("dotenv").config();

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');

var { mongoConnect } = require('./mongo.js');
mongoConnect();

var app = express();

app.use(cors());
app.options("*", cors());
```
- Run npm start to test that your server is connected to mongo and is up and running

### 3) Implement User Registration
- _Approach_: We will create a new API route for user registration that takes a user email and password from the request body. Next, we will implement the bcrypt gensalt and hash functions. The gensalt function will create what is known as a salt, which is a psuedo-randomly generated string of characters that is used to encrypt a string of characters. The hash function will take the generated salt string as well as our password string and cryptographically combine them to produce an encrypted password string. Once we have this encrypted password, we will store that along with the user email as a new user entry in our database.

- In the users route file (./routes/users), add a new POST route called "/register" and implement the following:
	- This route should get the user's email and password from the request body.
	- Next, it should generate a new salt with the bcrypt genSalt function. [1]
		- _Note_: The genSalt function takes a single number as the argument which is the amount of saltRounds to perform. The more salt rounds are that are performed, the more secure the encrypted password will be at the expense of computer processing time. For our purposes, we will set the number of salt rounds to 5.
	- Next, it should generate a hashed password using the bcrypt hash function. The hash function takes two arguments, the plain text user password as the first argument and the salt as the second. [2]
	- Once the hashed password has been generated, insert a new user into the 'users' collection. A user should have an id field generated by uuidv4, an email field set to the users email, and a password field set to the hashed password. [3]
	- If the above was successful, the route should respond with a success: true JSON object.
- Test this route by making a new POST request in postman and then checking your database using nosqlbooster to see if the new user was created properly.

### 4) Implement User Login
- _Approach_: Now that we have the ability to register a user, we will implement the ability to log them in to our application. First, we will use the bcrypt compare function to compare the input user password from the login request to the stored hashed password on the user document in our database. If the password is valid, then we will construct a signed JSON Web Token for that user known as the idToken. The idToken is an encrypted string that decodes to a JSON object server-side. The idToken carries user information with it such as the user id and the level of permissions a user has. To keep things simple, we will make a user an admin user if they have 'codeimmersives.com' as the domain of their email address. Once we construct the JWT, we will send it, along with some user data, in the response.

- In the users route file (./routes/users), add a new POST route called "/login" and implement the following:
	- This route should get the user's email and password from the request body.
	- Next, it should retrieve the user in the users database collection using the email address provided from the request. This user should have the email, id and password fields. [4]
	- If a user with this email address was not found in the database, the route should respond with a success: false object that also has the message "Could not find user." on it. [5]
	- Next, it should use the bcrypt compare function to compare the input password from the request body to the stored hashed password on the user object. [6]
		- _Note_: bcrypt compare takes two arguments, the first is the input plain text password and the second is the hashed password that is being stored on the user document. The compare function returns a boolean which will be true of the passwords match and false if they do not.
	- If the bcrypt compare function returned false, the route should respond with a success: false object that also has the message "Password was incorrect." on it. [7]
	- Next, it should create a new object variable called userData. This object should have 3 fields on it: date which is set to a new date, userId which is set to the user's id being stored on the database document, and scope which is set to "admin" if the user's email address contains "codeimmersives.com" and is set to "user" otherwise. [8]
		- _Commentary_: There are many ways applications set user permissions and it depends on the usecases your application has. Most will have a front-end user interface that allows an admin user to select which users get set to admin or not (this data would be stored on the user database document). For this assignment, we are keeping things simple by going off of the email address domain.
	- Next, it should create a new JSON Web Token for the user; to implement this step, do the following:
		- Add a new environment variable to the server .env file called JWT_SECRECT_KEY. JWT_SECRECT_KEY should be set to CodeImmersives2022. Restart your server process for this change to take effect. [9]
		- In the /login route, create a new object variable called payload. Set two properties onto the payload object. The first will have the key userData and the value of the userData variable you created before. The second will have the key exp (which is short for expiration). The value for exp should be set to Math.floor(Date.now() / 1000) + (60 * 60), which is the numerical value in seconds of 24 hours in the future. [10]
			- _Commentary_: JWT's always come with an expiration date. This is a security measure to ensure that if a user's token gets stolen, it will not be valid for more than 24 hours. In a more robust flow, we would check the expiration of the token on every request and invalidate a user's login status if the token is expired. Servers regularly issue new idTokens to users when they reauthenticate with the server. 
		- Use the jwt.sign method to create a new JSON Web Token and assign that value to a variable called token. jwt.sign takes two arguments, the first is the payload object you just created (with userData and exp), the second is the JWT_SECRET_KEY environment variable that you should access from process.env. [11]
			- _Commentary_: The JWT_SECRET_KEY is the passphrase that will be used to encrypt our tokens. This key should always be stored server-side and never exposed to users. If a third party had access to your server's secret key, they could decrypt a user's idToken and gain access to their user data. Or they could create their own fake tokens and immitate a user on your platform. Thus, this key should always be stored server-side and will be the only place that a jwt for your application can be encrypted/decrypted.
	- Lastly, send a success: true JSON object with the token and the user's email in the response. [12]
- If you implemented the above properly, you should be able to send the email and password you used to register in a POST request to /login. The response should contain success: true, a long string of alpha-numeric characters as the token and the email address you registered with.
	- _Example_:
```
{
	"success": true,
	"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyRGF0YSI6eyJ0aW1lIjoiMjAyMi0xMS0xMVQyMTozNDoxMy4wMzBaIiwidXNlcklkIjoiMWI1ODllNmUtYjUyMy00YTMxLThlNDAtYzY5YWQ1MTBkOTczIiwic2NvcGUiOiJ1c2VyIn0sImV4cCI6MTY2ODIwNjA1MywiaWF0IjoxNjY4MjAyNDUzfQ.82pjbZN5WpkZvl2NwqHKS86UDmDLL_zwkMAXre2EELY",
	"email": "james.nissenbaum@gmail.com",
}
```

### 5) Implement Sample Token Verification Route
- _Approach_: Now that we are able to log a user in by generating an idToken for them, we will implement a sample route that will decode the token and respond with a particular message based on whether or not a user is an admin or a normal user. In typical applications, the user's idToken will be sent in the headers for a request to the server from the client. The server will then get the token from the headers, decode it and use that information to respond to the request. First, we will add a new environment variable in our server that will be header key we will use to send our token. Second, we will create the Postman request that we will need to test our route. Last, we will code in the route itself.

- Add a new environment variable to the server .env file:
	- TOKEN_HEADER_KEY = ci_token_header_key
- Restart your server process for this change to take effect.

- In Postman, do the following:
	- Authenticate with your application by sending a POST request with your email and password to the /users/login route. In the response, you should see a new token that was generated by the route you implemented in the previous step. Copy that token.
	- Create a new GET request to /users/message
	- Click on the headers section of this new request.
	- Set one of the request headers to have the key ci_token_header_key and the value of the token you just copied. 
		- _Commentary_: This step is simulating the application client storing the users token from the login request and then sending that token in the headers of some new request to the server. 

- In the users route file (./routes/users), add a new GET route called "/message" and implement the following:
	- Get the user's token from the request headers and assign it to a new variable. [13]
		- _Hint_: The req.header() method will retrieve a value from a particular header on a request. The argument for .header() is the key of the header. In this case, we want to pass the TOKEN_HEADER_KEY from process.env into the .header() method as an argument. 
	- Next, use the jwt.verify method to decode and verify the token. The jwt.verify method takes two arguments. The first is the token itself which you should be getting from the request header. The second is the secret key being stored on your server that you used to create the token, in this case it is the JWT_SECRET_KEY environment variable coming from process.env. [14]
	- The jwt.verify method will return either false or the decoded token data. Add a condition that will send a success: false JSON object with the message "ID Token could not be verified" on it if the jwt.verify method returned false. [15]
	- Next, if the jwt.verify step worked, you should now have a decoded token with your user's userData on it. [16]
		- If the scope property on userData equals "user", respond with a success: true JSON object that has the message "I am a normal user" on it.
		- If the scope property on userData equals "admin", respond with a success: true JSON object that has the message "I am an admin user" on it.

- If all of the above steps were implemented properly, you should be able to do the following:
	- Register a new user with the application. If the email address has @codeimmersives.com in it, that user will be an admin, otherwise they will be a normal user.
	- Login with the user you just created to get an idToken specific to your user in the response.
	- Make a request to /users/message with the token value in the request headers to see a message declaring that you are either an admin user or a normal user.

## Code References
- [1]
```
const saltRounds = 5
const salt = await bcrypt.genSalt(saltRounds);
```
- [2]
```
const hash = await bcrypt.hash(password, salt);
```
- [3]
```
const user = {
	email: email,
	password: passwordHash,
	id: uuid(), // uid stands for User ID. This will be a unique string that we will can to identify our user
};

const insertResult = await db().collection("users").insertOne(user);
```
- [4]
```
const user = await db().collection("users").findOne({
	email,
});
```
- [5]
```
if (!user) {
	res.json({ success: false, message: "Could not find user." }).status(204);
	return;
}
```
- [6]
```
const match = await bcrypt.compare(password, user.password);
```
- [7]
```
if (!match) {
	res
		.json({ success: false, message: "Password was incorrect." })
		.status(204);
	return;
}	
```
- [8]
```
const userType = email.includes("codeimmersives.com") ? "admin" : "user";

const userData = {
	date: new Date(),
	userId: user.id, 
	scope: userType,
};
```
- [9]
```
JWT_SECRET_KEY = CodeImmersives2022
```
- [10]
```
const exp = Math.floor(Date.now() / 1000) + 60 * 60;
const payload = {
	userData,
	exp
}
```
- [11]
```
const jwtSecretKey = process.env.JWT_SECRET_KEY;
const token = jwt.sign(payload, jwtSecretKey);
```
- [12]
```
res.json({ success: true, token, email });
```
- [13]
```
const tokenHeaderKey = process.env.TOKEN_HEADER_KEY;
const token = req.header(tokenHeaderKey);
```
- [14]
```
const jwtSecretKey = process.env.JWT_SECRET_KEY;
const verified = jwt.verify(token, jwtSecretKey);
```
- [15]
```
if (!verifiedToken) {
	return res.json({
		success: false,
		message: "ID Token could not be verified",
	});
}
```
- [16]
```
if (userData && userData.scope === "user") {
	return res.json({
		success: true,
		message: "I am a normal user",
	});
}

if (userData && userData.scope === "admin") {
	return res.json({
		success: true,
		message: "I am an admin user",
	});
}

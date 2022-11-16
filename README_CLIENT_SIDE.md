# Fullstack Auth Part 2 - Client Implementation

## Overview
- Now that we have our server auth routes setup, we will implement the client-side code that will call our API auth methods.
- We will create a registration page that will make a request to the server to register a user.
- We will create a login page that a user can use to authenticate with our application and once authenticated, the client will store their idToken in local storage.
- We will create a navbar that automatically displays the user email based upon their login status.
- Lastly, we will implement a Home Page that will make a request to the server with the user's idToken and respond with a message based upon the user's permission level.

## Instructions

### 2) Client Setup

- In the fullstack-auth-client folder, initialize the client using create react app
	- ```npx create-react-app .```
- NPM Install react-router
	- ```npm i react-router-dom```
- Create a .env.local file in the project root
	- ```touch .env.local```
- Add the following environment variables to the .env.local file:
	- REACT_APP_URL_ENDPOINT = http://localhost:4000
	- REACT_APP_TOKEN_HEADER_KEY = ci_token_header_key
- Run npm start to test that your client is running on port 3000

### 3) Create Base Client Components
- Create a Layouts, Pages and Components folders in the ./src folder
- Create the following files and react components in those files: 
	- _Note_: For now, keep these as basic react components.
	- Create a new layout called GlobalLayout
	- Create a new component called NavBar
	- Create three new pages: HomePage, LoginPage and RegistrationPage
- Create a new browser router in the body of ```<App/>``` and add a new RouteProvider to the JSX of ```<App/>```.
- Set the "/" route in the browser router to render the ```<GlobalLayout/>``` as the element.
- Set the first child route of GlobalLayout to render ```<HomePage/>``` as the element. Set this route as the index route.
- Set the second child route of GlobalLayout to render ```<LoginPage/>``` as the element with the path 'login'.
- Set the third child route of GlobalLayout to render ```<RegistrationPage/>``` as the element with the path 'registration'.
- Import NavBar into the GlobalLayout file and add an instance of ```<NavBar/>``` into the JSX of ```<GlobalLayout/>```.
- Import Outlet from react-router-dom and add the ```<Outlet/>``` component to ```<GlobalLayout/>``` under ```<NavBar/>```
- Add an h1 header to the jsx of ```<HomePage/>``` that says 'Fullstack Auth Home Page'.
- Add an h1 header to the jsx of ```<LoginPage/>``` that says 'Fullstack Auth Login Page'.
- Add an h1 header to the jsx of ```<RegistrationPage/>``` that says 'Fullstack Auth Registration Page'.
- Add ```<Link/>``` components (imported from react-router-dom) to the ```<NavBar/>``` that links to the Home Page, Registration Page and Login Page.
	- "/" => Home
	- "/registration" => Registration Form
	- "/login" => Login Form

### 4) Add Auth Hook
- _Approach_: For this part of the project, the code needed to manage the state of user authentication client side will be provided to you. The following code uses react context to create an application wide custom hook that stores its own internal state. This custom hook called useAuth will manage the user token and load it in from the browser local storage when the client is refreshed, in effect persisting the user's logged in status. The useAuth hook provides functionality to register, login and logout a user from the application which we will use in our application pages.

- Create a new folder in ./src called Hooks.
- Create a new file in ./src/Hooks called auth.js
- Copy/paste the following code into auth.js
```
import { useState, useEffect, createContext, useContext, useMemo } from "react";
const urlEndpoint = process.env.REACT_APP_URL_ENDPOINT;
const AuthContext = createContext();

/* 
@Source: https://blog.logrocket.com/complete-guide-authentication-with-react-router-v6/#basic-routing-with-routes
*/
export const AuthProvider = ({ children }) => {
  const [userToken, setUserToken] = useState(null);
  const [userEmail, setUserEmail] = useState("")
  const [isAuthLoading, setIsAuthLoading] = useState(false);

  useEffect(() => {
    const userData = getLSUserData();
		if (userData && userData.token) {
			setUserToken(userData.token);
		}
		if (userData && userData.email) {
			setUserEmail(userData.email);
		}
  }, [isAuthLoading]);

  // call this function when you want to register the user
  const register = async (email, password) => {
    setIsAuthLoading(true);
    const registerResult = await registerUser(email, password);
    setIsAuthLoading(false);
    return registerResult;
  };

  // call this function when you want to authenticate the user
  const login = async (email, password) => {
    setIsAuthLoading(true);
    const loginResult = await loginUser(email, password);
    if (loginResult.success) {
      setLSUserData(loginResult.token, loginResult.email);
    }
    setIsAuthLoading(false);
    return loginResult
  };

  // call this function to sign out logged in user
  const logout = async () => {
    setIsAuthLoading(true);
    await removeLSUserData(); // This has to be awaited for the useEffect to work
    setUserToken(null);
    setUserEmail("");
    setIsAuthLoading(false);
  };

  /*  
    https://reactjs.org/docs/hooks-reference.html#usememo
    Memoization is essentially caching. The variable value will only be recalculated if the 
    variables in the watched array change.
  */
  const value = useMemo(
    () => ({
      userToken,
      userEmail,
      login,
      logout,
      register,
    }),
    [userToken]
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  return useContext(AuthContext);
};

const registerUser = async (email, password) => {
  const url = `${urlEndpoint}/users/register`;
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      email,
      password,
    }),
  });
  const responseJSON = await response.json();
  return responseJSON;
};

const loginUser = async (email, password) => {
  const url = `${urlEndpoint}/users/login`;
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      email,
      password,
    }),
  });
  const responseJSON = await response.json();
  return responseJSON;
};

const setLSUserData = (token, email) => {
  localStorage.setItem(
    process.env.REACT_APP_TOKEN_HEADER_KEY,
    JSON.stringify({token, email})
  );
};

const removeLSUserData = () => {
  localStorage.removeItem(process.env.REACT_APP_TOKEN_HEADER_KEY);
  return true;
};

const getLSUserData = () => {
  return JSON.parse(
    localStorage.getItem(process.env.REACT_APP_TOKEN_HEADER_KEY)
  );
};
```
- In ./src/index.js, import { AuthProvider } from "./Hooks/Auth";
- Replace the JSX of the root render in index.js with the following code:
	- 
	```
	<React.StrictMode>
		<AuthProvider>
    	<App />
		</AuthProvider>
  </React.StrictMode>
	```
	- _Commentary_: The ```<AuthProvider/>``` components are created using react context. Any component that is a child of ```<AuthProvider/>``` will now be able to access any of the methods exposed with our custom useAuth hook.

### 5) Implement the Registration and Login Forms
- In the Registration Page, implement the following:
	- Add state variables, labels and input fields for:	
		- email => should be a type="text" input field with the state variable initialized to ""
		- password => should be a type="password" input field with the state variable initialized to ""
			- _Note_: By setting the field type to be "password", the characters typed into the input field will be replaced by dots.
	- Add a state variable called registerMessage initialized to "". Display registerMessage in an h3 tag. 
	- Add the following imports to the page:
		- 
		```
		Import { useAuth } from "../Hooks/Auth"
		Import { useNavigate } from "react-router-dom"
		```
	- In the body of ```<RegistrationPage/>``` instantiate the useAuth and useNavigate hooks.
		- 
		```
		const auth = useAuth();
		const navigate = useNavigate();
		```
	- Add a button at the bottom of the registration form called Sign Up. This button should call await auth.register() with the email and password passed in as arguments and assign the result to a new variable registerResult. If registerResult.success is true, programmatically navigate the page to "/login". If registerResult.success is false, set registrationMessage to registerResult.message to display the error message to the user. [1]

- Implement the above steps for Login Page except:
	- The message state variable should be called loginMessage instead of registrationMessage
	- The button should be titled Login instead of Sign Up.
	- The button onClick handler should call auth.login instead of calling auth.register.
	- The page should programmatically navigate to "/" if loginResult.success is true. [2]

### 6) Display Home Page User Message
- In the Home Page, add a new state variable to ```<HomePage/>``` called message and display the message in an h3 tag in the JSX of ```<HomePage/>```.
- Import the useAuth hook and instantiate it in the body of ```<HomePage/>```. [3]
- Add a new variable urlEndpoint in the global scope of Home Page set to the environment variable REACT_APP_URL_ENDPOINT. [4]
- Add a new useEffect to ```<HomePage/>```. This useEffect should be watching auth.userToken in the dependency array for changes. [5]
- Add a new asynchronous fetch function to the useEffect effect function called fetchMessage that makes a GET request to `${urlEndpoint}/users/message`. In this fetch request, add the currently logged in users token to the headers by setting the key of ```[process.env.REACT_APP_TOKEN_HEADER_KEY]``` to the value of auth.userToken. [6]
- In fetchMessage, get the message sent from the server from the response and set the message state variable to it. 
- Inside the useEffect effect function, call fetchMessage only if userToken does not equal null. If it does equal null, set the message state variable to "". [7]
	- _Commentary_: When the application is first loading in, react needs to load in the user token from local storage and so we only want to call this fetch function if the user's token is not null. Additionally, when the user is logged out, the token will be null and we want to set the message back to an empty string in this case.

### 7) Improved NavBar
- In ./src/Components/NavBar.js, import the useAuth hook and instantiate it in the body of ```<NavBar/>```.
- Add an h3 tag in the JSX of NavBar (as the first element inside the enclosing div tags) that conditionally renders ``` `Current User: ${auth.userEmail}` ``` if auth.userEmail is not null.
- Add a button as the last element in the JSX of NavBar that says Logout. The onClick handler for this button should call auth.logout().

- If you implemented the above steps correctly, you should be able to register a new user with the applicaition, log in as that user and then have a message specific to that user display on the Home Page. You should also see the user email appear in the Nav Bar if the user is logged in. You should also be able to click the logout button to have the state of the application reset to its initial state.


## Code References
- [1]
```
onClick={async () => {
	const registerResult = await auth.register(email, password);
	if (registerResult.success) {
		navigate("/login");
	}
	if (!registerResult.success) {
		setRegisterMessage(registerResult.message);
	}
}}
```
- [2]
```
const loginResult = await auth.login(email, password);
	if (loginResult.success) {
		navigate("/")
	}
	if (!loginResult.success) {
		setLoginMessage(loginResult.message)
	}
}}
```
- [3]
```
const auth = useAuth();
```
- [4]
```
const urlEndpoint = process.env.REACT_APP_URL_ENDPOINT
```
- [5]
```
useEffect(()=>{
		
}, [auth.userToken])
```
- [6]
```
const response = await fetch(`${urlEndpoint}/users/message`, {
	method: "GET",
	headers: {
		"Content-Type": "application/json",
		[process.env.REACT_APP_TOKEN_HEADER_KEY]: userToken
	},
});
```
- [7]
```
if (userToken !== null) {
	fetchMessage()
}
if (userToken === null) {
	setMessage("")
}
```

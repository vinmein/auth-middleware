
# Auth server


## Installation

```sh
$ npm install git+http://github.com/vinmein/auth-middleware.git --save
```
or update dependencies section of package.json with :
```sh
"sg-lab-auth-support": "git+http://github.com/vinmein/auth-middleware.git"

```
then run 
```sh
$ npm install
```
## Usage

```js
const authSupport = require('auth-middleware');


//Get role manager
let roleManager = authSupport.roleManager;

//Get highest role
let maxRole = roleManager.getMaxRole();

roleManager.isRoot(maxRole) // returns true

roleManager.hasRole(maxRole,"admin"); // returns true as root user got admin access

//Setting up security middleware for the application
//Assuming app reference corresonds to your express app instance
app.use(authSupport.security); //now every routes exposed by your app will be secured by default

//To override this behaviour and make specific routes unsecure

//make GET request for '/api/health-check' unsecure
authSupport.addUnsecureRoute('/api/health-check','GET');
//make POST and GET request for '/api/create' unsecure
authSupport.addUnsecureRoute('/api/create',['POST','GET']);

//Setting up role permission middleware on routes
//For user role only endpoints , we need to validate whether the requesting user is having the corresponding token
//this can be implemented through the options object

let authOptions = {};
//if you want to validate based on request params, ex : /api/:userId
//this make sure the token user id and userid request params are matching before endpoint execution
authOptions.userValidator ="userId"; 
//for even flexible validation you can register a callback function
authOptions.userValidator = function(req){
    //apply request processing logic
    //return boolean
}
//set the options to authSupport module
authSupport.options(authOptions);

/** Below route will be accessible only for admin roles **/
router.route('/')
    .get(authSupport.permission('admin'),userCtrl.list)

```

'use strict';
const jwt = require('express-jwt');
const env = require('dotenv')
var roles = process.env.ROLE //['students','teachers','principal','teaching','non-teaching','principal', 'owner', 'admin', 'root'];
const _config ={};
const unSecureRoots = [];
if(!process.env.JWT_SECRET){
    throw new Error("Environment variable not found : JWT_SECRET");
}
const roleManager ={
    getMaxRole: function () {
        return roles[roles.length - 1];
    },

    hasRole: function (role, checkRole) {
        return roles.indexOf(role) >= roles.indexOf(checkRole);
    },

    isRoot: function (role) {
        return roles.indexOf(role) === roles.length - 1;
    },

    isUser : function(role){
        return roles.indexOf(role) === 0;
    },
    getRoles : function(role){
        return roles;
    },
    //if role is valid, normalize. Otherwise throw error
    isValid: function (role) {
        if (roles.indexOf(role) > -1) {
            return role;
        }
        throw new Error("Invalid Role");
    },
    isPermitted: function (role, by) {
        var create = roles.indexOf(role)
        var by = roles.indexOf(by)
        if (create > -1 &&  by> -1 && !roleManager.isUser(role) && !roleManager.isUser(by)) {

            if(create<by)
                return role;
            else
                return "unAuthorized";
        }
        return "unAuthorized";
    }
};

const permission = function (allowed) {
    let isAllowed = req => {
        if (roleManager.isUser(req.user.role) && _config.userValidator) {
            return _config.userValidator(req);
        }
        return roleManager.hasRole(req.user.role,allowed);
    };

    return (req, res, next) => {

        if (req.user && isAllowed(req)){
            next();
        } else {
          res.status(403).json({message: "Forbidden"});
        }
    };
};

const security = jwt({
    secret: process.env.JWT_SECRET,
     getToken: function fromHeaderOrQuerystring(req) {
        if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
            return req.headers.authorization.split(' ')[1];
        } else if (req.query && req.query.token) {
            return req.query.token;
        }
        return null;
    }
}).unless({ path: unSecureRoots });

const addUnsecureRoute = function(endPoint,methods){
    let unsecureMethods = Array.isArray(methods) ? methods : [methods];
    unSecureRoots.push({ url: endPoint, methods: unsecureMethods });
};

const options = function(value){
    if(typeof value.userValidator === 'function'){
        _config.userValidator = function(req){return value.userValidator(req)};
    } else if(typeof value.userValidator === 'string'){
        _config.userValidator = function(req){return req.user._id == req.params[value.userValidator]};
    }

};

module.exports = { roleManager, permission, security, addUnsecureRoute, options };

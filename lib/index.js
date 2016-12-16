'use strict';
const jwt = require('express-jwt');
var roles = ['user','manager', 'admin', 'root'];
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
    }
};

const permission = function (allowed,exclusions) {

    let isAllowed = req =>{
        if(roleManager.isUser(req.user.role) && _config.userValidator){
            return _config.userValidator(req);
        }
        return roleManager.hasRole(req.user.role,allowed);
    };
    let exclusionRoles=[];
    if(exclusions){
      exclusionRoles = Array.isArray(exclusions) ? exclusions : [exclusions];
    }

    return (req, res, next) => {

        if (req.user && isAllowed(req)){
            next();
        } else {
          res.status(403).json({message: "Forbidden"});
        }
    };
};

const security = jwt({ secret: process.env.JWT_SECRET }).unless({path :unSecureRoots});

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

const exclude = (roles)=>{return roles};

module.exports = {roleManager,permission,security, addUnsecureRoute,options,exclude};

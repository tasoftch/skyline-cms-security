# Skyline CMS Security
Install this package to apply the ``` skyline/security ``` package easy into your application.  
It ships with a preconfiguration that you can easy adjust to your requirements.

### Compiler annotations
This package extends your application compilation by another annotation compiler.   
Annotations can be placed in your action controller. Everywhere else they don't affect compilation.
````php
<?php
use Skyline\Application\Controller\AbstractActionController;

/**
 * @annotation ....  Class annotations are valid for all action methods.
 */
class MyActionController extends AbstractActionController {
    
    /**
     * @annotation ....  This annotation is only valid for the action myAction
     */
    public function myAction() {
        // ...
    }
}
````

This annotations are available:  
**Identification**
- ````@reliability <number or IdentityInterface::RELIABILITY_* constant>```` (multiple not allowed)  
    Requires a minimal reliability.
- ```@token <string>``` (multiple allowed, if one matches, condition is fulfilled)  
    Requires a specific identity token name.

**Authentication**
- ```@user <string>``` (multiple allowed, if one matches, condition is fulfilled)  
    Requires a specific user by its name.
- ````@group <string>```` (multiple allowed, if one matches, condition is fulfilled)  
    Requires, that the authenticated user is member of specific group

**Authozization**
- ```@role <string>``` (multiple allowed, if all match, condition is fulfilled)  
    Requires, that the authenticated user has a specific role
    
Please note that depending what you require not all security processes are performed:  
If you only require a reliability and a token, no authentication is done!  
See [Package ```skyline/security```](https://github.com/tasoftch/skyline-security) for more information.

### Compile DataBase
Skyline Compiler allows you the compilation flag ```--with-pdo```.  
Compiling with this flag, this package will try to create database tables that allow a fully working login system.  
- ```SKY_USER```  
    Table hold all necessary information for a user, of course, you may easy extends it.
- ````SKY_ROLE````  
    Authorization part are roles, who has which roles to access an action.
- ```SKY_GROUP```  
    Users can be member of one or more groups. This also allows authorizing an action.
- ````SKY_USER_GROUP````  
    Intermediate table: Which user is member of which group
- ````SKY_USER_ROLE````  
    Intermediate table: Which user owns which roles
- ````SKY_GROUP_ROLE````  
    Intermediate table: Which group owns which roles

So if a user is member or a group, the user inherits all roles assigned by the group.

### Security Trait
````php
<?php
trait SecurityTrait {
    // ....
}
````
The security trait can be used in any class that you want to access dynamically security features.
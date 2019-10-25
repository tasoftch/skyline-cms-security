<?php

use Skyline\CMS\Security\UserSystem\Group;
use Skyline\CMS\Security\UserSystem\Role;
use Skyline\CMS\Security\UserSystem\User;
use Skyline\PDO\Compiler\Structure\Table\Field;
use Skyline\PDO\Compiler\Structure\Table\Table;

$ROLE_INTERNAL = Role::OPTION_INTERNAL;
$ROLE_VISIBLE = Role::OPTION_INTERNAL|Role::OPTION_VISIBLE|Role::OPTION_ASSIGNABLE;
$ROLE_FINAL = Role::OPTION_INTERNAL|Role::OPTION_VISIBLE|Role::OPTION_ASSIGNABLE;

return [
    (new Table("SKY_USER"))
        ->addField(new Field("id", Field::TYPE_INTEGER, 11, Field::ATTR_AUTO_INCREMENT|Field::ATTR_INDEX))
        ->addField(new Field("username", Field::TYPE_STRING, 50))
        ->addField(new Field("credentials", Field::TYPE_STRING, 100))
        ->addField(new Field("email", Field::TYPE_STRING, 80))
        ->addField(new Field("prename", Field::TYPE_STRING, 50))
        ->addField(new Field("surname", Field::TYPE_STRING, 50))
        ->addField(new Field("options", Field::TYPE_INTEGER, 11, Field::ATTR_HAS_DEFAULT, User::OPTION_CAN_LOGIN_WITH_MAIL))
        ->addField(new Field("lastLoginDate", Field::TYPE_DATE_TIME, 0, Field::ATTR_DEFAULT_TIMESTAMP|Field::ATTR_HAS_DEFAULT|Field::ATTR_UPDATE_TIME_STAMP)),
    (new Table("SKY_ROLE"))
        ->addField(new Field("id", Field::TYPE_INTEGER, 11, Field::ATTR_AUTO_INCREMENT|Field::ATTR_INDEX))
        ->addField(new Field("name", Field::TYPE_STRING, 50))
        ->addField(new Field("description", Field::TYPE_TEXT, 0, Field::ATTR_ALLOWS_NULL | Field::ATTR_HAS_DEFAULT, NULL))
        ->addField(new Field("parent", Field::TYPE_INTEGER, 11, Field::ATTR_HAS_DEFAULT, 0))
        ->addField(new Field("options", Field::TYPE_INTEGER, 11, Field::ATTR_HAS_DEFAULT, Role::OPTION_ASSIGNABLE|Role::OPTION_VISIBLE))
        ->setContents([
            ["id" => 1, 'name'=>"SKYLINE", "options" => Role::OPTION_INTERNAL],
            ["id" => 2, 'parent' => 1, 'name'=>"ADMIN", "description" => "The Administration Privilege. It allows the user to access the Control Panel of Skyline CMS", "options" => $ROLE_INTERNAL],
            ["id" => 3, 'parent' => 1, 'name' => 'CONTENTS', "description" => 'Privilege to edit the web site\'s content', 'options' => $ROLE_VISIBLE],
            ["id" => 4, 'parent' => 1, 'name' => 'EDITOR', "description" => 'Privilege to edit the web site\'s content', 'options' => $ROLE_VISIBLE]
        ]),
    (new Table("SKY_GROUP"))
        ->addField(new Field("id", Field::TYPE_INTEGER, 11, Field::ATTR_AUTO_INCREMENT|Field::ATTR_INDEX))
        ->addField(new Field("name", Field::TYPE_STRING, 50))
        ->addField(new Field("description", Field::TYPE_TEXT, 0, Field::ATTR_ALLOWS_NULL|Field::ATTR_HAS_DEFAULT, NULL))
        ->addField(new Field("options", Field::TYPE_INTEGER, 11, Field::ATTR_HAS_DEFAULT, 0))
        ->setContents([
            ['id' => 1, 'name' => "Administrator", 'description' => 'The administrators of Skyline CMS', "options" => Group::OPTION_INTERNAL],
            ['id' => 2, 'name' => "Author", 'description' => 'Authors can add and edit pages to your website', "options" => Group::OPTION_INTERNAL],
            ['id' => 3, 'name' => "Translator", 'description' => 'Translators can translate existing text into several languages', "options" => Group::OPTION_INTERNAL]
        ]),
    (new Table("SKY_USER_ROLE"))
        ->addField(new Field("user", Field::TYPE_INTEGER))
        ->addField(new Field("role", Field::TYPE_INTEGER)),
    (new Table("SKY_USER_GROUP"))
        ->addField(new Field("user", Field::TYPE_INTEGER))
        ->addField(new Field("groupid", Field::TYPE_INTEGER)),
    (new Table("SKY_GROUP_ROLE"))
        ->addField(new Field("groupid", Field::TYPE_INTEGER))
        ->addField(new Field("role", Field::TYPE_INTEGER)),
];
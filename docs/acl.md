# ACL

You can use the access control system to differentiate access to files and folders for different users.
For this you need to make the following settings.
Open configuration file - config/file-manager.php

1. Turn ON ACL system (fm-acl middleware will turn ON automatically)

    ```php
    // set true
    'acl' => true,
    ```

2. You can hide files and folders to which the user does not have access(access = 0).

    ```php
    'aclHideFromFM' => true,
    ```
3. ACL system operation strategies:

    ```php
    /**
     * ACL strategy
     *
     * blacklist - Allow everything(access - 2 - r/w) that is not forbidden by the ACL rules list
     *
     * whitelist - Deny anything(access - 0 - deny), that not allowed by the ACL rules list
     */
    'aclStrategy'   => 'blacklist',
    ```

4. Set the rule repository, the default is the configuration file.
   
   ```php
   /**
    * ACL rules repository
    *
    * default - config file(ConfigACLRepository)
    */
   'aclRepository' => \Alexusmai\LaravelFileManager\Services\ACLService\ConfigACLRepository::class,
   ```
   
   Now you can add your rules in 'aclRules' array. But if you want to store your rules in another place, such as a database, you need to create your own class, and implements two functions from ACLRepository.
   
   I have already made a similar class for an example, and if it suits you, you can use it. You only need to replace the repository name in the configuration file. And add a new migration to the database.
   
   ```php
    php artisan vendor:publish --tag=fm-migrations
    ```
   
   See [/src/Services/ACLService/DBACLRepository.php](../src/Services/ACLService/DBACLRepository.php) and [/migrations/2019_02_06_174631_make_acl_rules_table.php](./../migrations/2019_02_06_174631_make_acl_rules_table.php)
   
## Example 1

I have disk 'images' in /config/filesystems.php for folder /public/images

```php
'disks' => [

        'images' => [
            'driver' => 'local',
            'root'   => public_path('images'),
            'url'    => env('APP_URL').'/images/',
        ],
]
```

This disk contain:

```php
/              // disk root folder
|-- nature     // folder
|-- cars       // folder
|-- icons
|-- image1.jpg   // file
|-- image2.jpg
|-- avatar.png
```

I add this disk to file-manager config file

```php
'diskList'  => ['images'],

'aclStrategy'   => 'blacklist',

// now it's a black list
'aclRules'      => [
       // null - for not authenticated users
        null => [
            ['disk' => 'images', 'path' => 'nature', 'access' => 0],      // guest don't have access for this folder
            ['disk' => 'images', 'path' => 'icons', 'access' => 1],       // only read - guest can't change folder - rename, delete
            ['disk' => 'images', 'path' => 'icons/*', 'access' => 1],     // only read all files and foders in this folder
            ['disk' => 'images', 'path' => 'image*.jpg', 'access' => 0],  // can't read and write (preview, rename, delete..)
            ['disk' => 'images', 'path' => 'avatar.png', 'access' => 1],  // only read (view)

        ],
        // for user with ID = 1
        1 => [
            ['disk' => 'images', 'path' => 'cars', 'access' => 0],        // don't have access
            ['disk' => 'public', 'path' => 'image*.jpg', 'access' => 1],  // only read (view)
        ],
    ],
```

## Example 2

> Task: For each registered user, a new folder is created with his name(in folder /users). You want to allow users access only to their folders. But for an administrator with ID = 1, allow access to all folders.

- You need to create a new repository for ACL rules, for example, in the / app / Http folder

```php
<?php

namespace App\Http;

use Alexusmai\LaravelFileManager\Services\ACLService\ACLRepository;

class UsersACLRepository implements ACLRepository
{
    /**
     * Get user ID
     *
     * @return mixed
     */
    public function getUserID()
    {
        return \Auth::id();
    }

    /**
     * Get ACL rules list for user
     *
     * @return array
     */
    public function getRules(): array
    {
        if (\Auth::id() === 1) {
            return [
                ['disk' => 'disk-name', 'path' => '*', 'access' => 2],
            ];
        }
        
        return [
            ['disk' => 'disk-name', 'path' => '/', 'access' => 1],                                  // main folder - read
            ['disk' => 'disk-name', 'path' => 'users', 'access' => 1],                              // only read
            ['disk' => 'disk-name', 'path' => 'users/'. \Auth::user()->name, 'access' => 1],        // only read
            ['disk' => 'disk-name', 'path' => 'users/'. \Auth::user()->name .'/*', 'access' => 2],  // read and write
        ];
    }
}
```

- disk-name - you need to replace for your disk name

- now in the config file we will change the repository to a new one, and set aclStrategy in whitelist - we will deny everything that is not allowed by the rules. You can also hide folders and files that are not available.

```php
/**
     * Hide files and folders from file-manager if user doesn't have access
     * ACL access level = 0
     */
    'aclHideFromFM' => true,

/**
     * ACL strategy
     *
     * blacklist - Allow everything(access - 2 - r/w) that is not forbidden by the ACL rules list
     *
     * whitelist - Deny anything(access - 0 - deny), that not allowed by the ACL rules list
     */
    'aclStrategy'   => 'whitelist',

/**
     * ACL rules repository
     *
     * default - config file(ConfigACLRepository)
     */
    'aclRepository' => \App\Http\UsersACLRepository::class,
```


## Important limitations

### Wildcard rules match across "/" boundaries

Rules are matched with PHP's `fnmatch()`, which does **not** treat `/` as a special
boundary the way a shell glob usually does:

- `'path' => 'folder1*'` matches `folder1`, `folder12`, and `folder1-secret-admin-area` -
  any sibling sharing that prefix, not just subfolders of `folder1`.
- `'path' => 'folder2/*'` matches `folder2/anything/nested/this/deep`, because `*` also
  matches across further `/` separators - not just `folder2`'s direct children.

This is especially risky under the **whitelist** strategy (Example 2 above), where a rule
that matches more than you intended *grants* access rather than denying it - e.g. in
`['disk' => 'disk-name', 'path' => 'users/'. \Auth::user()->name .'/*', 'access' => 2]`,
if a username could ever contain `*`, `?`, or `[`, it would be interpreted as a glob
pattern rather than a literal name. Prefer narrower, explicit rules over a bare prefix
wildcard when you're not sure, and test a new rule against a path you expect it to *deny*,
not just one you expect it to allow.

### ACL does not protect direct storage URLs

ACL governs requests that go through this package's own routes (`content`, `preview`,
`download`, ...). It does **not** retroactively protect a file once a direct URL to it has
been handed out via the `url` endpoint (`Storage::disk($disk)->url($path)`): for the
`public` disk (or any disk with a public, webserver-reachable URL), that URL is served
directly by the webserver/storage driver, bypassing this package - and therefore bypassing
ACL - entirely. In practice this means "read access in the file manager" for a file on a
public disk is equivalent to "permanent, unauthenticated access to that file's URL for
anyone who obtains it," regardless of ACL rules or later revocation. If you need
access that can be revoked per-user, don't rely on a public disk/symlinked storage for
that content - proxy the file's bytes through your own authenticated controller action
instead.

## What's next

[Events](./events.md)

# Country Access Blocker

## WordPress Plugin to Block Whole Countries

For use when you want to block traffic from countries that have no business on your site. The plugin is meant to limit malicious traffic. Examples are when you only ship to the United States and Canada, you can block all other countries. If you write a blog that is only meant for English-speaking countries, you can block countries whose primary language isn't English.

## Features

* Uses open-source [country.is](https://country.is/) API to determine visitor location
* Caches IP / Country Code so [country.is](https://country.is/) is only pinged once
* Protects admin access by never blocking the administrator's country
* Can run as a Must-Use plugin to ensure it loads before other security plugins
* Allows blocking/unblocking via checkboxes
* Clearly marks admin's country as protected
* Minimal error messages to blocked visitors

## Installation

### /plugins

This plugin can be installed like any other plugin, and uploaded through the WordPress `Plugins` → `Add New Plugin` → `[Upload Plugin]`.

The plugin begins with "__" to take advantage of WordPress' alphabetical loading of plugins. If you find another plugin loads first, you can always change the prefix of `__country-access-blocker.php`.

### /mu-plugins

Country Access Blocker is designed to be used in the 'must-use' plugin directory, too. This will ensure that it loads before other plugins, and make it difficult to disable.

If you have FTP access to your website:

1. Copy the folder `__country-access-blocker` into `/yourwebsite/wp-content/mu-plugins` first.
2. Then, copy `__country-access-blocker.php` into `/yourwebsite/wp-content/mu-plugins`.

## Use At Your Own Risk

I wrote this plugin for a friend of mine and I. I am making it available through GitHub if you want to use it or fork it. But, don't expect any type of support because I'm an old retired guy who does this as a hobby.

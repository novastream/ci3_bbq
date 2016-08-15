# Block Bad Queries for Codeigniter 3

This is the famous BBQ plugin for Wordpress ported to Codeigniter 3.

This version also includes a simple logging feature. We use a file for logging so we don't have to depend or add traffic to your database.

### Original Author
Jeff Starr /
https://plugin-planet.com/

You can make donation for his work here / http://m0n.co/donate


### Installation

Place the Bbq.php file in your libraries directory.
If you autoload the library or use it as below the class will be loaded with default settings.
```php
$this->load->library('bbq');
```
Here is a customized alternative

```php
$params = array(
    'log_enable' => true,
    'log_file' => 'application/log/bbq.log',
    'log_seperator' => '|',
    'time_format' => 'Y-m-d H:i:s'        
);
    
$this->load->library('bbq', $params);
```
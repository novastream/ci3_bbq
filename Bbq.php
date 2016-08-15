<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');
/*
	Class name: BBQ (block bad queries)
    Original Author: Jeff Starr
    Author URI: https://plugin-planet.com/
    Donate link: http://m0n.co/donate
    Ported to CI3 by: Jonathan Lindgren
    License: GPLv2 or later
    
    Customized to work with Codeigniter 3.
    - Added the following user agents: 'java'
    - Added logging functionality
    
    USES getenv SO YOU NEED PHP 5.3+
    
    Example usage (logging will be disabled):
    $this->load->library('bbq');
    
    or you can load it in the constructor of a controller
    
    $params = array(
        'log_enable' => true,
        'log_file' => 'application/log/bbq.log',
        'log_seperator' => '|',
        'time_format' => 'Y-m-d H:i:s'        
    );
    
    $this->load->library('bbq', $params);
*/

class Bbq {
	
	/**
     * Suspicious URIs
    */
    private $request_uris = array(
        'eval\(',
        'UNION(.*)SELECT', 
        '\(null\)', 
        'base64_', 
        '\/localhost', 
        '\%2Flocalhost', 
        '\/pingserver', 
        '\/config\.', 
        '\/wwwroot', 
        '\/makefile', 
        'crossdomain\.', 
        'proc\/self\/environ', 
        'etc\/passwd', 
        '\/https\:', 
        '\/http\:', 
        '\/ftp\:', 
        '\/cgi\/', 
        '\.cgi', 
        '\.exe', 
        '\.sql', 
        '\.ini', 
        '\.dll', 
        '\.asp', 
        '\.jsp', 
        '\/\.bash', 
        '\/\.git', 
        '\/\.svn', 
        '\/\.tar', 
        ' ', 
        '\<', 
        '\>', 
        '\/\=', 
        '\.\.\.', 
        '\+\+\+', 
        '\/&&', 
        '\/Nt\.', 
        '\;Nt\.', 
        '\=Nt\.', 
        '\,Nt\.', 
        '\.exec\(', 
        '\)\.html\(', 
        '\{x\.html\(', 
        '\(function\(', 
        '\.php\([0-9]+\)', 
        '(benchmark|sleep)(\s|%20)*\('
    );
    
    /**
     * Suspicious query strings
    */
    private $query_strings = array(
        '\.\.\/', 
        '127\.0\.0\.1', 
        'localhost', 
        'loopback', 
        '\%0A', 
        '\%0D', 
        '\%00', 
        '\%2e\%2e', 
        'input_file', 
        'execute', 
        'mosconfig', 
        'path\=\.', 
        'mod\=\.', 
        'config\.php',
        'database\.php'
    );    
    
    /**
     * Suspicious user agents
    */
    private $user_agents = array(
        'acapbot', 
        'binlar', 
        'casper', 
        'cmswor', 
        'diavol', 
        'dotbot', 
        'finder', 
        'flicky', 
        'morfeus', 
        'nutch', 
        'planet', 
        'purebot', 
        'pycurl', 
        'semalt', 
        'skygrid', 
        'snoopy', 
        'sucker', 
        'turnit', 
        'vikspi', 
        'zmeu',
        'java'        
    );
    
    private $request_uri_string = false;
    private $query_string_string = false;
    private $user_agent_string = false;
    
    private $bbq_log_enable;
    private $bbq_log_file;
    private $bbq_log_seperator;
    private $bbq_time_format;
    
	public function __construct($params = array('log_enable' => false, 'log_file' => 'application/logs/bbq.log', 'log_seperator' => '|', 'time_format' => 'Y-m-d H:i:s'))
	{
        $CI =& get_instance();        
        $CI->load->helper(array('file'));
        
        $this->bbq_log_enable = $params['log_enable'];
        $this->bbq_log_file = $params['log_file'];
        $this->bbq_log_seperator = $params['log_seperator'];
        $this->bbq_time_format = $params['time_format'];
		$this->init_core_protection();
	}
    
    private function init_core_protection()
    {
        if (isset($_SERVER['REQUEST_URI']) && !empty($_SERVER['REQUEST_URI']))
        {
            $this->request_uri_string  = $_SERVER['REQUEST_URI'];
        }
        
        if (isset($_SERVER['QUERY_STRING']) && !empty($_SERVER['QUERY_STRING']))
        {
            $this->query_string_string = $_SERVER['QUERY_STRING'];
        }
        
        if (isset($_SERVER['HTTP_USER_AGENT']) && !empty($_SERVER['HTTP_USER_AGENT']))
        {
            $this->user_agent_string = $_SERVER['HTTP_USER_AGENT'];
        }
        
        if ($this->request_uri_string || $this->query_string_string || $this->user_agent_string) 
        {
            if (preg_match('/'. implode('|', $this->request_uris)  .'/i', $this->request_uri_string) ||
                preg_match('/'. implode('|', $this->query_strings) .'/i', $this->query_string_string) || 
                preg_match('/'. implode('|', $this->user_agents)   .'/i', $this->user_agent_string)) 
            {
                $user_ip = $this->visitor_ip();
                $user_time = date($this->bbq_time_format);
             
                $data = $user_time.$this->bbq_log_seperator.$user_ip.$this->bbq_log_seperator.$this->request_uri_string.$this->bbq_log_seperator.$this->query_string_string.$this->bbq_log_seperator.$this->user_agent_string.PHP_EOL;
                                
                try 
                {
                    write_file($this->bbq_log_file, $data, 'a');
                }
                catch (Exception $e)
                {
                    // ignore any logging error
                }
                
                $this->bbq_response();
            }		
	   }
    }
    
    private function visitor_ip() {
        $ipaddress = '';
        if (getenv('HTTP_CLIENT_IP'))
            $ipaddress = getenv('HTTP_CLIENT_IP');
        else if(getenv('HTTP_X_FORWARDED_FOR'))
            $ipaddress = getenv('HTTP_X_FORWARDED_FOR');
        else if(getenv('HTTP_X_FORWARDED'))
            $ipaddress = getenv('HTTP_X_FORWARDED');
        else if(getenv('HTTP_FORWARDED_FOR'))
            $ipaddress = getenv('HTTP_FORWARDED_FOR');
        else if(getenv('HTTP_FORWARDED'))
            $ipaddress = getenv('HTTP_FORWARDED');
        else if(getenv('REMOTE_ADDR'))
            $ipaddress = getenv('REMOTE_ADDR');
        else
            $ipaddress = 'UNKNOWN';

        return $ipaddress;
    }
    
    private function bbq_response()
    {
       header('HTTP/1.1 403 Forbidden');
	   header('Status: 403 Forbidden');
	   header('Connection: Close');
	   exit;
    }
}
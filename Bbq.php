<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');
/*
	Class name: BBQ (block bad queries)
    Original Author: Jeff Starr
    Author URI: https://plugin-planet.com/
    Donate link: http://m0n.co/donate
    Ported to CI3 by: Jonathan Lindgren
    License: GPLv2 or later
    
    Customized to work with Codeigniter 3.
    - Added a couble of bad user agents
    - Added Codeigniter specific config files
    - Added logging functionality
    
    USES getenv SO YOU NEED PHP 5.3+
    
    Example usage (logging will be disabled):
    $this->load->library('bbq');
    
    or you can load it in the constructor of a controller
    
    Default params:
    $params = array(
        'log_enable' => false,
        'log_file' => 'application/log/bbq.log',
        'log_seperator' => '|',
        'time_format' => 'Y-m-d H:i:s',
        'bad_lang' => true,
        'message' => ''
    );
    
    $this->load->library('bbq', $params);
*/

class Bbq {
	
	/**
     * Suspicious URIs
     * Perishablepress 6G
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
     * Perishablepress 6G
     * Plus some Codeigniter configs
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
        'database\.php',
        'mobiquo\.php',
        'phpinfo\.php',
        'shell\.php',
        'sqlpatch\.php',
        'thumb\.php',
        'thumb_editor\.php',
        'thumbopen\.php',
        'timthumb\.php',
        'webshell\.php'
    );
    
    /* Suspicious query strings Part 2
     * Contains some common spam words
     * Set bad_lang to true
    */
    private $query_strings_pt2 = array(
        'ultram',
        'unicauca',
        'valium',
        'viagra',
        'vicodin',
        'xanax',
        'ypxaieo',
        'erections',
        'hoodia',
        'huronriveracres',
        'impotence',
        'levitra',
        'libido',
        'ambien',
        'cialis',
        'cocaine',
        'ejaculation',
        'erectile',
        'lipitor',
        'phentermin',
        'pro[sz]ac',
        'sandyauer',
        'tramadol',
        'troyhamby'
    );
    
    /**
     * Suspicious user agents
     * Perishablepress 6G
     * Plus some custom entries
    */
    private $user_agents = array(
        'abonti',
        'acapbot',
        'aggregator',
        'ahrefsbot',
        'almaden',
        'anarchie',
        'archive.org',
        'binlar',
        'casper',
        'checkpriv',
        'choppy',
        'clshttp',
        'cmsworld',
        'diavol',
        'dotbot',
        'extract',
        'feedfinder',
        'aspseek',
        'asterias',
        'autoemailspider',
        'backweb',
        'bandit',
        'batchftp',
        'bdcbot',
        'blackwidow',
        'blexbot',
        'bolt',
        'buddy',
        'builtbottough',
        'bullseye',
        'bumblebee',
        'bunnyslippers',
        'ca-crawler',
        'cazoodlebot',
        'ccbot',
        'cegbfeieh',
        'cheesebot',
        'cherrypicker',
        'cherrypickerelite',
        'cherrypickerse',
        'chinaclaw',
        'cicc',
        'coccoc',
        'collector',
        'copier',
        'copyrightcheck',
        'cosmos',
        'crescent',
        'custo',
        'diibot',
        'discobot',
        'dittospyder',
        'doc',
        'dotbot',
        'drip',
        'dsurf15a',
        'easouspider',
        'ecatch',
        'ecxi',
        'eirgrabber',
        'emailcollector',
        'emailsiphon',
        'emailwolf',
        'erocrawler',
        'exabot',
        'extractorpro',
        'eyenetie',
        'fasterfox',
        'feedbooster',
        'finder',
        'flicky',
        'g00g1e',
        'harvest',
        'heritrix',
        'httrack',
        'kmccrew',
        'loader',
        'miner',
        'flashget',
        'foobot',
        'frontpage',
        'genieo',
        'getright',
        'getsmart',
        'getweb',
        'gigabaz',
        'go!zilla',
        'go-ahead-got-it',
        'gotit',
        'grabber',
        'grabnet',
        'grafula',
        'grub-client',
        'harvest',
        'heritrix',
        'hloader',
        'hmview',
        'httpdown',
        'httplib',
        'httrack',
        'humanlinks',
        'id-search',
        'idbot',
        'ieautodiscovery',
        'incutio',
        'infonavirobot',
        'interget',
        'internetlinkagent',
        'internetseer',
        'iria',
        'irlbot',
        'istellabot',
        'java',
        'jennybot',
        'jetcar',
        'justview',
        'k2spider',
        'kenjin spider',
        'keyword density',
        'larbin',
        'leechftp',
        'lexibot',
        'lftp',
        'libweb',
        'libwww',
        'libwww-perl',
        'likse',
        'link*sleuth',
        'linkextractorpro',
        'linko',
        'linkscan',
        'linkwalker',
        'lmspider',
        'lnspiderguy',
        'lwp-trivial',
        'mag-net',
        'magpie',
        'mata hari',
        'maxpointcrawler',
        'maxthon$',
        'megaindex',
        'memo',
        'memorybot',
        'mfc_tear_sample',
        'microsoft url control',
        'midown',
        'miixpc',
        'mippin',
        'missigua locator',
        'mister pix',
        'mj12bot',
        'moget',
        'morfeus',
        'nikto',
        'nutch',
        'planetwork',
        'postrank',
        'purebot',
        'pycurl',
        'python',
        'seekerspider',
        'msiecrawler',
        'navroad',
        'nearsite',
        'netants',
        'netmechanic',
        'netspider',
        'nicerspro',
        'niki-bot',
        'ninja',
        'npbot',
        'nutch',
        'octopus',
        'offline explorer',
        'openfind',
        'openfind data gathere',
        'pagegrabber',
        'panscient',
        'pavuk',
        'pcbrowser',
        'peoplepal',
        'phpcrawl',
        'pingalink',
        'pleasecrawl',
        'pockey',
        'propowerbot',
        'prowebwalker',
        'psbot',
        'pump',
        'python-urllib',
        'qrva',
        'queryn metasearch',
        'reaper',
        'recorder',
        'reget',
        'repomonkey',
        'rippers',
        'rma',
        'sbider',
        'scooter',
        'seamonkey$',
        'seeker',
        'semalt',
        'siclab',
        'skygrid',
        'semrushbot',
        'serf',
        'seznambot',
        'siphon',
        'sistrix',
        'sitecheck',
        'sitesnagger',
        'slysearch',
        'smartdownload',
        'snake',
        'snappreviewbot',
        'snoopy',
        'sqlmap',
        'sucker',
        'turnit',
        'vikspider',
        'winhttp',
        'xxxyy',
        'youda',
        'zmeu',
        'zune',
        'sogou',
        'spacebison',
        'spankbot',
        'spanner',
        'spbot',
        'spinn3r',
        'sproose',
        'steeler',
        'stripper',
        'sucker',
        'superbot',
        'superhttp',
        'suzuran',
        'szukacz',
        'takeout',
        'teleport',
        'teleportpro',
        'telesoft',
        'intraformant',
        'thenomad',
        'tighttwatbot',
        'titan',
        'tocrawl',
        'true_robot',        
        'turingos',
        'turnitinbot',
        'ubicrawler',
        'unisterbot',
        'unknown',
        'urlspiderpro',
        'urly warning',
        'vacuum',
        'vci',        
        'voideye',
        'wbsearchbot',
        'web downloader',
        'web image collector',
        'webalta',
        'webauto',
        'webbandit',
        'webcollage',
        'webcopier',
        'webemailextrac',
        'webenhancer',
        'webfetch',
        'webgo',
        'webhook',
        'webleacher',
        'webmasterworldforumbot',
        'webminer',
        'webmirror',
        'webreaper',
        'websauger',
        'website quester',
        'webster pro',
        'webstripper',
        'webzip',
        'whacker',
        'widow',
        'win32',
        'wotbox',
        'wsr-agent',
        'www-collector-e',
        'www-mechanize',
        'wwwoffle',
        'x-tractor',
        'xaldon',
        'xenu',
        'yandex',
        'zao',
        'zermelo',
        'zeus',
        'zyborg'
    );
    
    private $request_uri_string = false;
    private $query_string_string = false;
    private $user_agent_string = false;
    
    private $bbq_log_enable;
    private $bbq_log_file;
    private $bbq_log_seperator;
    private $bbq_time_format;
    private $bbq_bad_lang;
    private $bbq_message;
    
	/**
     * We are loading all the params in the constructor and
     * loading CI. Isn't really needed, you can use native
     * PHP if you want to.
    */
    public function __construct($params = array('log_enable' => false, 'log_file' => 'application/logs/bbq.log', 'log_seperator' => '|', 'time_format' => 'Y-m-d H:i:s', 'bad_lang' => true, 'message' => ''))
	{
        $CI =& get_instance();        
        $CI->load->helper(array('file'));
        
        $this->bbq_log_enable = $params['log_enable'];
        $this->bbq_log_file = $params['log_file'];
        $this->bbq_log_seperator = $params['log_seperator'];
        $this->bbq_time_format = $params['time_format'];
        $this->bbq_bad_lang = $params['bad_lang'];
        $this->bbq_message = $params['message'];
        
        if ($this->bbq_bad_lang == true)
        {
            $this->query_strings = array_merge($this->query_strings, $this->query_strings_pt2);
        }
        
		$this->init_core_protection();
	}
    
    /**
     * Core filtering function
     * Uses a try block when writing to file
     * if any errors it skips right to the bbq_response()          
    */
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
        elseif (isset($_SERVER['HTTP_USER_AGENT']) && empty($_SERVER['HTTP_USER_AGENT']))
        {
            $this->user_agent_string = '';
        }
        
        if ($this->request_uri_string || $this->query_string_string || $this->user_agent_string) 
        {
            if (preg_match('/'. implode('|', $this->request_uris)  .'/i', $this->request_uri_string) ||
                preg_match('/'. implode('|', $this->query_strings) .'/i', $this->query_string_string) || 
                preg_match('/'. implode('|', $this->user_agents)   .'/i', $this->user_agent_string)) 
            {
                if ($this->bbq_log_enable)
                {
                    try 
                    {
                        $log_data = date($this->bbq_time_format).$this->bbq_log_seperator;
                        $log_data .= $this->visitor_ip().$this->bbq_log_seperator;
                        $log_data .= $this->request_uri_string.$this->bbq_log_seperator;
                        $log_data .= $this->query_string_string.$this->bbq_log_seperator;
                        $log_data .= $this->user_agent_string.PHP_EOL;
                        write_file($this->bbq_log_file, $log_data, 'a');
                    }
                    catch (Exception $e)
                    {
                        // ignore any logging error
                    }
                }
                
                $this->bbq_response();
            }		
	   }
    }
    
    /**
     * Gets the visitors IP by using getenv
     * Requires PHP 5.3+
     * @return string
    */
    private function visitor_ip() {
        $ipaddress = '';
        if (getenv('HTTP_CLIENT_IP'))
        {
            $ipaddress = getenv('HTTP_CLIENT_IP');
        }
        else if(getenv('HTTP_X_FORWARDED_FOR'))
        {
            $ipaddress = getenv('HTTP_X_FORWARDED_FOR');
        }
        else if(getenv('HTTP_X_FORWARDED'))
        {
            $ipaddress = getenv('HTTP_X_FORWARDED');
        }
        else if(getenv('HTTP_FORWARDED_FOR'))
        {
            $ipaddress = getenv('HTTP_FORWARDED_FOR');
        }
        else if(getenv('HTTP_FORWARDED'))
        {
            $ipaddress = getenv('HTTP_FORWARDED');
        }
        else if(getenv('REMOTE_ADDR'))
        {
            $ipaddress = getenv('REMOTE_ADDR');
        }
        else
        {
            $ipaddress = 'UNKNOWN';
        }

        return $ipaddress;
    }
    
    /**
     * Outputs 403 status headers with
     * an optional message.
     * exit() is required
    */
    private function bbq_response()
    {
        header('HTTP/1.1 403 Forbidden');
        header('Status: 403 Forbidden');
        header('Connection: Close');
        exit($this->bbq_message);
    }
}
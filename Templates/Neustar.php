<?php
/**
 * Novutec Domain Tools
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @category   Novutec
 * @package    DomainParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * @namespace Novutec\Whois\Parser\Templates
 */
namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Regex;

/**
 * Template for Neustar (.BIZ, .CO, .US, .TRAVEL)
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Neustar extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/domain name:(?>[\x20\t]*)(.*?)(?=registry registrant id\:)/is', 
            2 => '/registry registrant id:(?>[\x20\t]*)(.*?)(?=registry admin id\:)/is', 
            3 => '/registry admin id:(?>[\x20\t]*)(.*?)(?=registry tech id\:)/is', 
            4 => '/registry tech id:(?>[\x20\t]*)(.*?)(?=name server\:)/is',
            5 => '/name server:(?>[\x20\t]*)(.*?)(?=dnssec\:)/is',
            6 => '/dnssec:(?>[\x20\t]*)(.*?)(?=>>>)/is');

    /**
	 * items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array( 
                    '/registrar url \(registration services\):(?>[\x20\t]*)(.+)$/im' => 'registrar:url',
                    '/updated date:(?>[\x20\t]*)(.+)$/im' => 'changed',
                    '/creation date:(?>[\x20\t]*)(.+)$/im' => 'created',
                    '/registry expiry date:(?>[\x20\t]*)(.+)$/im' => 'expires',
                    '/registrar:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/registrar iana id:(?>[\x20\t]*)(.+)$/im' => 'registrar:id',
                    '/(?>domain )*status:(?>[\x20\t]*)([^\x20\t]+)[ ]+.+$/im' => 'status'), 
            2 => array(
                    '/registrant id:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:handle', 
                    '/registrant name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/registrant organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/registrant address[0-9]*:(?>[\x20\t]+)(.+)$/im' => 'contacts:owner:address', 
                    '/registrant city:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/registrant state\/province:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:state', 
                    '/registrant postal code:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/registrant country code:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/registrant phone number:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/registrant facsimile number:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax', 
                    '/registrant email:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email', 
                    '/registrant application purpose:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:application_purpose', 
                    '/registrant nexus category:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:nexus_category'), 
            3 => array(
                    '/administrative contact id:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:handle', 
                    '/administrative contact name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/administrative contact organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/administrative contact address[0-9]*:(?>[\x20\t]+)(.+)$/im' => 'contacts:admin:address', 
                    '/administrative contact city:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city', 
                    '/administrative contact state\/province:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:state', 
                    '/administrative contact postal code:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode', 
                    '/administrative contact country code:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/administrative contact phone number:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/administrative contact facsimile number:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax', 
                    '/administrative contact email:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email', 
                    '/administrative application purpose:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:application_purpose', 
                    '/administrative nexus category:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:nexus_category'),
            4 => array(
                    '/technical contact id:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle', 
                    '/technical contact name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/technical contact organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/technical contact (street|address)[0-9]*:(?>[\x20\t]+)(.+)$/im' => 'contacts:tech:address', 
                    '/technical contact city:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/technical contact state\/province:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:state', 
                    '/technical contact postal code:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode', 
                    '/technical contact country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/technical contact phone number:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/technical contact facsimile number:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/technical contact email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email', 
                    '/technical application purpose:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:application_purpose', 
                    '/technical nexus category:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:nexus_category'), 
            5 => array(
                    '/name server:(?>[\x20\t]+)(.+)$/im' => 'nameserver'),
            6 => array(
                    '/dnssec:(?>[\x20\t]*)(.+)$/im' => 'dnssec'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No Data Found/i';

    /**
     * After parsing ...
     *
     * If dnssec key was found we set attribute to true.
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        if (preg_match("/unsigned/i", $ResultSet->dnssec)) {
            $ResultSet->dnssec = false;
        } else {
            $ResultSet->dnssec = true;
        }
    }
}
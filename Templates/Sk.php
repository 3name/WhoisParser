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
 * Template for .SK
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Sk extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     * @access protected
     */
    protected $blocks = array(
        1 => '/\nContact(.*?)(?=Updated)/s',
        2 => '/\nRegistrar(.*?)(?=Contact)/s',
        3 => '/Domain(.*?)(?=\n\nRegistrar)/s',
    );

    /**
     * Items for each block
     *
     * @var array
     * @access protected
     */
    protected $blockItems = array(
        1 => array(
            '/Contact:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:handle',
            '/Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name',
            '/Street:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address',
            '/City:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city',
            '/Country Code:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country',
            '/Postal Code:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode',
            '/Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone',
            '/Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email',
            '/Organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization',
            '/Organization ID:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:orgid',
        ),

        2 => array(
            '/Registrar:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle',
            '/Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name',
            '/Street:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address',
            '/Postal Code:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode',
            '/City:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city',
            '/Country Code:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country',
            '/Postal Code:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode',
            '/Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone',
            '/Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email',
            '/Organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization',
            '/Organization ID:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:orgid',
        ),

        3 => array(
            '/Nameserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver',
            '/Created:(?>[\x20\t]*)(.+)$/im' => 'created',
            '/Updated:(?>[\x20\t]*)(.+)$/im' => 'changed',
            '/Valid Until:(?>[\x20\t]*)(.+)$/im' => 'expires',
            '/EPP status:(?>[\x20\t]*)(.+)$/im' => 'status',
        ),
    );

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Not found./i';
}

<?php

namespace SOUtils;

class XMLConverter {
    // Converts passed string to XML element object
    // @param [string] $str with raw XML
    // @return [\DOMElement] the XML element object
    public static function str_to_xml($str) {
        return dom_import_simplexml(simplexml_load_string($str));
    }

    // Converts passed XML element object to string
    // @param $xml element object
    // @return [string] the string with xml
    public static function xml_to_str(\DOMElement $xml) {
        return $xml->ownerDocument->saveXML($xml);
    }
}

?>

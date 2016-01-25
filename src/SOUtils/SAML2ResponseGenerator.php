<?php

namespace SOUtils;

define('DEFAULT_RESPONSE_TIME_DELTA', 300); // 5 min

require_once('LibsLoader.php');
require_once('MissingValueException.php');
require_once('SAML2Constants.php');
require_once('XMLConverter.php');

class SAML2ResponseGenerator {
    // Generates NameID value which could be sent to SAML2 lib generators
    // @param [string] $value of NameID field
    // @return [array] the value which contain correct format of NameID field
    public static function build_name_id($value) {
        return array(
            'Format' => SAML_NAMEID_FORMAT,
            'Value' => ($value ? $value : '')
        );
    }

    // Modifies the passed original SAML Response
    // @param [string] $original_response_str the SAML Response which should be modified
    // @param $values is the configuration array which should contain all necessary data
    // @return [string] the XML string with generated SAML Response
    public static function modify_response($original_response_str, array $values) {
        $original_response = new \SAML2_Response(XMLConverter::str_to_xml($original_response_str));
        $modified_response = self::combine_response($values, $original_response);
        return self::to_str($modified_response, $values);
    }

    // Generates XML string which contains SAML Response
    // @param $values is the configuration array which should contain all necessary data
    // @return [string] the XML string with generated SAML Response
    public static function generate(array $values) {
        if (empty($values)) {
            throw new MissingValueException('Passed values could not be empty');
        } else if (!array_key_exists('Issuer', $values)) {
            throw new MissingValueException('Issuer value should be present');
        } else if (!array_key_exists('NameID', $values)) {
            throw new MissingValueException('NameID value should be present');
        } else if (!array_key_exists('AllowedTimeDelta', $values) || !is_int($values['AllowedTimeDelta'])) {
            throw new MissingValueException('AllowedTimeDelta value should be present and should be int');
        } else if (!array_key_exists('Audience', $values)) {
            throw new MissingValueException('Audience value should be present');
        } else if (!array_key_exists('Attributes', $values) || !is_array($values['Attributes'])) {
            throw new MissingValueException('Attributes value should be present and should be associative array');
        } else if (!array_key_exists('AuthnContextClassRef', $values)) {
            throw new MissingValueException('AuthnContextClassRef value should be present');
        } else if (!array_key_exists('SessionIndex', $values)) {
            throw new MissingValueException('SessionIndex value should be present');
        } else if (!array_key_exists('Destination', $values)) {
            throw new MissingValueException('Destination value should be present');
        } else {
            if (self::need_sign($values)) {
                if (!array_key_exists('SHA256KeyFile', $values)) {
                    throw new MissingValueException('SHA256KeyFile value should be present');
                } else if (!file_exists($values['SHA256KeyFile'])) {
                    throw new MissingValueException('Certificate key file ' . $values['SHA256KeyFile'] .' doesn\'t exist');
                } else if (!array_key_exists('SHA256CertFile', $values)) {
                    throw new MissingValueException('SHA256CertFile value should be present');
                } else if (!file_exists($values['SHA256CertFile'])) {
                    throw new MissingValueException('Certificate file ' . $values['SHA256CertFile'] .' doesn\'t exist');
                }
            } else {
                if (array_key_exists('SHA256KeyFile', $values) || array_key_exists('SHA256CertFile', $values)) {
                    throw new MissingValueException('Certificate file passed, but any sign off');
                }
            }
        }

        return self::safe_generate($values);
    }

    // Generates XML string without checking that all necessary values are set
    // @param $values is the configuration array
    // @return [string] the XML string with generated SAML Response
    public static function safe_generate(array $values) {
        $response = self::combine_response($values);
        return self::to_str($response, $values);
    }

    // Checks that passed SAML Response should be signed or not by passed values
    // and converts it to XML string
    // @param $response which will be converted to XML string
    // @param $values is the configuration array
    // @return [string] the XML string with generated SAML Response
    private static function to_str(\SAML2_Response $response, array $values) {
        $xml = self::need_sign($values) ? $response->toSignedXML() : $response->toUnsignedXML();
        return XMLConverter::xml_to_str($xml);
    }

    // Combines the SAML Response by passed configuration array
    // @param $values is the configuration array
    // @param $response which will be modified if passed
    // @return [\SAML2_Response] the (re)combined SAML Response
    private static function combine_response(array $values, \SAML2_Response $response = NULL) {
        if (!isset($response)) $response = new \SAML2_Response();
        $presented_assertions = $response->getAssertions();
        $assertion = empty($presented_assertions) ? new \SAML2_Assertion() : $presented_assertions[0];

        if (self::original_spid_isset($values)) {
            $response->setInResponseTo($values['InResponseTo']);
        }

        if (array_key_exists('ResponseID', $values)) {
            $response->setId($values['ResponseID']);
        }

        if (array_key_exists('AssertionID', $values)) {
            $assertion->setId($values['AssertionID']);
        }

        if (array_key_exists('Issuer', $values)) {
            $response->setIssuer($values['Issuer']);
            $assertion->setIssuer($values['Issuer']);
        }

        if (array_key_exists('NameID', $values)) {
            $assertion->setNameId(self::build_name_id($values['NameID']));
        }

        $not_on_or_after_time = time();
        if (array_key_exists('AllowedTimeDelta', $values)) {
            $not_on_or_after_time += $values['AllowedTimeDelta'];
            $assertion->setNotBefore(time() - $values['AllowedTimeDelta']);
            $assertion->setNotOnOrAfter($not_on_or_after_time);
        } else {
            $not_on_or_after_time += DEFAULT_RESPONSE_TIME_DELTA;
        }

        if (array_key_exists('Audience', $values)) {
            $assertion->setValidAudiences(array($values['Audience']));
        }

        if (array_key_exists('Attributes', $values)) {
            $assertion->setAttributes($values['Attributes']);
        }

        $assertion->setAuthnInstant(time());
        if (array_key_exists('AuthnContextClassRef', $values)) {
            $assertion->setAuthnContextClassRef($values['AuthnContextClassRef']);
        }

        if (array_key_exists('SessionIndex', $values)) {
            $assertion->setSessionIndex($values['SessionIndex']);
        }

        if (self::original_spid_isset($values) || array_key_exists('Destination', $values)) {
            $original_confirmations = $assertion->getSubjectConfirmation();
            $confirmation = NULL;
            if (empty($original_confirmations)) {
                $confirmation = new \SAML2_XML_saml_SubjectConfirmation();
                $confirmation->Method = SAML_CONFIGURATION_METHOD;
            } else {
                $confirmation = $original_confirmations[0];
            }

            $original_data = $confirmation->SubjectConfirmationData;
            $data = NULL;
            if (empty($original_data)) {
                $data = new \SAML2_XML_saml_SubjectConfirmationData();
                $data->NotOnOrAfter = $not_on_or_after_time;
            } else {
                $data = $original_data;
                if (empty($data->NotOnOrAfter)) {
                    $data->NotOnOrAfter = $not_on_or_after_time;
                }
            }

            if (array_key_exists('Destination', $values)) {
                $data->Recipient = $values['Destination'];
            }

            if (self::original_spid_isset($values)) {
                $data->InResponseTo = $values['InResponseTo'];
            }

            $confirmation->SubjectConfirmationData = $data;
            $assertion->setSubjectConfirmation(array($confirmation));
        }

        if (array_key_exists('Destination', $values)) {
            $response->setDestination($values['Destination']);
        }

        if (self::need_sign($values)) {
            if (array_key_exists('SHA256KeyFile', $values)) {
                $ekey = new \XMLSecurityKey(\XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
                $ekey->loadKey($values['SHA256KeyFile'], true);

                if (self::need_sign_attributes($values)) $assertion->setSignatureKey($ekey);
                if (self::need_sign_message($values)) $response->setSignatureKey($ekey);
            }

            if (array_key_exists('SHA256CertFile', $values)) {
                $certifictaes = array(file_get_contents($values['SHA256CertFile']));

                if (self::need_sign_attributes($values)) $assertion->setCertificates($certifictaes);
                if (self::need_sign_message($values)) $response->setCertificates($certifictaes);
            }
        }

        $response->setAssertions(array($assertion));
        return $response;
    }

    // Checks that passed values contains InResponseTo field
    // @param $values is the configuration array
    // @return [bool] is set original spid or not
    private static function original_spid_isset(array $values) {
        return array_key_exists('InResponseTo', $values) && !empty($values['InResponseTo']);
    }

    // Checks that the wholly response should be signed
    // @param $values is the configuration array
    // @return [bool] is required to sign the response message
    private static function need_sign_message(array $values) {
        return array_key_exists('SignResponseMessage', $values) && $values['SignResponseMessage'];
    }

    // Checks that the response attributes should be signed
    // @param $values is the configuration array
    // @return [bool] is required to sign the response attributes
    private static function need_sign_attributes(array $values) {
        return array_key_exists('SignResponseAttributes', $values) && $values['SignResponseAttributes'];
    }

    // Checks that the response should be signed
    // @param $values is the configuration array
    // @return [bool] is required to sign the response
    private static function need_sign(array $values) {
        return self::need_sign_message($values) || self::need_sign_attributes($values);
    }
}

?>

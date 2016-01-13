<?php

require_once('libs_loader.php');
require_once('saml_constants.php');
require_once('xml_converter.php');

namespace SOUtils;

class IncorrectFieldException extends Exception {}

// Wraps original SAML2 Response object for provides short call ways to get neccessary attributes
class WrappedSAML2Response {
    protected $xml;
    private $saml;

    // Initializes authn response by xml
    // @param $str with xml which describes request
    public function __construct($str) {
        $this->xml = XMLConverter::str_to_xml($str);
        $this->saml = new SAML2_Response(XMLConverter::str_to_xml($str));
    }

    // @return [string]
    public function get_destination() {
        $destination = $this->saml->getDestination();
        if ($destination === NULL) {
            throw new IncorrectFieldException('Destination could not be found');
        }

        return $destination;
    }

    // @return [string]
    public function get_recipient() {
        $recipient = $this->confirmation_data()->Recipient;
        if ($recipient === NULL) {
            throw new IncorrectFieldException('Recipient could not be found');
        }

        return $recipient;
    }

    // @return [string]
    public function get_response_id() {
        $id = $this->saml->getId();
        if (empty($id)) {
            throw new IncorrectFieldException('Response ID could not be found');
        }

        return $id;
    }

    // @return [string]
    public function get_assertion_id() {
        $id = $this->assertion()->getId();
        if (empty($id)) {
            throw new IncorrectFieldException('Assertion ID could not be found');
        }

        return $id;
    }

    // @return [string]
    public function get_name_id() {
        $name_id = $this->assertion()->getNameId();
        if (empty($name_id) || $name_id['Value'] === NULL) {
            throw new IncorrectFieldException('Name ID value could not be found');
        }

        return $name_id['Value'];
    }

    // @return [string]
    public function get_session_index() {
        $session_index = $this->assertion()->getSessionIndex();
        if ($session_index === NULL) {
            throw new IncorrectFieldException('Session index could not be found');
        }

        return $session_index;
    }

    // @return [string]
    public function get_audience() {
        $audiences = $this->assertion()->getValidAudiences();
        if (count($audiences) != 1) {
            throw new IncorrectFieldException('Incorrect number of audiences');
        }

        return $audiences[0];
    }

    // @return [string]
    public function get_authn_context_class_ref() {
        $context_class_ref = $this->assertion()->getAuthnContextClassRef();
        if ($context_class_ref === NULL) {
            throw new IncorrectFieldException('Authentication context class reference could not be found');
        }

        return $context_class_ref;
    }

    // @return [string]
    public function has_attribute($name) {
        $attributes = $this->get_attributes();
        return array_key_exists($name, $attributes);
    }

    // @return [string]
    public function get_attribute($name, $is_required=false) {
        $attributes = $this->get_attributes();
        if (array_key_exists($name, $attributes)) {
            return $attributes[$name];
        } else if (!$is_required) {
            return array('');
        } else {
            throw new IncorrectFieldException('Attribute "' . $name . '" could not be found');
        }
    }

    public function get_one_attribute($name) {
        $values = $this->get_attribute($name, true);
        if (count($values) != 1) {
            throw new IncorrectFieldException('Incorrect number of "' . $name . '" values');
        }

        return $values[0];
    }

    // @return [array]
    public function get_attributes() {
        return $this->assertion()->getAttributes();
    }

    // @return [string]
    protected function get_status() {
        $status = $this->saml->getStatus();
        if (empty($status)) {
            throw new IncorrectFieldException('Status could not be found');
        }

        return $status['Code'];
    }

    // @return [SAML2_Assertion]
    protected function assertion() {
        $assertions = $this->saml->getAssertions();
        if (count($assertions) != 1) {
            throw new IncorrectFieldException('Incorrect number of assertions');
        }

        return $assertions[0];
    }

    // @return [SAML2_XML_saml_SubjectConfirmationData]
    private function confirmation_data() {
        $confirmations = $this->assertion()->getSubjectConfirmation();
        if (count($confirmations) != 1) {
            throw new IncorrectFieldException('Incorrect number of confirmations');
        }

        $confirmation = $confirmations[0];
        if ($confirmation->SubjectConfirmationData === NULL) {
            throw new IncorrectFieldException('Subject confirmation data could not be found');
        }

        return $confirmation->SubjectConfirmationData;
    }
}

?>

<?php

namespace SOUtils;

require_once('LibsLoader.php');
require_once('IncorrectFieldException.php');
require_once('SAML2Constants.php');
require_once('XMLConverter.php');

// Wraps original SAML2 Response object for provides short call ways to get neccessary attributes
class WrappedSAML2Response {
    private $response;

    // Initializes authn response by xml
    // @param $str with xml which describes request
    public function __construct($str) {
        $this->response = new \SAML2_Response(XMLConverter::str_to_xml($str));
    }

    // @return [string]
    public function get_issuer() {
        $issuer = $this->response->getIssuer();
        if ($issuer === NULL) {
            throw new IncorrectFieldException('Issuer cannot be found');
        }

        return $issuer;
    }

    // @return [string]
    public function get_destination() {
        $destination = $this->response->getDestination();
        if ($destination === NULL) {
            throw new IncorrectFieldException('Destination cannot be found');
        }

        return $destination;
    }

    // @return [string]
    public function get_recipient() {
        $recipient = $this->confirmation_data()->Recipient;
        if ($recipient === NULL) {
            throw new IncorrectFieldException('Recipient cannot be found');
        }

        return $recipient;
    }

    // @return [string]
    public function get_in_response_to() {
        $value = $this->response->getInResponseTo();
        if (empty($value)) {
            throw new IncorrectFieldException('Value of InResponseTo field cannot be found');
        }

        return $value;
    }

    // @return [string]
    public function get_response_id() {
        $id = $this->response->getId();
        if (empty($id)) {
            throw new IncorrectFieldException('Response ID cannot be found');
        }

        return $id;
    }

    // @return [string]
    public function get_assertion_id() {
        $id = $this->assertion()->getId();
        if (empty($id)) {
            throw new IncorrectFieldException('Assertion ID cannot be found');
        }

        return $id;
    }

    // @return [string]
    public function get_name_id() {
        $name_id = $this->assertion()->getNameId();
        if (empty($name_id) || $name_id['Value'] === NULL) {
            throw new IncorrectFieldException('Name ID value cannot be found');
        }

        return $name_id['Value'];
    }

    // @return [string]
    public function get_session_index() {
        $session_index = $this->assertion()->getSessionIndex();
        if ($session_index === NULL) {
            throw new IncorrectFieldException('Session index cannot be found');
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
            throw new IncorrectFieldException('Authentication context class reference cannot be found');
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
            throw new IncorrectFieldException('Attribute "' . $name . '" cannot be found');
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

    // @return [array]
    public function get_not_before() {
        return $this->assertion()->getNotBefore();
    }

    // @return [array]
    public function get_not_on_or_after() {
        return $this->assertion()->getNotOnOrAfter();
    }

    // @return [string]
    protected function get_status() {
        $status = $this->response->getStatus();
        if (empty($status)) {
            throw new IncorrectFieldException('Status cannot be found');
        }

        return $status['Code'];
    }

    // @return [\SAML2_Assertion]
    protected function assertion() {
        $assertions = $this->response->getAssertions();
        if (count($assertions) != 1) {
            throw new IncorrectFieldException('Incorrect number of assertions');
        }

        return $assertions[0];
    }

    // @return [\SAML2_XML_saml_SubjectConfirmationData]
    private function confirmation_data() {
        $confirmations = $this->assertion()->getSubjectConfirmation();
        if (count($confirmations) != 1) {
            throw new IncorrectFieldException('Incorrect number of confirmations');
        }

        $confirmation = $confirmations[0];
        if ($confirmation->SubjectConfirmationData === NULL) {
            throw new IncorrectFieldException('Subject confirmation data cannot be found');
        }

        return $confirmation->SubjectConfirmationData;
    }

    // @return [array]
    public function certificates() {
        return array_unique(array_merge(
            $this->response->getCertificates(),
            $this->assertion()->getCertificates()
        ));
    }
}

?>

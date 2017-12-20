<?php
	namespace signature_facturae;
	require('vendor/autoload.php');

	use RobRichards\XMLSecLibs\XMLSecEnc;
	use RobRichards\XMLSecLibs\XMLSecurityDSig;
	use RobRichards\XMLSecLibs\XMLSecurityKey;
	use DOMDocument;

	class signature_facturae {
		const ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

		private static function createSignedPropertiesNode () {
			$dom = new DOMDocument('1.0', 'utf-8');
			$QualifyingProperties = $dom->createElementNS('http://uri.etsi.org/01903/v1.3.2#', 'xades:QualifyingProperties');
			//$QualifyingProperties->setAttribute('Target', '#Signature');
			$dom->appendChild($QualifyingProperties);

			$SignedProperties = $dom->createElement('xades:SignedProperties', '');
			//$SignedProperties->setAttribute('Id', 'Signature-SignedProperties');
			$QualifyingProperties->appendChild($SignedProperties);

			$SignedSignatureProperties = $dom->createElement('xades:SignedSignatureProperties', '');
			$SignedProperties->appendChild($SignedSignatureProperties);

			$SigningTime = $dom->createElement('xades:SigningTime', date(DATE_ATOM));
			$SignedSignatureProperties->appendChild($SigningTime);

			$SignaturePolicyIdentifier = $dom->createElement('xades:SignaturePolicyIdentifier', '');
			$SignedSignatureProperties->appendChild($SignaturePolicyIdentifier);

			$SignaturePolicyId = $dom->createElement('xades:SignaturePolicyId', '');
			$SignaturePolicyIdentifier->appendChild($SignaturePolicyId);

			$SigPolicyId = $dom->createElement('xades:SigPolicyId', '');
			$SignaturePolicyId->appendChild($SigPolicyId);

			$Identifier = $dom->createElement('xades:Identifier', 'http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf');
			$Identifier->setAttribute('Qualifier', 'OIDAsURI');
			$SigPolicyId->appendChild($Identifier);

			$Description = $dom->createElement('xades:Description', 'Política de Firma FacturaE v3.1');
			$SigPolicyId->appendChild($Description);

			$SigPolicyHash = $dom->createElement('xades:SigPolicyHash', '');
			$SignaturePolicyId->appendChild($SigPolicyHash);

			$DigestMethod = $dom->createElement('ds:DigestMethod', '');
			$DigestMethod->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1');
			$SigPolicyHash->appendChild($DigestMethod);

			$DigestValue = $dom->createElement('ds:DigestValue', 'Ohixl6upD6av8N7pEvDABhEL6hM=');
			$SigPolicyHash->appendChild($DigestValue);

			$SignerRole = $dom->createElement('xades:SignerRole', '');
			$SignedSignatureProperties->appendChild($SignerRole);

			$SignerCalimedRoles = $dom->createElement('xades:ClaimedRoles', '');
			$SignerRole->appendChild($SignerCalimedRoles);

			$SignerCalimedRole = $dom->createElement('xades:ClaimedRole', 'emisor');
			$SignerCalimedRoles->appendChild($SignerCalimedRole);

			return $dom->documentElement;
		}

		public static function sign (DOMDocument $data, $privateKey, $publicKey) {
			$objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, ['type' => 'private']);
			$objKey->loadKey($privateKey);

			$objXMLSecDSig = new XMLSecurityDSig();
			$objXMLSecDSig->setCanonicalMethod(XMLSecurityDSig::C14N);
			$objXMLSecDSig->add509Cert($publicKey);

			$contentSignedProp = self::createSignedPropertiesNode();
			$objXMLSecDSig->addObject($contentSignedProp);

			$objXMLSecDSig->addReference($data, XMLSecurityDSig::SHA1, [self::ENVELOPED], ['force_uri' => true]);

			$objKeyInfo = $objXMLSecDSig->sigNode->getElementsByTagName('KeyInfo')->item(0);
			$objXMLSecDSig->addReference($objKeyInfo, XMLSecurityDSig::SHA1, [self::ENVELOPED], ['overwrite' => false]);

			$objSignedProperties = $objXMLSecDSig->sigNode->getElementsByTagName('xades:SignedProperties')->item(0);
			$objXMLSecDSig->addReference($objSignedProperties, XMLSecurityDSig::SHA1, [self::ENVELOPED], ['overwrite' => false]);

			$objXMLSecDSig->sign($objKey, $data->documentElement);
		}
	}

	$pkcs12_file = 'certificate_file.p12';
	$pkcs12_pass = 'MyPass2016';
	$file = 'factura-prueba-v1-2-0.xml';

	if (is_file($pkcs12_file) and !empty($pkcs12_pass)) {
		if (openssl_pkcs12_read(file_get_contents($pkcs12_file), $certs, $pkcs12_pass)) {
			$data = new DOMDocument();
			$data->load($file);
			signature_facturae::sign($data, $certs['pkey'], $certs['cert']);
			if (is_file($file . '.xsig')) unlink($file . '.xsig');
			$data->save($file . '.xsig');
		}
	}
?>

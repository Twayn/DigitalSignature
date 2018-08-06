package smevsingtest;

import java.security.cert.X509Certificate;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPMessage;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

class SmevSignValidator {
	private static final QName QNAME_SIGNATURE = new QName("http://www.w3.org/2000/09/xmldsig#", "Signature", "ds");

	static boolean validate(SOAPMessage signed) throws Exception {
		boolean coreValidity = true;

		Document doc = signed.getSOAPBody().extractContentAsDocument();

		NodeList signs = doc.getElementsByTagNameNS(QNAME_SIGNATURE.getNamespaceURI(), QNAME_SIGNATURE.getLocalPart());
		Element sign = (Element) signs.item(0);

		org.apache.xml.security.signature.XMLSignature sig = new org.apache.xml.security.signature.XMLSignature(sign, "");

		X509Certificate certificate = sig.getKeyInfo().getX509Certificate();

		if (!sig.checkSignatureValue(certificate.getPublicKey())) coreValidity = false;

		return coreValidity;
	}
}
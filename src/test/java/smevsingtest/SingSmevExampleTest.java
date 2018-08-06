package smevsingtest;

import static java.nio.charset.StandardCharsets.UTF_8;
import static smevsign.KeyStoreWrapper.getPrivateKey;
import static smevsign.KeyStoreWrapper.getX509Certificate;
import static smevsign.Resources.SIGNED_BY_CONSUMER;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.xml.soap.SOAPMessage;

import org.junit.Assert;
import org.junit.Test;

import smevsign.SignAttributesSupplier;
import smevsign.Signer;

public class SingSmevExampleTest{
	private static final String SEND_REQUEST_REQUEST_NO_ATTACH =
			"<S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\">\n" +
			"   <S:Body>\n" +
			"      <ns2:SendRequestRequest xmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\" xmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\" xmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\">\n" +
			"         <ns:SenderProvidedRequestData Id=\"SIGNED_BY_CONSUMER\" xmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\" xmlns:ns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\" xmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\">\t<ns:MessageID>db0486d0-3c08-11e5-95e2-d4c9eff07b77</ns:MessageID><ns2:MessagePrimaryContent><ns1:BreachRequest xmlns:ns1=\"urn://x-artefacts-gibdd-gov-ru/breach/root/1.0\"  xmlns:ns2=\"urn://x-artefacts-gibdd-gov-ru/breach/commons/1.0\"  xmlns:ns3=\"urn://x-artefacts-smev-gov-ru/supplementary/commons/1.0.1\" Id=\"PERSONAL_SIGNATURE\"> <ns1:RequestedInformation> <ns2:RegPointNum>Т785ЕС57</ns2:RegPointNum> </ns1:RequestedInformation> <ns1:Governance> <ns2:Name>ГИБДД РФ</ns2:Name> <ns2:Code>GIBDD</ns2:Code> <ns2:OfficialPerson> <ns3:FamilyName>Загурский</ns3:FamilyName> <ns3:FirstName>Андрей</ns3:FirstName> <ns3:Patronymic>Петрович</ns3:Patronymic> </ns2:OfficialPerson></ns1:Governance> </ns1:BreachRequest> </ns2:MessagePrimaryContent>\t<ns:TestMessage/></ns:SenderProvidedRequestData>\n" +
			"         <ns2:CallerInformationSystemSignature></ns2:CallerInformationSystemSignature>\n" +
			"      </ns2:SendRequestRequest>\n" +
			"   </S:Body>\n" +
			"</S:Envelope>";

	private static final String KEY_ALIAS = "test";
	private static final String KEY_PASSWORD = "123";

	@Test
	public void test() throws Exception {
		SOAPMessage signed = Signer.sign(SEND_REQUEST_REQUEST_NO_ATTACH.getBytes(UTF_8), new SignAttributes());
		Assert.assertTrue(SmevSignValidator.validate(signed));
		//signed.writeTo(new FileOutputStream(new File("C:\\FB\\SOAP.xml")));
	}

	static class SignAttributes implements SignAttributesSupplier {
		@Override public X509Certificate x509Certificate() throws Exception { return getX509Certificate(KEY_ALIAS); }
		@Override public PrivateKey privateKey() throws Exception { return getPrivateKey(KEY_ALIAS, KEY_PASSWORD.toCharArray()); }
		@Override public String forSignElementId() { return SIGNED_BY_CONSUMER; }
	}
}
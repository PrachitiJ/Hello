package com.example.encryption.impl;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONObject;
import org.json.XML;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.xml.soap.MessageFactory;
import jakarta.xml.soap.SOAPBody;
import jakarta.xml.soap.SOAPElement;
import jakarta.xml.soap.SOAPEnvelope;
import jakarta.xml.soap.SOAPHeader;
import jakarta.xml.soap.SOAPMessage;
import jakarta.xml.soap.SOAPPart;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class EncryptionDecryptionService {

	private static final String SECRET_KEY = "i3JSoK3GLDrLNm7UarrLf/7xE4JwO2e0h73xOz8sb1nTqIrgLxnfF4VDKfsaeFdtUMfHgseAV9rWV7giZZvXMwrDl8eaYVkCagmsUXI/zRLbXL3Qv3K0OKag5/GZWvWyEkis4HuGlbGqRyrt+cLXTCsnhH1NjJnBTro7l/EGZ1qJspiwLUdR3/xzIvV9QZC2RIg68DjRAhpke/dYj9KdUwmNpswjnBmVsBTTxXW214IrVs1CxMo/6JOXoRi9Rcj//a7hNzRMQ9zrDjfVQPVhZfm43mrB9XwKStqfFMBLd86bnbnAIk42oIk/GQUJqeiZDGMLA5lyPW+JYy5zlVwNcQ==";

	public ResponseEntity<String> encryptData(EncryptionRequestDto requestDto) throws IOException {

		// Convert json object to json string
		ObjectMapper objectMapper = new ObjectMapper();
		String jsonString = objectMapper.writeValueAsString(requestDto);
		jsonString = jsonString.trim();

		// IV
		byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		StringWriter writer = new StringWriter();

		try {
			Security.addProvider(new BouncyCastleProvider());

			// Generate Private Key
			String privateKeyString = "MIIEpAIBAAKCAQEAs9fbc+FjUw0i8t05/OoDxXh7E27LBsEjbLRSmv+aWKx/QCcI\n"
					+ "XPv+YwF0ULIZ3AuT+I1YKmfE//Fyg9KXrwsV52r1RWNpxk3mE+c3huTuVfh3sFZT\n"
					+ "EMSbvS6HxhjoC4Xp560BOwaTPfxKGfWYDqrKDhNn5Loa8kKaecpORg2sEfPpP1J6\n"
					+ "0vVrvQ/uMbSxkyp9tCbRTqrWl8w5ICUM1aYrN/Qqt4q43SMxhMtfcf9q723dXYCD\n"
					+ "wXZLV+72kgSaGx5aZi9/oS2iNi9G3t4ttuNNACQL1KZpE/twAY549EayNjOPzwyG\n"
					+ "RXp46Rw1EFAeE1hv+zdswcO8UNtPR0lHAb3AewIDAQABAoIBAAPJc9GI2XKSQD4k\n"
					+ "8mek9ddephjOqG/H+Vr8oRCqeTGM0FElgUOT+tNS4IQie/DqPX9qWoTqEnfhOawU\n"
					+ "7yS8cwWgdvGzGjMWyNV6dOzePTaKONr5tl4QBceCB1HgjGJRu48pUXFQviD8AwNw\n"
					+ "7HbCmeaZ+gIS+SZIyL/vxp4rA4iNNT7PSqLbW/utVhoMwWif2BFv+mBEJbe/3x/1\n"
					+ "uNEwusqyT9RnaRK8Rk47VLHW1vmLwjPvz5zV5KPEF4jhKYSgwD3pBUtTVpNrXcws\n"
					+ "rpCe62ciuw/PTTWGoHUQsMLUGkDAI4W/wma8SzI2CsFpzRZLHPdYb0yeB8Xvkf17\n"
					+ "GhjUPiECgYEA1yzzZCM7vLpnrpCaTtT+if4IuIZMAZaxFgxFZa9vZQ4OtEemDskN\n"
					+ "w+SvH/+uEz5zQsATOxjBmkecvkjMeWx4cb/f23Yl/4x5WxJU8metITwoN1AvNQd4\n"
					+ "zjviSCwRem7V+U6NrAjaafQTN1CjTOB2jO09Ac36QJDruwMuTuoxOCcCgYEA1fbR\n"
					+ "F8Wds6QsveNbCu1t3TZ64pG79aw4SPPPLyRxZc5sCxTDvbcUfjomF+bnFNZQudYw\n"
					+ "hWKs/2k6msuv5D7sPX1D6pi7mIFH4AL8euHbo5fO5pjN1OpoSwMMUMdOPwpyUGao\n"
					+ "YNLB1Vs0l3Mkj+H2zRRlhXhdEyFDcTIYFE1IdY0CgYEAobbQvUOVk8NsRM+8iN6e\n"
					+ "5kqbd0LHQLJmKLHUPhXZXFNyTZ9Dd/02cTEfRKc9xoy6x0Hfshxq9G45qPDBa8hP\n"
					+ "xP11WlSzPhnu4rkmSoAMp9u0Rc3njK0u56At8hvcju1ZtuKIqvCEZfjfsETUVeSk\n"
					+ "dEmf/gk1uOyxnX1IglqT3yUCgYEAloXZmUir5goUc83zaZ+Yz6wZDTWLLozm1+O1\n"
					+ "mKuhnwZ2GeGUxu16XEbaL6yAWrde+S3G2r+Nhu1njijHZ+IgXi22zt598w7YGq7f\n"
					+ "Ii+sTc1pf+51t1jk4AiX7GgaEt1tiESAJgV+2XMdb4JQcWx9LM8xkJEZoXCgOo0M\n"
					+ "RZQM6q0CgYBCwdjWEeamnbzUwyRLlbmrjqAGR2yB6NVWh+u8qZHAYRRs3mCkfaB2\n"
					+ "PGL/OrbEtZUb7JDCDeoDi1/xUsb4N7BbuNq8I6cBFLHmJZDSyxfmOOoX924D6q40\n"
					+ "/Dt2v1/4rOJBEDZN0iQasahhGZhIJMdaR1hCjAETlUIxz8tB1bcM+g==";
			privateKeyString = privateKeyString.replace("\n", "");
			KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(
					Base64.getDecoder().decode(privateKeyString.replace("\n", "")));
			PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

			// Secret key
			byte[] encryptedKey = Base64.getDecoder().decode(SECRET_KEY.getBytes());
			log.info("length : " + encryptedKey.length);
			Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] keyBytes = cipher.doFinal(encryptedKey);
			log.info("key bytes length : " +keyBytes.length);
			
			SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
			 log.info("encryption key : " + Base64.getEncoder().encodeToString(secretKey.getEncoded()));
			 
			// Encryption
			Cipher cipher1 = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher1.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
			String response = Base64.getEncoder()
					.encodeToString(cipher1.doFinal(jsonString.getBytes(StandardCharsets.UTF_8)));

			// Create Soap message
			SOAPMessage soapMessage = getSoapXML(response, privateKeyString , SECRET_KEY);

			// convert soap into string
			TransformerFactory transformerFactory = TransformerFactory.newInstance();
			Transformer transformer = transformerFactory.newTransformer();
			transformer.transform(new DOMSource(soapMessage.getSOAPPart()), new StreamResult(writer));
			log.info("soap response : " + writer.toString());

		} catch (Exception e) {
			e.printStackTrace();
		}

		return ResponseEntity.ok(writer.toString());
	}

	private SOAPMessage getSoapXML(String response, String privateKey , String enString) {
		SOAPMessage soapMessage = null;
		try {
			MessageFactory messageFactory = MessageFactory.newInstance();
			soapMessage = messageFactory.createMessage();

			SOAPPart soapPart = soapMessage.getSOAPPart();
			SOAPEnvelope envelope = soapPart.getEnvelope();
			envelope.setPrefix("soap");

			SOAPHeader soapHeader = soapMessage.getSOAPHeader();
			soapHeader.setPrefix("soap");
			SOAPElement securityElement = soapHeader.addChildElement("Security", "wsse",
					"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
			securityElement.addNamespaceDeclaration("wsu",
					"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
			SOAPElement encryptedKeyElement = securityElement.addChildElement("EncryptedKey", "xenc",
					"http://www.w3.org/2001/04/xmlenc#");
			SOAPElement encryptionMethodElement = encryptedKeyElement.addChildElement("EncryptionMethod", "xenc");
			encryptionMethodElement.addAttribute(envelope.createName("Algorithm"),
					"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");

			// Add the CipherData element
			SOAPElement cipherDataElement = encryptedKeyElement.addChildElement("CipherData", "xenc");
			SOAPElement cipherValueElement = cipherDataElement.addChildElement("CipherValue", "xenc");
			cipherValueElement.addTextNode(enString);

			SOAPElement binarySecurityTokenElement = securityElement.addChildElement("BinarySecurityToken", "wsse");
			binarySecurityTokenElement.setAttribute("EncodingType",
					"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
			binarySecurityTokenElement.setAttribute("ValueType",
					"http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey");
			binarySecurityTokenElement.setAttribute("wsu:Id", "X509-7ae0eacf-8c46-4525-ad96-4aa0612bc48c");
			binarySecurityTokenElement.setTextContent(privateKey); // Encode as Base64

			SOAPBody body = envelope.getBody();
			body.setPrefix("soap");
			SOAPElement encryptedDataElement = body.addChildElement("EncryptedData", "xenc",
					"http://www.w3.org/2001/04/xmlenc#");

			// Add EncryptionMethod element
			SOAPElement encryptionMethodElement1 = encryptedDataElement.addChildElement("EncryptionMethod", "xenc");
			encryptionMethodElement1.addAttribute(envelope.createName("Algorithm"),
					"http://www.w3.org/2001/04/xmlenc#aes128-cbc");

			// Add CipherData element
			SOAPElement cipherDataElement1 = encryptedDataElement.addChildElement("CipherData", "xenc");
			SOAPElement cipherValueElement1 = cipherDataElement1.addChildElement("CipherValue", "xenc");
			cipherValueElement1.addTextNode(response);
		} catch (Exception e) {
			e.getStackTrace();
		}
		return soapMessage;
	}

	public ResponseEntity<?> decryptData(DecryptionRequestDto requestDto, Class<Response> returnType) {
        Security.addProvider(new BouncyCastleProvider());
        Object decryptedData = null;
        Response decryptedDat = null;
        System.out.println("requestDto--->" + requestDto);
        try {
            // Convert SOAP XML to JSON Object
            String soapMessageXmlString = new String(Base64.getDecoder().decode(requestDto.getRequest()));
            log.info("SOAP: " + soapMessageXmlString);
            JSONObject jsonObject = XML.toJSONObject(soapMessageXmlString);
            log.info("JSON: " + jsonObject);

            // Private Key
            String privateKeyString = "MIIEpAIBAAKCAQEAs9fbc+FjUw0i8t05/OoDxXh7E27LBsEjbLRSmv+aWKx/QCcI\n"
                    + "XPv+YwF0ULIZ3AuT+I1YKmfE//Fyg9KXrwsV52r1RWNpxk3mE+c3huTuVfh3sFZT\n"
                    + "EMSbvS6HxhjoC4Xp560BOwaTPfxKGfWYDqrKDhNn5Loa8kKaecpORg2sEfPpP1J6\n"
                    + "0vVrvQ/uMbSxkyp9tCbRTqrWl8w5ICUM1aYrN/Qqt4q43SMxhMtfcf9q723dXYCD\n"
                    + "wXZLV+72kgSaGx5aZi9/oS2iNi9G3t4ttuNNACQL1KZpE/twAY549EayNjOPzwyG\n"
                    + "RXp46Rw1EFAeE1hv+zdswcO8UNtPR0lHAb3AewIDAQABAoIBAAPJc9GI2XKSQD4k\n"
                    + "8mek9ddephjOqG/H+Vr8oRCqeTGM0FElgUOT+tNS4IQie/DqPX9qWoTqEnfhOawU\n"
                    + "7yS8cwWgdvGzGjMWyNV6dOzePTaKONr5tl4QBceCB1HgjGJRu48pUXFQviD8AwNw\n"
                    + "7HbCmeaZ+gIS+SZIyL/vxp4rA4iNNT7PSqLbW/utVhoMwWif2BFv+mBEJbe/3x/1\n"
                    + "uNEwusqyT9RnaRK8Rk47VLHW1vmLwjPvz5zV5KPEF4jhKYSgwD3pBUtTVpNrXcws\n"
                    + "rpCe62ciuw/PTTWGoHUQsMLUGkDAI4W/wma8SzI2CsFpzRZLHPdYb0yeB8Xvkf17\n"
                    + "GhjUPiECgYEA1yzzZCM7vLpnrpCaTtT+if4IuIZMAZaxFgxFZa9vZQ4OtEemDskN\n"
                    + "w+SvH/+uEz5zQsATOxjBmkecvkjMeWx4cb/f23Yl/4x5WxJU8metITwoN1AvNQd4\n"
                    + "zjviSCwRem7V+U6NrAjaafQTN1CjTOB2jO09Ac36QJDruwMuTuoxOCcCgYEA1fbR\n"
                    + "F8Wds6QsveNbCu1t3TZ64pG79aw4SPPPLyRxZc5sCxTDvbcUfjomF+bnFNZQudYw\n"
                    + "hWKs/2k6msuv5D7sPX1D6pi7mIFH4AL8euHbo5fO5pjN1OpoSwMMUMdOPwpyUGao\n"
                    + "YNLB1Vs0l3Mkj+H2zRRlhXhdEyFDcTIYFE1IdY0CgYEAobbQvUOVk8NsRM+8iN6e\n"
                    + "5kqbd0LHQLJmKLHUPhXZXFNyTZ9Dd/02cTEfRKc9xoy6x0Hfshxq9G45qPDBa8hP\n"
                    + "xP11WlSzPhnu4rkmSoAMp9u0Rc3njK0u56At8hvcju1ZtuKIqvCEZfjfsETUVeSk\n"
                    + "dEmf/gk1uOyxnX1IglqT3yUCgYEAloXZmUir5goUc83zaZ+Yz6wZDTWLLozm1+O1\n"
                    + "mKuhnwZ2GeGUxu16XEbaL6yAWrde+S3G2r+Nhu1njijHZ+IgXi22zt598w7YGq7f\n"
                    + "Ii+sTc1pf+51t1jk4AiX7GgaEt1tiESAJgV+2XMdb4JQcWx9LM8xkJEZoXCgOo0M\n"
                    + "RZQM6q0CgYBCwdjWEeamnbzUwyRLlbmrjqAGR2yB6NVWh+u8qZHAYRRs3mCkfaB2\n"
                    + "PGL/OrbEtZUb7JDCDeoDi1/xUsb4N7BbuNq8I6cBFLHmJZDSyxfmOOoX924D6q40\n"
                    + "/Dt2v1/4rOJBEDZN0iQasahhGZhIJMdaR1hCjAETlUIxz8tB1bcM+g==";

            byte[] encodedPrivateKey = Base64.getDecoder().decode(privateKeyString.replaceAll("\n", ""));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

            // Encryption key
            String encryptedKeyString = jsonObject
                    .optJSONObject("soap:Envelope").optJSONObject("soap:Header")
                    .optJSONObject("wsse:Security").optJSONObject("xenc:EncryptedKey")
                    .optJSONObject("xenc:CipherData").optString("xenc:CipherValue");

            byte[] encryptedKeyBytes = Base64.getDecoder().decode(encryptedKeyString);

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] keyBytes = cipher.doFinal(encryptedKeyBytes);

            // Encrypted Data
            String encryptedMsgString = jsonObject
                    .optJSONObject("soap:Envelope").optJSONObject("soap:Body")
                    .optJSONObject("xenc:EncryptedData").optJSONObject("xenc:CipherData")
                    .optString("xenc:CipherValue");

            byte[] encryptedMsgBytes = Base64.getDecoder().decode(encryptedMsgString);

            SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher1 = Cipher.getInstance("AES/CBC/NoPadding");

            byte[] ivBytes = new byte[cipher1.getBlockSize()];
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

            cipher1.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

            byte[] msgBytes = cipher1.doFinal(encryptedMsgBytes);

            String decryptedSoapXML = new String(msgBytes);
            System.out.println(decryptedSoapXML);
            int startIndex = decryptedSoapXML .indexOf("{");
            int endIndex = decryptedSoapXML .indexOf("}", startIndex);
            String desiredSubstring = decryptedSoapXML.substring(startIndex, endIndex + 1) ;
            System.out.println("--->"+desiredSubstring);

            ObjectMapper objectMapper = new ObjectMapper();

            try {

                System.out.println("fdyhjkd---"+decryptedSoapXML.replaceAll("\\s",""));
                JsonNode jsonNode = objectMapper.readTree(decryptedSoapXML.replace(" ",""));

                String uniqueRequestId = jsonNode.get("uniqueRequestId").asText();
                String emailId = jsonNode.get("emailId").toString();
                String mobileNumber = jsonNode.get("mobileNumber").toString();

                System.out.println("uniqueRequestId: " + uniqueRequestId);
                System.out.println("emailId: " + emailId);
                System.out.println("mobileNumber: " + mobileNumber);
            } catch (Exception e) {
                e.printStackTrace();
            }
            System.out.println("Service--->");

            if (returnType.equals(String.class)) {
                decryptedData = decryptedSoapXML;
            } else if (returnType.equals(Response.class)) {
//                int startIndex = decryptedSoapXML.indexOf("\"uniqueRequestId\"");
//                int endIndex = decryptedSoapXML.indexOf("}", startIndex);
//                String desiredSubstring = "{" + decryptedSoapXML.substring(startIndex, endIndex + 1);

                System.out.println("desiredSubstring" + desiredSubstring);

                decryptedData = new ObjectMapper().readValue(desiredSubstring, Response.class);

                System.out.println("decryptedDat.getName()---==-->" + decryptedDat.getName());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("decryptedData :" + decryptedData);

        return ResponseEntity.ok(decryptedData);
    }

	
}
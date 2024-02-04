package com.example.encryption.impl;

import java.io.IOException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import lombok.extern.slf4j.Slf4j;

@RestController
@Slf4j
public class EncryptionController {
	
	@Autowired
	private EncryptionDecryptionService encryptionService;
	
	@PostMapping("encrypt")
    public ResponseEntity<String> encryption(@RequestBody EncryptionRequestDto requestDto) throws IOException {
        log.info("Encryption controller invoke");
        return encryptionService.encryptData(requestDto);
    }
	
	@PostMapping("decrypt")
    public ResponseEntity<?> decryption(@RequestBody DecryptionRequestDto requestDto) throws IOException {
        log.info("decryption controller invoke");
        log.info("request :" +requestDto.getRequest());
        return encryptionService.decryptData(requestDto,Response.class);
    }
}

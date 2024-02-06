package com.example.encryption.impl;

import lombok.Data;

@Data
public class EncryptionRequestDto {

	private String uniqueRequestId;
    private String emailId;
    private String mobileNumber;
    private String pan;
    private String bankAccountNumber;
    private String name;
    private String ifsc;

}

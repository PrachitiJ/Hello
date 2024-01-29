package com.example.encryption.impl;

import lombok.Data;

@Data
public class DITRequest {
	String status = "FAILURE";
    String message = "Something went wrong";
    String uniqueRequestId = "";
    String emailId = "";
    String mobileNumber = "";
    String pan = "";
    String bankAccountNumber = "";
    String name = "";
    String ifsc = "";
}

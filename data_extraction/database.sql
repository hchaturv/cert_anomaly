DROP TABLE IF EXISTS subject_dn ; 
CREATE TABLE cert_data (sha256 TEXT, content TEXT, subject_c TEXT, subject_o TEXT, subject_cn TEXT, issuer_c TEXT, issuer_o TEXT, signing_algorithm TEXT, self_signed BOOL, key_algorithm TEXT, start_data TEXT, validity_length TEXT, org TEXT, common_name TEXT, issuer_org TEXT, issuer_country TEXT, issuer_common_name TEXT, subject_key_info TEXT, ip TEXT, sub_country TEXT, key_usage TEXT) ;


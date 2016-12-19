DROP TABLE IF EXISTS subject_dn ;

CREATE TABLE cert_data (sha256 TEXT, content TEXT, subject_cn TEXT, issuer_cn TEXT, signing_algorithm TEXT, self_signed BOOL, key_algorithm TEXT, val_length INT, enc_only BOOL,cert_sign BOOL, key_enc BOOL, digi_sign BOOL, cont_commit BOOL,dec_only BOOL, key_agreem BOOL, data_enc BOOL) ;

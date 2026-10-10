ALTER TABLE webauthn_credentials
    ADD COLUMN provisioner VARCHAR(64) NOT NULL DEFAULT '';

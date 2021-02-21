#!/usr/bin/sage
# vim: syntax=python

import os
import sys
import json
import hmac
import hashlib
import struct

try:
    from sagelib.opaque_common import I2OSP, OS2IP, encode_vector, encode_vector_len, decode_vector, decode_vector_len
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

if sys.version_info[0] == 3:
    xrange = range
    def _as_bytes(x): return x if isinstance(x, bytes) else bytes(x, "utf-8")
    def _strxor(str1, str2): return bytes(
        s1 ^ s2 for (s1, s2) in zip(str1, str2))
else:
    def _as_bytes(x): return x
    def _strxor(str1, str2): return ''.join(chr(ord(s1) ^ ord(s2))
                                            for (s1, s2) in zip(str1, str2))

# enum {
#   base(1),
#   custom_identifier(2),
#   (255)
# } EnvelopeMode;
envelope_mode_base = 0x01
envelope_mode_custom_identifier = 0x02

# struct {
#    opaque client_private_key[Nsk];
# } SecretCredentials;
# 
# struct {
#    opaque server_public_key[Npk];
# } CleartextCredentials;
#
# struct {
#   SecretCredentials secret_credentials;
#   CleartextCredentials cleartext_credentials;
# } Credentials;

def deserialize_secret_credentials(data):
    return SecretCredentials(data), len(data)

class SecretCredentials(object):
    def __init__(self, skU):
        self.skU = skU

    def serialize(self):
        return self.skU

class CleartextCredentials(object):
    def __init__(self, pkS, mode = envelope_mode_base):
        self.pkS = pkS
        self.mode = mode

    def serialize(self):
        return self.pkS

class CustomCleartextCredentials(CleartextCredentials):
    def __init__(self, pkS, idU, idS):
        CleartextCredentials.__init__(self, pkS, envelope_mode_custom_identifier)
        self.idU = idU
        self.idS = idS

    def serialize(self):
        return self.pkS + encode_vector(self.idU) + encode_vector(self.idS)

class Credentials(object):
    def __init__(self, skU, pkU, idU = None, idS = None):
        self.skU = skU
        self.pkU = pkU
        self.idU = idU
        self.idS = idS

# struct {
#   InnerEnvelopeMode mode;
#   opaque nonce[32];
#   opaque ct[Nsk];
# } InnerEnvelope;
def deserialize_inner_envelope(config, data):
    if len(data) < 35:
        raise Exception("Insufficient bytes")
    mode = OS2IP(data[0:1])
    nonce = data[1:33]
    if len(data) < 33+config.Nsk:
        raise Exception("Invalid inner envelope encoding")
    ct = data[33:33+config.Nsk]
    return InnerEnvelope(mode, nonce, ct), 33+len(ct)

class InnerEnvelope(object):
    def __init__(self, mode, nonce, ct):
        assert(len(nonce) == 32)
        self.mode = mode
        self.nonce = nonce
        self.ct = ct

    def serialize(self):
        return I2OSP(self.mode, 1) + self.nonce + self.ct

# struct {
#   InnerEnvelope contents;
#   opaque auth_tag[Nh];
# } Envelope;
def deserialize_envelope(config, data):
    contents, offset = deserialize_inner_envelope(config, data)
    Nh = config.hash().digest_size
    if offset + Nh > len(data):
        raise Exception("Insufficient bytes")
    auth_tag = data[offset:offset+Nh]
    return Envelope(contents, auth_tag), offset+Nh

class Envelope(object):
    def __init__(self, contents, auth_tag):
        self.contents = contents
        self.auth_tag = auth_tag

    def serialize(self):
        return self.contents.serialize() + self.auth_tag

    def __eq__(self, other):
        if isinstance(other, Envelope):
            serialized = self.serialize()
            other_serialized = other.serialize()
            return serialized == other_serialized
        return False

class ProtocolMessage(object):
    def __init__(self):
        pass

    def serialize(self):
        raise Exception("Not implemented")

    def __eq__(self, other):
        if isinstance(other, ProtocolMessage):
            serialized = self.serialize()
            other_serialized = other.serialize()
            return serialized == other_serialized
        return False

# struct {
#     SerializedElement data;
# } RegistrationRequest;
def deserialize_registration_request(config, msg_bytes):
    length = config.oprf_suite.group.element_byte_length()
    if len(msg_bytes) < length:
        raise Exception("Invalid message")
    return RegistrationRequest(msg_bytes[0:length])

class RegistrationRequest(ProtocolMessage):
    def __init__(self, data):
        ProtocolMessage.__init__(self)
        self.data = data

    def serialize(self):
        return self.data

# struct {
#     SerializedElement data;
#     opaque pkS[Npk];
# } RegistrationResponse;
def deserialize_registration_response(config, msg_bytes):
    length = config.oprf_suite.group.element_byte_length()
    data = msg_bytes[0:length]
    pkS = msg_bytes[length:]
    if len(pkS) != config.Npk:
        raise Exception("Invalid message: %d %d" % (len(pkS), config.Npk))

    return RegistrationResponse(data, pkS)

class RegistrationResponse(ProtocolMessage):
    def __init__(self, data, pkS):
        ProtocolMessage.__init__(self)
        self.data = data
        self.pkS = pkS

    def serialize(self):
        return self.data + self.pkS

# struct {
#     opaque pkU[Npk];
#     Envelope envU;
# } RegistrationUpload;
def deserialize_registration_upload(config, msg_bytes):
    offset = 0

    if len(msg_bytes) < config.Npk:
        raise Exception("Invalid message")
    pkU = msg_bytes[offset:config.Npk]

    envU, _ = deserialize_envelope(config, msg_bytes[config.Npk:])

    return RegistrationUpload(envU, pkU)

class RegistrationUpload(ProtocolMessage):
    def __init__(self, envU, pkU):
        ProtocolMessage.__init__(self)
        self.envU = envU
        self.pkU = pkU

    def serialize(self):
        return self.pkU + self.envU.serialize()

# struct {
#     SerializedElement data;
# } CredentialRequest;
def deserialize_credential_request(config, msg_bytes):
    length = config.oprf_suite.group.element_byte_length()
    if len(msg_bytes) < length:
        raise Exception("Invalid message")
    return CredentialRequest(msg_bytes[0:length]), length

class CredentialRequest(ProtocolMessage):
    def __init__(self, data):
        ProtocolMessage.__init__(self)
        self.data = data

    def serialize(self):
        return self.data

# struct {
#     SerializedElement data;
#     opaque pkS[Npk];
#     Envelope envelope;
# } CredentialResponse;
def deserialize_credential_response(config, msg_bytes):
    length = config.oprf_suite.group.element_byte_length()
    data = msg_bytes[0:length]

    pkS = msg_bytes[length:length+config.Npk]
    offset = length + config.Npk

    envU, length = deserialize_envelope(config, msg_bytes[offset:])
    offset = offset + length

    return CredentialResponse(data, pkS, envU), offset

class CredentialResponse(ProtocolMessage):
    def __init__(self, data, pkS, envU):
        ProtocolMessage.__init__(self)
        self.data = data
        self.pkS = pkS
        self.envU = envU

    def serialize(self):
        return self.data + self.pkS + self.envU.serialize()

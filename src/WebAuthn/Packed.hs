{-# LANGUAGE OverloadedStrings #-}
module WebAuthn.Packed where

import Crypto.Hash
import Data.ByteString (ByteString)
import qualified Data.ByteArray as BA
import qualified Data.X509 as X509
import qualified Codec.CBOR.Term as CBOR
import qualified Codec.CBOR.Decoding as CBOR
import qualified Data.Map as Map
import WebAuthn.Signature
import WebAuthn.Types

data Stmt = Stmt Int ByteString (Maybe (X509.SignedExact X509.Certificate))
  deriving Show

decode :: CBOR.Term -> CBOR.Decoder s Stmt
decode (CBOR.TMap xs) = do
  let m = Map.fromList xs
  CBOR.TInt algc <- Map.lookup (CBOR.TString "alg") m ??? "alg"
  CBOR.TBytes sig <- Map.lookup (CBOR.TString "sig") m ??? "sig"
  cert <- case Map.lookup (CBOR.TString "x5c") m of
    Just (CBOR.TList (CBOR.TBytes certBS : _)) ->
      either fail (pure . Just) $ X509.decodeSignedCertificate certBS
    _ -> pure Nothing
  return $ Stmt algc sig cert
  where
    Nothing ??? e = fail e
    Just a ??? _ = pure a
decode _ = fail "Packed.decode: expected a Map"

verify :: Stmt
  -> AuthenticatorData
  -> ByteString
  -> Digest SHA256
  -> Bool
  -> Either VerificationFailure ()
verify (Stmt _ sig cert) ad adRaw clientDataHash allowSelfAttestation = do
  let dat = adRaw <> BA.convert clientDataHash
  -- 8.2
  case cert of
    Just x509 -> do
      let pub = X509.certPubKey $ X509.getCertificate x509
      verifyX509Sig (X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_EC) pub dat sig "Packed"
      -- FIXME verify that certificate meets criteria stated in 8.2.1
      -- FIXME verify that certificate has proper aaguid set under appropriate extension
    Nothing -> do
        if allowSelfAttestation then do
          pub <- case attestedCredentialData ad of
              Nothing -> Left MalformedAuthenticatorData
              Just c -> parsePublicKey $ credentialPublicKey c
          -- FIXME verify that alg in AuthenticatorData matches the type of pub
          verifySig pub sig dat
        else
          Left $ UnsupportedAttestationFormat "Self attestation not supported"

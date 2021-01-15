{-# LANGUAGE RecordWildCards, NamedFieldPuns #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
-----------------------------------------------------------------------
-- |
-- Module      :  WebAuthn
-- License     :  BSD3
--
-- Maintainer  :  Fumiaki Kinoshita <fumiexcel@gmail.com>
--
-- <https://www.w3.org/TR/webauthn/ Web Authentication API> Verification library
-----------------------------------------------------------------------

module WebAuthn (
  -- * Basic
  TokenBinding(..)
  , Origin(..)
  , RelyingParty(..)
  , defaultRelyingParty
  , User(..)
  -- Challenge
  , Challenge(..)
  , generateChallenge
  , WebAuthnType(..)
  , CollectedClientData(..)
  , AuthenticatorData(..)
  , AttestedCredentialData(..)
  , AAGUID(..)
  , CredentialPublicKey(..)
  , CredentialId(..)
  -- * verfication
  , VerificationFailure(..)
  , registerCredential
  , verify
  , encodeAttestation
  ) where

import Prelude hiding (fail)
import Data.Aeson as J
import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.Serialize as C
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.Map as Map
import Data.Text (Text)
import Crypto.Random
import Crypto.Hash
import qualified Codec.CBOR.Term as CBOR
import qualified Codec.CBOR.Read as CBOR
import qualified Codec.CBOR.Decoding as CBOR
import qualified Codec.CBOR.Encoding as CBOR
import qualified Codec.Serialise as CBOR
import Control.Monad.Fail
import WebAuthn.Signature
import WebAuthn.Types
import qualified WebAuthn.TPM as TPM
import qualified WebAuthn.FIDOU2F as U2F
import qualified WebAuthn.Packed as Packed
import qualified WebAuthn.AndroidSafetyNet as Android
import Control.Monad.IO.Class (MonadIO)
import Control.Monad.Trans.Except (runExceptT, ExceptT(..), throwE)
import Data.Text (pack)
import qualified Data.X509.CertificateStore as X509
import Data.Bifunctor (first)
import Data.Text.Encoding (encodeUtf8)

-- | Generate a cryptographic challenge (13.1).
generateChallenge :: Int -> IO Challenge
generateChallenge len = Challenge <$> getRandomBytes len

parseAuthenticatorData :: C.Get AuthenticatorData
parseAuthenticatorData = do
  rpIdHash' <- C.getBytes 32
  rpIdHash <- maybe (fail "impossible") pure $ digestFromByteString rpIdHash'
  flags <- C.getWord8
  _counter <- C.getBytes 4
  attestedCredentialData <- if testBit flags 6
    then do
      aaguid <- AAGUID <$> C.getBytes 16
      len <- C.getWord16be
      credentialId <- CredentialId <$> C.getBytes (fromIntegral len)
      n <- C.remaining
      credentialPublicKey <- CredentialPublicKey <$> C.getBytes n
      pure $ Just AttestedCredentialData{..}
    else pure Nothing
  let authenticatorDataExtension = B.empty --FIXME
  let userPresent = testBit flags 0
  let userVerified = testBit flags 2
  return AuthenticatorData{..}

-- | Attestation (6.4) provided by authenticators

data AttestationObject = AttestationObject {
  fmt :: Text
  , attStmt :: AttestationStatement
  , authData :: ByteString
}

data AttestationStatement = AF_Packed Packed.Stmt
  | AF_TPM TPM.Stmt
  | AF_AndroidKey
  | AF_AndroidSafetyNet StmtSafetyNet
  | AF_FIDO_U2F U2F.Stmt
  | AF_None
  deriving Show

decodeAttestation :: CBOR.Decoder s AttestationObject
decodeAttestation = do
  m :: Map.Map Text CBOR.Term <- CBOR.decode
  CBOR.TString fmt <- maybe (fail "fmt") pure $ Map.lookup "fmt" m
  stmtTerm <- maybe (fail "stmt") pure $ Map.lookup "attStmt" m
  -- 7.1.18
  stmt <- case fmt of
    "fido-u2f" -> maybe (fail "fido-u2f") (pure . AF_FIDO_U2F) $ U2F.decode stmtTerm
    "packed" -> AF_Packed <$> Packed.decode stmtTerm
    "tpm" -> AF_TPM <$> TPM.decode stmtTerm
    "android-safetynet" -> AF_AndroidSafetyNet <$> Android.decode stmtTerm
    _ -> fail $ "decodeAttestation: Unsupported format: " ++ show fmt
  CBOR.TBytes adRaw <- maybe (fail "authData") pure $ Map.lookup "authData" m
  return (AttestationObject fmt stmt adRaw)

encodeAttestation :: AttestationObject -> CBOR.Encoding 
encodeAttestation attestationObject = CBOR.encodeMapLen 3 
  <> CBOR.encodeString "fmt"
  <> encodeAttestationFmt
  <> CBOR.encodeString  "attStmt"
  where
    encodeAttestationFmt :: CBOR.Encoding
    encodeAttestationFmt =  case (attStmt attestationObject) of
      AF_FIDO_U2F _ -> CBOR.encodeString "fido-u2f"
      AF_Packed _ -> CBOR.encodeString "packed"
      AF_TPM _ -> CBOR.encodeString "tpm"
      AF_AndroidKey -> CBOR.encodeString "android-key"
      AF_AndroidSafetyNet _ -> CBOR.encodeString "android-safetynet"
      AF_None -> CBOR.encodeString ""

-- | 7.1. Registering a New Credential
registerCredential :: MonadIO m => X509.CertificateStore
  -> Challenge
  -> RelyingParty
  -> Maybe Text -- ^ Token Binding ID in base64
  -> Bool -- ^ require user verification?
  -> ByteString -- ^ clientDataJSON
  -> ByteString -- ^ attestationObject
  -> m (Either VerificationFailure AttestedCredentialData)
registerCredential cs challenge (RelyingParty rpOrigin rpId _ _) tbi verificationRequired clientDataJSON attestationObjectBS = runExceptT $ do
  -- 7.1.6 to 7.1.10
  _ <- hoistEither runAttestationCheck
  attestationObject <- hoistEither $ either (Left . CBORDecodeError "registerCredential") (pure . snd)
        $ CBOR.deserialiseFromBytes decodeAttestation
        $ BL.fromStrict 
        $ attestationObjectBS
  ad <- hoistEither $ extractAuthData attestationObject
  -- TODO: add public key parameters check 7.1.16
  -- TODO: extensions here (7.1.17)
  -- 7.1.18 done as a part of decoding
  case (attStmt attestationObject) of
    -- 8.2
    AF_FIDO_U2F s -> hoistEither $ U2F.verify s ad clientDataHash
    -- 8.3
    AF_Packed s -> hoistEither $ Packed.verify s ad (authData attestationObject) clientDataHash
    AF_TPM s -> hoistEither $ TPM.verify s ad (authData attestationObject) clientDataHash
    -- TODO: implement Android Key attestation statement format (8.4)
    -- 8.5
    AF_AndroidSafetyNet s -> Android.verify cs s (authData attestationObject) clientDataHash
    -- 8.6
    AF_FIDO_U2F s -> hoistEither $ U2F.verify s ad clientDataHash
    -- 8.7
    AF_None -> pure ()
    -- TODO implement Apple Anonymous Attestation Format (8.8)
    _ -> throwE (UnsupportedAttestationFormat (pack $ show (attStmt attestationObject)))

  -- TODO add trust anchors verification (7.1.20)

  case attestedCredentialData ad of
    Nothing -> throwE MalformedAuthenticatorData
    Just c -> pure c
  where
    -- 7.1.11
    clientDataHash = hash clientDataJSON :: Digest SHA256
    runAttestationCheck = do 
      -- 7.1.6
      CollectedClientData{..} <- either
        (Left . JSONDecodeError) Right $ J.eitherDecode $ BL.fromStrict clientDataJSON
      -- 7.1.7
      clientType == Create ?? InvalidType
      -- 7.1.8
      challenge == clientChallenge ?? MismatchedChallenge
      -- 7.1.9
      rpOrigin == clientOrigin ?? MismatchedOrigin
      -- 7.1.10 but misses checking for Token Binding ID for the connection (whatever it is) FIXME
      case clientTokenBinding of
        TokenBindingUnsupported -> pure ()
        TokenBindingSupported -> pure ()
        TokenBindingPresent t -> case tbi of
          Nothing -> Left UnexpectedPresenceOfTokenBinding
          Just t'
            | t == t' -> pure ()
            | otherwise -> Left MismatchedTokenBinding
    extractAuthData attestationObject = do
      -- 7.1.12
      ad <- either (const $ Left MalformedAuthenticatorData) pure $ C.runGet parseAuthenticatorData (authData attestationObject)
      -- 7.1.13
      hash (encodeUtf8 rpId) == rpIdHash ad ?? MismatchedRPID
      -- 7.1.14
      userPresent ad ?? UserNotPresent
      -- 7.1.15
      not verificationRequired || userVerified ad ?? UserUnverified
      pure ad

-- | 7.2. Verifying an Authentication Assertion
verify :: Challenge
  -> RelyingParty
  -> Maybe Text -- ^ Token Binding ID in base64
  -> Bool -- ^ require user verification?
  -> ByteString -- ^ clientDataJSON
  -> ByteString -- ^ authenticatorData
  -> ByteString -- ^ signature
  -> CredentialPublicKey -- ^ public key
  -> Either VerificationFailure ()
verify challenge rp tbi verificationRequired clientDataJSON adRaw sig pub = do
  -- 7.2.11 - 7.2.14
  clientDataCheck Get challenge clientDataJSON rp tbi
  -- 7.2.15 - 7.2.17
  _ <- verifyAuthenticatorData rp adRaw verificationRequired
  -- FIXME missing 7.2.18 - extensions support
  -- 7.2.20
  let clientDataHash = hash clientDataJSON :: Digest SHA256
      dat = adRaw <> BA.convert clientDataHash
  pub' <- parsePublicKey pub
  verifySig pub' sig dat
  -- FIXME missing 7.2.21 - signature count support 

clientDataCheck :: WebAuthnType -> Challenge -> ByteString -> RelyingParty -> Maybe Text -> Either VerificationFailure ()
clientDataCheck ctype challenge clientDataJSON rp tbi = do 
  ccd <-  first JSONDecodeError (J.eitherDecode $ BL.fromStrict clientDataJSON)
  -- 7.2.11
  clientType ccd == ctype ?? InvalidType
  -- 7.2.12
  challenge == clientChallenge ccd ?? MismatchedChallenge
  -- 7.2.13
  rpOrigin rp == clientOrigin ccd ?? MismatchedOrigin
  -- 7.2.14
  verifyClientTokenBinding tbi (clientTokenBinding ccd)

verifyClientTokenBinding :: Maybe Text -> TokenBinding -> Either VerificationFailure ()
verifyClientTokenBinding tbi (TokenBindingPresent t) = case tbi of
      Nothing -> Left UnexpectedPresenceOfTokenBinding
      Just t'
        | t == t' -> pure ()
        | otherwise -> Left MismatchedTokenBinding 
verifyClientTokenBinding _ _ = pure ()

verifyAuthenticatorData :: RelyingParty -> ByteString -> Bool -> Either VerificationFailure AuthenticatorData
verifyAuthenticatorData rp adRaw verificationRequired = do
  ad <- first (const MalformedAuthenticatorData) (C.runGet parseAuthenticatorData adRaw)
  -- 7.2.15
  hash (encodeUtf8 $ rpId (rp :: RelyingParty)) == rpIdHash ad ?? MismatchedRPID
  -- 7.2.16
  userPresent ad ?? UserNotPresent
  -- 7.2.17
  not verificationRequired || userVerified ad ?? UserUnverified
  pure ad

(??) :: Bool -> e -> Either e ()
False ?? e = Left e
True ?? _ = Right ()
infix 1 ??

hoistEither :: Monad m => Either e a -> ExceptT e m a
hoistEither = ExceptT . pure

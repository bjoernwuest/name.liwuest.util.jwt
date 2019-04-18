package name.liwuest.util.jwt;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.SQLException;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.naming.directory.NoSuchAttributeException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import name.liwuest.util.db.EDatabase;
import name.liwuest.util.jwt.EJWTCreation.JWTCreationExceptionCauses;
import name.liwuest.util.jwt.EJWTValidation.JWTValidationExceptionCauses;
import name.liwuest.util.types.CPair;
import net.minidev.json.JSONObject;

public class CJwt {
	private String m_Issuer;
	private String m_Audience;
	private String m_Subject;
	private Date m_IssueTime = new Date();
	private Date m_NotBeforeTime = null;
	private Date m_ExpirationTime = null;
	
	private JSONObject m_UnencryptedClaims = new JSONObject();
	private JSONObject m_EncryptedClaims = new JSONObject();
	
	
	public CJwt(String Issuer, String Audience, String Subject, Date JwtNotValidBefore, Date ExpirationTime) throws EJWTCreation {
		m_Issuer = (null == Issuer) ? "unspecified" : Issuer;
		m_Audience = (null == Audience) ? "unspecified" : Audience;
		if ((null == Subject) || Subject.isEmpty()) { throw new EJWTCreation(JWTCreationExceptionCauses.SigningFailure); }
		m_Subject = Subject;
		m_ExpirationTime = ExpirationTime;
		m_NotBeforeTime = JwtNotValidBefore;
		if (null != ExpirationTime) {
			if (m_IssueTime.after(ExpirationTime)) { throw new EJWTCreation(JWTCreationExceptionCauses.ExpiryBeforeIssueing); }
			if ((null != JwtNotValidBefore) && JwtNotValidBefore.after(ExpirationTime)) { throw new EJWTCreation(JWTCreationExceptionCauses.ExpiryBeforeUse); }
		}
	}
	
	
	public static CJwt renew(CJwt OriginalJwt, Date ExpirationTime) throws EJWTCreation {
		CJwt result = new CJwt(OriginalJwt.getIssuer(), OriginalJwt.getAudience(), OriginalJwt.getSubject(), OriginalJwt.getJwtNotValidBefore(), ExpirationTime);
		OriginalJwt.getClaims().forEach((k, v) -> result.setClaim(k, v) );
		OriginalJwt.getEncryptedClaims().forEach((k, v) -> result.setEncryptedClaim(k, v) );
		return result;
	}
	
	
	public CJwt(String SerializedJwt) throws EJWTValidation {
		if ((null == SerializedJwt) || (5 > SerializedJwt.length())) { throw new EJWTValidation(JWTValidationExceptionCauses.EmptyJWT); }
		try {
			SignedJWT sjwt = SignedJWT.parse(SerializedJwt);
			if (null == sjwt.getJWTClaimsSet().getSubject()) { throw new EJWTValidation(EJWTValidation.JWTValidationExceptionCauses.ExpectedClaimMissing); }
			if (null == sjwt.getJWTClaimsSet().getIssuer()) { throw new EJWTValidation(EJWTValidation.JWTValidationExceptionCauses.ExpectedClaimMissing); }
			if (null == sjwt.getJWTClaimsSet().getAudience()) { throw new EJWTValidation(EJWTValidation.JWTValidationExceptionCauses.ExpectedClaimMissing); }
			if (null == sjwt.getJWTClaimsSet().getIssueTime()) { throw new EJWTValidation(JWTValidationExceptionCauses.ExpectedClaimMissing); } else if (new Date().before(sjwt.getJWTClaimsSet().getIssueTime())) { throw new EJWTValidation(EJWTValidation.JWTValidationExceptionCauses.JWTShallNotBeIssuedUntilNow); } else { m_IssueTime = sjwt.getJWTClaimsSet().getIssueTime(); }
			if (null != sjwt.getJWTClaimsSet().getExpirationTime()) { if (new Date().after(sjwt.getJWTClaimsSet().getExpirationTime())) { throw new EJWTValidation(EJWTValidation.JWTValidationExceptionCauses.JWTExpired); } else { m_ExpirationTime = sjwt.getJWTClaimsSet().getExpirationTime(); } }
			if (null != sjwt.getJWTClaimsSet().getNotBeforeTime()) { if (new Date().before(sjwt.getJWTClaimsSet().getNotBeforeTime())) { throw new EJWTValidation(EJWTValidation.JWTValidationExceptionCauses.JWTNotValidNow); } else { m_NotBeforeTime = sjwt.getJWTClaimsSet().getNotBeforeTime(); } }
			
			// Check signature of JWT
			SecretKey secret = CJwks.getKey(Integer.parseInt(sjwt.getHeader().getKeyID()));
			if ((JWSObject.State.SIGNED == sjwt.getState()) || (JWSObject.State.VERIFIED == sjwt.getState())) { if (!sjwt.verify(new DefaultJWSVerifierFactory().createJWSVerifier(sjwt.getHeader(), secret))) { throw new EJWTValidation(JWTValidationExceptionCauses.InvalidSignature); } }
			if (JWSObject.State.VERIFIED != sjwt.getState()) { throw new EJWTValidation(EJWTValidation.JWTValidationExceptionCauses.InvalidSignature); }
			
			// Read custom claims
			try {
				JSONObject unCl = sjwt.getJWTClaimsSet().getJSONObjectClaim("__unencryptedClaims");
				if (null != unCl) {
					unCl.entrySet().forEach(e -> { setClaim(e.getKey(), e.getValue()); });
				}
			} catch (ParseException Ignore) { /* Do nothing if claim is not (properly) set */ }
			
			// Read encrpted claims; iv to be UTF-8 base64 encoded; cy to be UTF-8 string, pl to be UTF-8 base64 encoded
			try {
				JSONObject encryptedClaims = sjwt.getJWTClaimsSet().getJSONObjectClaim("__encryptedClaims");
				if ((null != encryptedClaims) && encryptedClaims.containsKey("cy") && encryptedClaims.containsKey("iv") && encryptedClaims.containsKey("pl")) {
					// Decrypt claims
					IvParameterSpec iv = new IvParameterSpec(Base64.getDecoder().decode(encryptedClaims.getAsString("iv").getBytes(StandardCharsets.UTF_8)));
					Cipher ciph = Cipher.getInstance(encryptedClaims.getAsString("cy"));
					ciph.init(Cipher.DECRYPT_MODE, secret, iv);
					m_EncryptedClaims = JSONObjectUtils.parse(new String(ciph.doFinal(Base64.getDecoder().decode(encryptedClaims.getAsString("pl").getBytes(StandardCharsets.UTF_8))), StandardCharsets.UTF_8));
				}
			} catch (ParseException | GeneralSecurityException Ignore) { /* Do nothing if claim is not (properly) set or cannot be decrypted */ }
		} catch (ParseException Ex) { throw new EJWTValidation(JWTValidationExceptionCauses.ParseFailed); }
		catch (EDatabase | SQLException | JOSEException Ex) { throw new EJWTValidation(JWTValidationExceptionCauses.TechnicalValidationFailure); }
		catch (NoSuchAttributeException Ex) { throw new EJWTValidation(JWTValidationExceptionCauses.SignageKeyMissing); }
	}
	
	
	public String getIssuer() { return m_Issuer; }
	public String getAudience() { return m_Audience; }
	public String getSubject() { return m_Subject; }
	public String getUserID() { return getSubject(); }
	public Date getIssueTime() { return m_IssueTime; }
	public Date getJwtNotValidBefore() { return m_NotBeforeTime; }
	public Date getJwtExpiresAt() { return m_ExpirationTime; }
	
	
	@SuppressWarnings("unchecked") public <T> T getClaim(String ClaimName, T Default) { synchronized (m_UnencryptedClaims) { return (T)(Default.getClass().cast(m_UnencryptedClaims.getOrDefault(ClaimName, Default))); } }
	public Object setClaim(String ClaimName, Object Value) { return m_UnencryptedClaims.put(ClaimName, Value); }
	public JSONObject getClaims() { synchronized (m_UnencryptedClaims) { return new JSONObject(m_UnencryptedClaims); } }
	
	@SuppressWarnings("unchecked") public <T> T getEncyptedClaim(String ClaimName, T Default) { synchronized (m_EncryptedClaims) { return (T)(Default.getClass().cast(m_EncryptedClaims.getOrDefault(ClaimName, Default))); } }
	public Object setEncryptedClaim(String ClaimName, Object Value) { return m_EncryptedClaims.put(ClaimName, Value); }
	public JSONObject getEncryptedClaims() { synchronized (m_EncryptedClaims) { return new JSONObject(m_EncryptedClaims); } }
	
	
	@Override public String toString() {
		try {
			// Get signing (and encrypting) key
			CPair<Integer, SecretKey> key = CJwks.getKey();
			// Set major claims
			JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().issuer(m_Issuer).audience(m_Audience).subject(m_Subject).issueTime(m_IssueTime).claim("kid", key.getLeft());
			if (null != m_NotBeforeTime) { claims.notBeforeTime(m_NotBeforeTime); }
			if (null != m_ExpirationTime) { claims.expirationTime(m_ExpirationTime); }
			// Add unencrypted claims
			synchronized (m_UnencryptedClaims) { claims.claim("__unencryptedClaims", new JSONObject(m_UnencryptedClaims)); }
			// Add encrypted claims
			synchronized (m_EncryptedClaims) {
				if (!m_EncryptedClaims.isEmpty()) {
					String cy = "AES/CBC/PKCS5PADDING";
					Cipher ciph = Cipher.getInstance(cy);
					Random rng = new SecureRandom();
					byte[] ivBytes = new byte[512];
					rng.nextBytes(ivBytes);
					ciph.init(Cipher.ENCRYPT_MODE, key.getRight(), new IvParameterSpec(ivBytes));
					String pl = new String(Base64.getEncoder().encode(ciph.doFinal(m_EncryptedClaims.toJSONString().getBytes(StandardCharsets.UTF_8))));
					// Set claims
					claims.claim("__encryptedClaims", (new JSONObject()).appendField("cy", cy).appendField("pl", pl).appendField("iv", new String(Base64.getEncoder().encode(ivBytes), StandardCharsets.UTF_8)));
				}
			}
			SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims.build());
			jwt.sign(new MACSigner(key.getRight()));
			return jwt.serialize();
		} catch (NoSuchAttributeException | SQLException | EDatabase | JOSEException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return null;
		}
	}
}

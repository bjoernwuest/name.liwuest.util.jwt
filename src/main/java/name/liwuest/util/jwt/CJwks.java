package name.liwuest.util.jwt;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.directory.NoSuchAttributeException;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;

import name.liwuest.util.config.CConfiguration;
import name.liwuest.util.db.CDBConnection;
import name.liwuest.util.db.CNamedPreparedStatement;
import name.liwuest.util.db.CNamedPreparedStatement.COpenedNamedPreparedStatement;
import name.liwuest.util.db.EDatabase;
import name.liwuest.util.types.CPair;

public class CJwks {
	/** <p>Create table to store JWT signature keys.</p> */
	private final static String m_SQL_JWTSignatureKey_CreateTable = "CREATE TABLE IF NOT EXISTS jwt_jwks(key_id INT NOT NULL, valid_from BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM now()) * 1000, valid_to BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM now()) * 1000, secret_key TEXT NOT NULL, key_type TEXT NOT NULL, PRIMARY KEY (key_id))";
	/** <p>Insert JWT signature key into table of {@link #m_SQL_JWTSignatureKey_CreateTable}.</p>
	 * 
	 * @param from The time from which the key is valid, measured in {@link System#currentTimeMillis()}.
	 * @param to The time until which the key is valid, measured in {@link System#currentTimeMillis()}.
	 * @param key {@link Base64#getEncoder() Base64 encoded} representation of the {@link SecretKey#getEncoded() encoded secret key}.
	 * @param type The type of the secret {@code key}.
	 */
	private final static String m_SQL_JWTSignatureKey_InsertNewKey = "INSERT INTO jwt_jwks (valid_from, valid_to, secret_key, key_type) VALUES (SELECT coalesce(max(key_id), 0) + 1, :from, :to, :key, :type FROM jwt_jwks) ON CONFLICT DO NOTHING RETURNING key_id";
	/** <p>Select JWT signature key from table of {@link #m_SQL_JWTSignatureKey_CreateTable}.</p>
	 * 
	 * <p>Returns the key that has the longest validity measured from now on.</p>
	 */
	private final static String m_SQL_JWTSignatureKey_SelectValidKey = "SELECT key_id FROM jwt_jwks WHERE valid_from < CURRENT_TIMESTAMP AND valid_to > CURRENT_TIMESTAMP ORDER BY valid_to DESC LIMIT 1";
	/**
	 */
	private final static String m_SQL_JWTSignatureKey_SelectKey = "SELECT secret_key, key_type FROM jwt_jwks WHERE key_id = :keyId AND valid_from < CURRENT_TIMESTAMP AND valid_to > CURRENT_TIMESTAMP";
	
	
	static {
		try (Connection conn = CDBConnection.connect(true); Statement stmt = conn.createStatement()) {
			stmt.execute(m_SQL_JWTSignatureKey_CreateTable);
			conn.commit();
		} catch (SQLException | EDatabase e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	/** <p>Create new secret key to use for JWT signing.</p>
	 * 
	 * <p>The key uses the AES algorithm with a length of 256 bit and is valid for 7 days from now on (machine time).</p>
	 * 
	 * <p>After creation of the key, it is stored in the database (entity {@code jwt_signature_key_store}). Further, a message is published of type {@link JWTSignatureKey#NewKey}.</p>
	 * 
	 * @return The key identifier of the key just created.
	 * @throws NoSuchAlgorithmException
	 * @throws EDatabase 
	 * @throws SQLException 
	 * @throws IOException 
	 * @throws JsonMappingException 
	 * @throws JsonParseException 
	 */
	final static int createKey() throws NoSuchAlgorithmException, SQLException, EDatabase, JsonParseException, JsonMappingException, IOException {
		if (256 > Cipher.getMaxAllowedKeyLength("AES")) { throw new NoSuchAlgorithmException("Require AES with a key length of at least 256bit."); }
		
		// Generate new key
		KeyGenerator kGen = KeyGenerator.getInstance("AES");
		kGen.init(256);
		final SecretKey secKey = kGen.generateKey();
		
		// Save new key in internal structure and in data base
		try (Connection conn = CDBConnection.connect(true); COpenedNamedPreparedStatement stmt = new CNamedPreparedStatement(m_SQL_JWTSignatureKey_InsertNewKey).open(conn)) {
			stmt.setLong("from", System.currentTimeMillis());
			stmt.setLong("to", System.currentTimeMillis() + CConfiguration.get("JWT", "new_jwt_age", new Integer(7 * 86400)).getFirst()); // By default, JWT key is valid for 7 days
			stmt.setString("key", Base64.getEncoder().encodeToString(secKey.getEncoded()));
			stmt.setString("type", secKey.getAlgorithm());
			try (ResultSet rSet = stmt.executeQuery()) {
				if (rSet.next()) {
					conn.commit();
					return rSet.getInt("key_id");
				} else { throw new IllegalStateException("Failed to create new key."); }
			}
		}
	}
	
	
	final static SecretKey getKey(int KeyId) throws SQLException, EDatabase, NoSuchAttributeException {
		try (Connection conn = CDBConnection.connect(); COpenedNamedPreparedStatement stmt = new CNamedPreparedStatement(m_SQL_JWTSignatureKey_SelectKey).open(conn)) {
			stmt.setInt("keyId", KeyId);
			try (ResultSet rSet = stmt.executeQuery()) {
				if (rSet.next()) {
					// Decode key
					byte[] decodedKey = Base64.getDecoder().decode(rSet.getString("secret_key"));
					// Store signature key entry
					return new SecretKeySpec(decodedKey, 0, decodedKey.length, rSet.getString("key_type"));
				} else { throw new NoSuchAttributeException("There is no such valid key with given identifier."); }
			}
		}
	}
	
	
	final static CPair<Integer, SecretKey> getKey() throws SQLException, EDatabase, NoSuchAttributeException {
		try (Connection conn = CDBConnection.connect(); COpenedNamedPreparedStatement stmt = new CNamedPreparedStatement(m_SQL_JWTSignatureKey_SelectValidKey).open(conn); ResultSet rSet = stmt.executeQuery()) {
			if (rSet.next()) {
				return new CPair<>(rSet.getInt("key_id"), getKey(rSet.getInt("key_id")));
			} else { throw new NoSuchAttributeException("Currently there is no key vailable."); }
		}
	}
}

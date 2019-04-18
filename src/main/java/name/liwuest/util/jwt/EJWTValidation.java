package name.liwuest.util.jwt;

/** <p>Exception to signal JWT validation exception and cause.</p>
 * 
 * @author Bjoern Wuest, Germany, 2018
 */
public final class EJWTValidation extends Exception {
	/** <p>Serial version identifier.</p> */
	private static final long serialVersionUID = -13825989676818542L;
	
	
	/** <p>Constants for JWT validation exception causes.</p>
	 * 
	 * @author Bjoern Wuest, Germany, 2018
	 */
	public enum JWTValidationExceptionCauses {
		/** <p>There was no JWT provided.</p> */
		EmptyJWT,
		/** <p>The provided JWT could not be parsed, eventually because it is invalid.</p> */
		ParseFailed,
		/** <p>The provided JWT shall not have been issued now, i.e. {@code iat} is before now.</p> */
		JWTShallNotBeIssuedUntilNow,
		/** <p>The provided JWT has been expired, i.e. {@code exp} is in the past.</p> */
		JWTExpired,
		/** <p>The provided JWT is not valid as of now, i.e. {@code nbf} is before now.</p> */
		JWTNotValidNow,
		/** <p>The provided JWT has an invalid signature according to the JWS header.</p> */
		InvalidSignature,
		/** <p>The provided JWT could not be validated due to another technical failure. See nested exception for details.</p> */
		TechnicalValidationFailure,
		/** <p>A claim that is expected is missing or is not satisfied.</p> */
		ExpectedClaimMissing,
		/** <p>The JWT is issued by someone not expected.</p> */
		UnexpectedIssuer,
		/** <p>The JWT is for an unexpected audience.</p> */
		UnexpectedAudience,
		/** <p>The JWT is authorizing someone else.</p> */
		WrongAuthorizedParty,
		/** <p>If the JWT does not contain a user ID ({@link java.util.UUID}) in the subject.</p> */
		UserIDMissing,
		/** <p>If there is no key available that was used for signing. Possible cause could also be expiry.</p> */
		SignageKeyMissing
	}
	
	
	/** <p>The cause for the exception.</p> */
	private final JWTValidationExceptionCauses m_Cause;
	
	
	/** <p>Signal JWT validation exception.</p>
	 * 
	 * @param Cause The cause why the JWT validation excepted.
	 * @param Nested The nested cause for this exception.
	 */
	public EJWTValidation(JWTValidationExceptionCauses Cause, Throwable Nested) { super(Nested); m_Cause = Cause; }
	
	
	/** <p>Signal JWT validation exception.</p>
	 * 
	 * @param Cause The cause why the JWT validation excepted.
	 */
	public EJWTValidation(JWTValidationExceptionCauses Cause) { m_Cause = Cause; }
	
	
	/** <p>Returns the cause why JWT validation excepted.</p>
	 * 
	 * @return The cause why JWT validation excepted.
	 */
	public final EJWTValidation.JWTValidationExceptionCauses getExceptionCause() { return m_Cause; }
}

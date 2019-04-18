package name.liwuest.util.jwt;

/** <p>Exception to signal that JWT creation failed.</p>
 * 
 * @author Bjoern Wuest, Germany, 2018
 */
public final class EJWTCreation extends Exception {
	/** <p>Serial version identifier.</p> */
	private static final long serialVersionUID = 5059844946226967256L;
	
	
	/** <p>Constants for JWT validation exception causes.</p>
	 * 
	 * @author Bjoern Wuest, Germany, 2018
	 */
	public enum JWTCreationExceptionCauses {
		/** <p>Signing failure. See cause for details.</p> */
		SigningFailure,
		/** <p>No valid signing key available.</p> */
		NoKeyAvailable,
		/** <p>No or empty subject given for JWT.</p> */
		SubjectMissing,
		/** <p>The JWT had been expired before it has been issued.</p> */
		ExpiryBeforeIssueing,
		/** <p>The JWT can be used only after it has expired.</p> */
		ExpiryBeforeUse
	}
	
	
	/** <p>The cause for the exception.</p> */
	private final JWTCreationExceptionCauses m_Cause;
	
	
	/** <p>Signal JWT validation exception.</p>
	 * 
	 * @param Cause The cause why the JWT validation excepted.
	 * @param Nested The nested cause for this exception.
	 */
	public EJWTCreation(JWTCreationExceptionCauses Cause, Throwable Nested) { super(Nested); m_Cause = Cause; }
	
	
	/** <p>Signal JWT validation exception.</p>
	 * 
	 * @param Cause The cause why the JWT validation excepted.
	 */
	public EJWTCreation(JWTCreationExceptionCauses Cause) { m_Cause = Cause; }
	
	
	/** <p>Returns the cause why JWT validation excepted.</p>
	 * 
	 * @return The cause why JWT validation excepted.
	 */
	public final JWTCreationExceptionCauses getExceptionCause() { return m_Cause; }
}

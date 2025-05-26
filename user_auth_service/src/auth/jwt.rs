use chrono::{Utc, Duration};
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation, errors::Error as JwtError};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use std::env;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub exp: usize,          // Expiration timestamp (seconds since epoch)
    pub iat: usize,          // Issued at timestamp (seconds since epoch)
    pub user_id: Uuid,       // User ID
    pub username: String,    // Username
}

// Function to generate JWT
pub fn generate_jwt(user_id: Uuid, username: &str) -> Result<String, JwtError> {
    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(1)) // Token valid for 1 hour
        .expect("valid timestamp")
        .timestamp();

    let issued_at = Utc::now().timestamp();

    let claims = Claims {
        user_id,
        username: username.to_owned(),
        exp: expiration as usize,
        iat: issued_at as usize,
    };

    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let encoding_key = EncodingKey::from_secret(secret.as_ref());

    encode(&Header::default(), &claims, &encoding_key)
}

// Function to validate JWT (basic structure)
pub fn validate_jwt(token: &str) -> Result<Claims, JwtError> {
    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let decoding_key = DecodingKey::from_secret(secret.as_ref());
    let mut validation = Validation::default();
    validation.leeway = 5; // Add leeway to account for clock skew

    decode::<Claims>(token, &decoding_key, &validation).map(|data| data.claims)
}


// Struct for AuthenticatedUser (to be used by middleware/guards later)
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    pub user_id: Uuid,
    pub username: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use std::env;
    use chrono::Duration;

    fn setup_test_environment() {
        env::set_var("JWT_SECRET", "test_secret_key_for_jwt_unit_tests");
    }

    #[test]
    fn test_generate_and_validate_jwt_success() {
        setup_test_environment();
        let user_id = Uuid::new_v4();
        let username = "testuser";

        let token = generate_jwt(user_id, username).expect("Failed to generate token");
        
        // Add a small delay to ensure 'iat' is not exactly 'exp' if token lifetime is very short,
        // or ensure 'exp' is sufficiently in the future. Our 1-hour expiry is fine.
        // std::thread::sleep(std::time::Duration::from_secs(1));


        let claims = validate_jwt(&token).expect("Failed to validate token");

        assert_eq!(claims.user_id, user_id);
        assert_eq!(claims.username, username);
        assert!(claims.exp > claims.iat, "Expiration should be after issued_at");

        let now_ts = Utc::now().timestamp() as usize;
        assert!(claims.exp > now_ts, "Token should not be expired yet");
        assert!(claims.iat <= now_ts, "Token issued_at should be now or in the past");
    }

    #[test]
    fn test_validate_jwt_expired() {
        setup_test_environment();
        let user_id = Uuid::new_v4();
        let username = "testuser_expired";

        // Create a token that is already expired
        let expiration = Utc::now()
            .checked_sub_signed(Duration::hours(1)) // 1 hour in the past
            .expect("valid timestamp")
            .timestamp();
        let issued_at = Utc::now()
            .checked_sub_signed(Duration::hours(2)) // 2 hours in the past
            .expect("valid timestamp")
            .timestamp();


        let claims_to_encode = Claims {
            user_id,
            username: username.to_owned(),
            exp: expiration as usize,
            iat: issued_at as usize,
        };

        let secret = env::var("JWT_SECRET").unwrap();
        let encoding_key = EncodingKey::from_secret(secret.as_ref());
        let token = encode(&Header::default(), &claims_to_encode, &encoding_key)
            .expect("Failed to generate expired token");

        let result = validate_jwt(&token);
        assert!(result.is_err());
        match result.err().unwrap() {
            JwtError(kind) => match kind {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {} // Expected
                _ => panic!("Expected ExpiredSignature error, got {:?}", kind),
            },
            _ => panic!("Expected JwtError"),
        }
    }

    #[test]
    fn test_validate_jwt_invalid_signature() {
        setup_test_environment();
        let user_id = Uuid::new_v4();
        let username = "testuser_sig";

        let token_from_main_secret = generate_jwt(user_id, username).expect("Token gen failed");

        // Now try to validate with a DIFFERENT secret
        env::set_var("JWT_SECRET", "wrong_secret_for_testing_signature");
        let result = validate_jwt(&token_from_main_secret);
        assert!(result.is_err());
        match result.err().unwrap() {
            JwtError(kind) => match kind {
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {} // Expected
                _ => panic!("Expected InvalidSignature error, got {:?}", kind),
            },
            _ => panic!("Expected JwtError"),
        }
        // Reset to original test secret for other tests if any depend on it
        setup_test_environment();
    }

     #[test]
    fn test_validate_jwt_tampered_token() {
        setup_test_environment();
        let user_id = Uuid::new_v4();
        let username = "testuser_tamper";
        let token = generate_jwt(user_id, username).expect("Token gen failed");

        // Tamper with the token payload (e.g., by adding extra characters)
        // This will likely cause a base64 decode error or a JSON deserialization error,
        // which jsonwebtoken might map to InvalidToken or other errors.
        let tampered_token = format!("{}tamper", token);

        let result = validate_jwt(&tampered_token);
        assert!(result.is_err());
        // The specific error can vary (InvalidToken, InvalidSignature if structure is mangled, etc.)
        // For this test, just ensuring it's an error is sufficient.
        // Example check:
        // match result.err().unwrap() {
        //     JwtError(kind) => match kind {
        //         jsonwebtoken::errors::ErrorKind::InvalidToken => {} // Common for malformed
        //         jsonwebtoken::errors::ErrorKind::InvalidSignature => {} // Also possible
        //         _ => {} // Other errors also indicate failure
        //     },
        //     _ => panic!("Expected JwtError"),
        // }
    }
}

use serde::Serialize;

#[derive(Serialize)]
pub struct ErrorResponse {
    pub status: String, // e.g., "error", "fail"
    pub message: String,
}

// Optional: A generic success response wrapper, can be expanded later
#[derive(Serialize)]
pub struct SuccessResponse<T> {
    pub status: String, // e.g., "success"
    pub data: T,
}

package org.wso2.charon.core.protocol;
/**
 * SCIM Protocol uses the response status codes defined in HTTP to indicate
 * operation success or failure. This class includes those code and relevant description as constants.
 */
public class ResponseCodeConstants {

    public static final String ERROR_RESPONSE_SCHEMA_URI = "urn:ietf:params:scim:api:messages:2.0:Error";

    public static final String ERRORS = "Errors";
    public static final String STATUS = "status";
    public static final String DESCRIPTION = "description";

    public static final int CODE_TEMPORARY_REDIRECT = 307;
    public static final String DESC_TEMPORARY_REDIRECT = "The client is directed to repeat the same HTTP request at the " +
            "location identified. The client SHOULD NOT use the location provided in the response as a permanent reference to the " +
            "resource and SHOULD continue to use the original request URI.";

    public static final int CODE_PERMANENT_REDIRECT = 308;
    public static final String DESC_PERMANENT_REDIRECT = "The client is directed to repeat the same HTTP request at the " +
            "location identified. The client SHOULD use the location provided in the response as a permanent reference to the " +
            "resource.";

    public static final int CODE_BAD_REQUEST = 400;
    public static final String DESC_BAD_REQUEST = "Request is unparsable, syntactically incorrect, or violates schema.";

    public static final int CODE_UNAUTHORIZED = 401;
    public static final String DESC_UNAUTHORIZED = "Authorization failure. The authorization header is invalid or missing.";

    public static final int CODE_FORBIDDEN = 403;
    public static final String DESC_FORBIDDEN = "Operation is not permitted based on the supplied authorization.";

    public static final int CODE_RESOURCE_NOT_FOUND = 404;
    public static final String DESC_RESOURCE_NOT_FOUND = "Specified resource (e.g., User) or endpoint does not exist.";

    public static final int CODE_FORMAT_NOT_SUPPORTED = 406;
    public static final String DESC_FORMAT_NOT_SUPPORTED = "Requested format is not supported.";

    public static final int CODE_CONFLICT = 409;
    public static final String DESC_CONFLICT = "The specified version number does not match the resource's " +
            "latest version number, or a service provider refused to create a new, duplicate resource.";

    public static final int CODE_PRECONDITION_FAILED = 412;
    public static final String DESC_PRECONDITION_FAILED = "Failed to update. Resource has changed on the server.";

    public static final int CODE_PAYLOAD_TOO_LARGE = 413;
    public static final String DESC_PAYLOAD_TOO_LARGE = "{\"maxOperations\": 1000,\"maxPayloadSize\": 1048576}";

    public static final int CODE_INTERNAL_ERROR = 500;
    public static final String DESC_INTERNAL_ERROR = "An internal error. Implementers SHOULD provide descriptive debugging advice.";

    public static final int CODE_NOT_IMPLEMENTED = 501;
    public static final String DESC_NOT_IMPLEMENTED = "Service provider does not support the request operation.";


    //For HTTP status code 400 (Bad Request) responses, the following detail error types are defined:
    public static final String INVALID_FILTER = "InvalidFilter";
    public static final String TOO_MANY = "tooMany";
    public static final String UNIQUENESS = "uniqueness";
    public static final String MUTABILITY = "mutability";
    public static final String INVALID_SYNTAX = "invalidSyntax";
    public static final String INVALID_PATH= "invalidPath";
    public static final String NO_TARGET= "noTarget";
    public static final String INVALID_VALUE = "invalidValue";
    public static final String INVALID_VERS = "invalidVers";
    public static final String SENSITIVE = "sensitive";
}
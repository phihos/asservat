// Generated from canonical browser OpenAPI. Run npm run generate; do not edit.
export interface paths {
    "/auth/login": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Start bounded OIDC login */
        get: operations["begin_browser_login"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/auth/callback": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Consume state and exchange the one-use authorization code */
        get: operations["complete_browser_login"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/auth/csrf": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read CSRF metadata for a retained browser session without token refresh */
        get: operations["get_browser_csrf"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/auth/refresh": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Resolve current identity and refresh credentials when needed */
        post: operations["refresh_browser_session"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/auth/logout": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Sign out of Asservat */
        post: operations["end_browser_session"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/auth/backchannel-logout": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Receive a signed OIDC provider logout event
         * @description Authenticated by the logout token, not browser cookies or a CSRF token. Signature, issuer, client, event, expiry, freshness and replay checks are mandatory. Bounded unknown form parameters are ignored as required by OIDC.
         */
        post: operations["receive_oidc_logout"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/session": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get session */
        get: operations["get_session"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
}
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        Session: {
            principal: {
                issuer: string;
                /** @enum {unknown} */
                kind: "user" | "group";
                subject_id: string;
            };
            roles: string[];
            csrf_token: string;
            /** Format: date-time */
            expires_at: string;
            /** @enum {unknown} */
            step_up: "required" | "verified" | "unavailable";
        };
        Problem: {
            /** Format: uri */
            type: string;
            title: string;
            status: number;
            code: string;
            /** Format: uuid */
            request_id: string;
            retry_after_seconds?: number;
            /** @enum {unknown} */
            safe_action?: "sign_in" | "refresh" | "narrow" | "review" | "wait" | "contact_operator" | "none";
        };
        CSRF: {
            csrf_token: string;
        };
    };
    responses: {
        /** @description Sanitized failure. 400 malformed; 401 sign-in required; 403 CSRF/origin denied; 429 capacity; 409 same-session credential rotation in progress (Retry-After: 1), including CSRF lookup; 503 unavailable. Retain the cookie and current page during bounded Busy retry. CSRF and the following POST share the original attempt budget. For logout, 409 guarantees rejection before revocation starts; uncertain revocation returns 503 and must not be automatically retried. No stale CSRF token, identity or evidence is returned. No upstream credential details. */
        Problem: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/problem+json": {
                    /** @constant */
                    type: "about:blank";
                    title: string;
                    status: number;
                };
            };
        };
    };
    parameters: {
        /** @description Must exactly equal the protected HTTPS console origin. */
        Origin: string;
        CSRF: string;
    };
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export interface operations {
    begin_browser_login: {
        parameters: {
            query?: {
                return_to?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Pinned provider redirect and Secure HttpOnly SameSite=Lax browser-binding cookie. */
            303: {
                headers: {
                    Location?: string;
                    [name: string]: unknown;
                };
                content?: never;
            };
            default: components["responses"]["Problem"];
        };
    };
    complete_browser_login: {
        parameters: {
            query: {
                state: string;
                code: string;
                iss: string;
                session_state?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Local return path and fresh opaque Secure HttpOnly SameSite=Strict session cookie. No provider credential in the response. */
            303: {
                headers: {
                    Location?: string;
                    [name: string]: unknown;
                };
                content?: never;
            };
            default: components["responses"]["Problem"];
        };
    };
    get_browser_csrf: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description No identity or evidence is returned. Enables a returning tab to POST refresh before reading current identity. A retained unexpired session may also obtain this token for local logout while settings are suspended or stale; refresh still requires current settings. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        csrf_token: string;
                    };
                };
            };
            default: components["responses"]["Problem"];
        };
    };
    refresh_browser_session: {
        parameters: {
            query?: never;
            header: {
                /** @description Must exactly equal the protected HTTPS console origin. */
                Origin: components["parameters"]["Origin"];
                "X-CSRF-Token": components["parameters"]["CSRF"];
            };
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Current session without extending absolute expiry. Administrator lifetime reductions can shorten expiry. Refresh is serialized across replicas and requires current protected settings. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Session"];
                };
            };
            default: components["responses"]["Problem"];
        };
    };
    end_browser_session: {
        parameters: {
            query?: never;
            header: {
                /** @description Must exactly equal the protected HTTPS console origin. */
                Origin: components["parameters"]["Origin"];
                "X-CSRF-Token": components["parameters"]["CSRF"];
            };
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Local session removed and cookie cleared. Does not sign out of other services. */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            default: components["responses"]["Problem"];
        };
    };
    receive_oidc_logout: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/x-www-form-urlencoded": {
                    logout_token: string;
                } & {
                    [key: string]: unknown;
                };
            };
        };
        responses: {
            /** @description Current matching sessions revoked or exact event retry acknowledged. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            default: components["responses"]["Problem"];
        };
    };
    get_session: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Authorized bounded projection or operation receipt. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Session"];
                };
            };
            /** @description Transport or application failure, nondisclosing before access is established. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["Problem"];
                };
            };
        };
    };
}

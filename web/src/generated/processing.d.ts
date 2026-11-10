// Generated from canonical browser OpenAPI. Run npm run generate; do not edit.
export type paths = Record<string, never>;
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        Contract_processing_fa2777465e6a04e4: {
            /** Format: uuid */
            rootID: string;
            initialized: boolean;
            /** Format: uuid */
            epoch: string;
            sequence: number;
            rules: components["schemas"]["Contract_processing_ebfbfb6e2ab36705"][];
            /** Format: uuid */
            nextCursor?: string;
            /** Format: date-time */
            observedAt: string;
            /** Format: date-time */
            validUntil: string;
        };
        Contract_processing_ebfbfb6e2ab36705: {
            /** Format: uuid */
            id: string;
            revision: number;
            /** @enum {unknown} */
            state: "reserved" | "restricted" | "released";
            scope: components["schemas"]["Contract_processing_30a5a965212655cf"];
            /** Format: date-time */
            administrationUntil: string;
            /** Format: date-time */
            retireBy: string;
        };
        Contract_processing_30a5a965212655cf: {
            /** @constant */
            kind: "artifact";
            location: {
                /** Format: uuid */
                clusterID: string;
                /** Format: uuid */
                artifactID: string;
                /** Format: uuid */
                attemptID: string;
            };
        } | {
            /** @constant */
            kind: "workloadInterval";
            /** Format: uuid */
            clusterID: string;
            namespaceUID: string;
            workloadUID: string;
            /** Format: date-time */
            acquiredFrom: string;
            /** Format: date-time */
            acquiredUntil: string;
        };
        ProcessingInventory: components["schemas"]["Contract_processing_fa2777465e6a04e4"];
        Contract_processing_5c4c1b2613c810e5: {
            /** @constant */
            action: "initialize_processing";
        } | {
            /** @constant */
            action: "restrict_processing";
            /** Format: uuid */
            ruleID: string;
            /** @constant */
            expectedRevision: 0;
            /** Format: uuid */
            artifactID: string;
        } | {
            /** @enum {unknown} */
            action: "restrict_processing" | "release_processing";
            /** Format: uuid */
            ruleID: string;
            expectedRevision: number;
            scope: components["schemas"]["Contract_processing_30a5a965212655cf"];
        };
        ProcessingChange: components["schemas"]["Contract_processing_5c4c1b2613c810e5"];
        Contract_processing_777db293a5ce3458: {
            /** Format: uuid */
            rootID: string;
            /** Format: uuid */
            epoch: string;
            /** Format: uuid */
            requestID: string;
            /** Format: uuid */
            ruleID?: string;
            /** Format: uuid */
            operationID: string;
            /** @enum {unknown} */
            state: "initialized" | "restricted" | "released";
            revision: number;
            sequence: number;
            /** Format: date-time */
            observedAt: string;
            /** Format: date-time */
            validUntil: string;
        };
        ProcessingReceipt: components["schemas"]["Contract_processing_777db293a5ce3458"];
    };
    responses: never;
    parameters: never;
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export type operations = Record<string, never>;

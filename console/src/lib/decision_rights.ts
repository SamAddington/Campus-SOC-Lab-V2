export type DecisionRight = {
  socAction: string;
  aiRole: "autonomous" | "recommend" | "draft only" | "never";
  humanApproval: "yes" | "no";
  privacyBoundary: string[];
  auditEvidence: string[];
};

export const DECISION_RIGHTS_MATRIX: DecisionRight[] = [
  {
    socAction: "Open ticket",
    aiRole: "draft only",
    humanApproval: "yes",
    privacyBoundary: [
      "Minimum alert data",
      "Specific time window",
      "Show only needed identity context",
      "User visibility preserved (no covert actions)",
      "Preserve record",
    ],
    auditEvidence: [
      "ticket_id",
      "reason",
      "query_scope",
      "message",
      "approver",
      "evidence_links",
      "decision_record_id",
      "denied_event (if rejected)",
    ],
  },
  {
    socAction: "Request more logs",
    aiRole: "recommend",
    humanApproval: "yes",
    privacyBoundary: [
      "Specific time window",
      "Limit device / data sources to what is necessary",
      "Minimize identity context",
      "Preserve record",
    ],
    auditEvidence: [
      "ticket_id",
      "reason",
      "query_scope (time range, sources)",
      "approver",
      "evidence_collected",
      "decision_record_id",
      "denied_event (if rejected)",
    ],
  },
  {
    socAction: "Contact user",
    aiRole: "draft only",
    humanApproval: "yes",
    privacyBoundary: [
      "Show only needed identity context",
      "User visibility preserved (user is the recipient)",
      "Minimum alert data",
      "Preserve record",
    ],
    auditEvidence: [
      "ticket_id",
      "reason",
      "message (template + final)",
      "approver",
      "delivery_channel",
      "decision_record_id",
      "denied_event (if rejected)",
    ],
  },
  {
    socAction: "Disable account",
    aiRole: "never",
    humanApproval: "yes",
    privacyBoundary: [
      "Limit identity context to account identifier only",
      "Specific time window / incident scope",
      "Preserve record",
      "User visibility preserved (notification required)",
    ],
    auditEvidence: [
      "ticket_id",
      "reason",
      "approver",
      "account_identifier_used",
      "scope",
      "evidence",
      "decision_record_id",
      "denied_event (if rejected)",
    ],
  },
  {
    socAction: "Quarantine endpoint",
    aiRole: "never",
    humanApproval: "yes",
    privacyBoundary: [
      "Limit device scope to required endpoint(s)",
      "Specific time window / incident scope",
      "Preserve record",
      "User visibility preserved (notification required)",
    ],
    auditEvidence: [
      "ticket_id",
      "reason",
      "approver",
      "device_scope",
      "evidence",
      "decision_record_id",
      "denied_event (if rejected)",
    ],
  },
  {
    socAction: "Delete evidence",
    aiRole: "never",
    humanApproval: "yes",
    privacyBoundary: [
      "Preserve record (tombstone; do not silently erase)",
      "Least-privilege deletion scope",
      "User visibility preserved when applicable",
    ],
    auditEvidence: [
      "ticket_id",
      "reason",
      "approver",
      "deletion_scope",
      "tombstone_record",
      "decision_record_id",
      "denied_event (if rejected)",
    ],
  },
];

export function decisionRightsForAction(socAction: string): DecisionRight | undefined {
  return DECISION_RIGHTS_MATRIX.find((r) => r.socAction.toLowerCase() === socAction.toLowerCase());
}


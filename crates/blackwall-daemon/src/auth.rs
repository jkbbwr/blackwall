//! Future-ready authorization seam (`Operator > User > Agent`) for `blackwall-daemon`.
//!
//! Today, all authenticated callers (local `0600` UDS and the `--http-listen` bearer/cookie
//! session) run as [`CallerContext::operator_local`]. A future multi-tier authenticator
//! (scoped API tokens, separate user/agent sockets) will inject a `CallerContext` with
//! [`PrincipalRole::Operator`], [`PrincipalRole::User`], or [`PrincipalRole::Agent`] at
//! the single middleware seam [`attach_default_operator_context`].

use crate::error::ApiError;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use serde::{Deserialize, Serialize};

/// Role hierarchy for Blackwall control-plane callers (`Operator > User > Agent`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalRole {
    Agent = 1,
    User = 2,
    Operator = 3,
}

impl PrincipalRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::User => "user",
            Self::Operator => "operator",
        }
    }
}

/// Fine-grained control-plane capabilities checked at route boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    MutateProfiles,
    BuildImages,
    DeleteImages,
    CreateSandbox,
    MutateBridges,
    MutateIngress,
    OperateSandbox,
}

/// Authenticated principal context attached to every daemon request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallerContext {
    pub role: PrincipalRole,
    pub subject: String,
}

impl CallerContext {
    /// Default single-user local operator context (`role = Operator`, `subject = "local-operator"`).
    pub fn operator_local() -> Self {
        Self {
            role: PrincipalRole::Operator,
            subject: "local-operator".to_string(),
        }
    }

    /// Check whether this principal is authorized to exercise `cap`.
    pub fn can(&self, cap: Capability) -> bool {
        match self.role {
            PrincipalRole::Operator => true,
            PrincipalRole::User => !matches!(
                cap,
                Capability::MutateProfiles | Capability::BuildImages | Capability::DeleteImages
            ),
            PrincipalRole::Agent => matches!(
                cap,
                Capability::CreateSandbox | Capability::OperateSandbox
            ),
        }
    }

    /// Enforce that this principal has `cap`, returning `403 Forbidden` otherwise.
    pub fn require(&self, cap: Capability) -> Result<(), ApiError> {
        if self.can(cap) {
            Ok(())
        } else {
            Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "insufficient_role",
                format!(
                    "caller role '{}' does not have required capability '{cap:?}'",
                    self.role.as_str()
                ),
            ))
        }
    }
}

/// Axum middleware that ensures every request carries a [`CallerContext`], defaulting to
/// [`CallerContext::operator_local`] if an upstream authenticator did not inject one.
pub async fn attach_default_operator_context(mut req: Request, next: Next) -> Response {
    if req.extensions().get::<CallerContext>().is_none() {
        req.extensions_mut().insert(CallerContext::operator_local());
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_ordering_is_strictly_operator_gt_user_gt_agent() {
        assert!(PrincipalRole::Operator > PrincipalRole::User);
        assert!(PrincipalRole::User > PrincipalRole::Agent);
        assert!(PrincipalRole::Operator > PrincipalRole::Agent);
        assert_eq!(serde_json::to_string(&PrincipalRole::Operator).unwrap(), "\"operator\"");
        assert_eq!(serde_json::to_string(&PrincipalRole::User).unwrap(), "\"user\"");
        assert_eq!(serde_json::to_string(&PrincipalRole::Agent).unwrap(), "\"agent\"");
    }

    #[test]
    fn capability_matrix_enforces_decreasing_privilege() {
        let all_caps = [
            Capability::MutateProfiles,
            Capability::BuildImages,
            Capability::DeleteImages,
            Capability::CreateSandbox,
            Capability::MutateBridges,
            Capability::MutateIngress,
            Capability::OperateSandbox,
        ];

        let operator = CallerContext::operator_local();
        assert_eq!(operator.role, PrincipalRole::Operator);
        assert_eq!(operator.subject, "local-operator");
        for cap in all_caps {
            assert!(operator.can(cap), "Operator must have {cap:?}");
            assert!(operator.require(cap).is_ok());
        }

        let user = CallerContext {
            role: PrincipalRole::User,
            subject: "alice".into(),
        };
        assert!(!user.can(Capability::MutateProfiles));
        assert!(!user.can(Capability::BuildImages));
        assert!(!user.can(Capability::DeleteImages));
        assert!(user.can(Capability::CreateSandbox));
        assert!(user.can(Capability::MutateBridges));
        assert!(user.can(Capability::MutateIngress));
        assert!(user.can(Capability::OperateSandbox));
        assert_eq!(
            user.require(Capability::MutateProfiles).unwrap_err().status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            user.require(Capability::BuildImages).unwrap_err().status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            user.require(Capability::DeleteImages).unwrap_err().status,
            StatusCode::FORBIDDEN
        );

        let agent = CallerContext {
            role: PrincipalRole::Agent,
            subject: "claude-agent".into(),
        };
        assert!(!agent.can(Capability::MutateProfiles));
        assert!(!agent.can(Capability::BuildImages));
        assert!(!agent.can(Capability::DeleteImages));
        assert!(!agent.can(Capability::MutateBridges));
        assert!(!agent.can(Capability::MutateIngress));
        assert!(agent.can(Capability::CreateSandbox));
        assert!(agent.can(Capability::OperateSandbox));
        for denied in [
            Capability::MutateProfiles,
            Capability::BuildImages,
            Capability::DeleteImages,
            Capability::MutateBridges,
            Capability::MutateIngress,
        ] {
            let err = agent.require(denied).unwrap_err();
            assert_eq!(err.status, StatusCode::FORBIDDEN);
            assert_eq!(err.code, "insufficient_role");
        }
    }
}
